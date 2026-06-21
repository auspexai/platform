"""Promotion-gate certification primitive + registry (RFC 0001 / Ethics §6.7)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.certification import (
    CertificateEnvelope,
    auto_check,
    envelope_from_manifest,
    match,
    sign_certificate,
)
from auspexai_platform.db.repositories.certified_profiles import (
    CertifiedProfileRepository,
    DuplicateCertificationError,
)
from auspexai_platform.receipts.signing import (
    CoseVerificationError,
    SigningKey,
    cose_sign1_decode,
)


def _starter_manifest(**over):
    m = {
        "tenant_id": "vigiles-lab",
        "research_class": "behavioral_drift",
        "sensitive_content_flags": [],
        "models": [{"id": "gemma-3-1b-it-q4"}],
        "replication_factor": 2,
        "expected_duration_hours": 1.0,
        "executor": {"package_sha256": "a" * 64},
        "reducer": {"kind": "builtin_hash_agreement"},
    }
    m.update(over)
    return m


def _key() -> SigningKey:
    return SigningKey._from_private(Ed25519PrivateKey.generate())


def _insert(repo: CertifiedProfileRepository, **over):
    kw = {
        "package_sha256": "a" * 64,
        "snapshot_version": "vigiles-tenant@v0.1.0",
        "tenant_id": "vigiles-lab",
        "profile_name": "starter",
        "research_class": "behavioral_drift",
        "sensitive_content_flags": [],
        "model_ids": ["gemma-3-1b-it-q4"],
        "replication_floor": 2,
        "max_units_ceiling": None,
        "duration_hours_ceiling": 1.0,
        "cose_signed_blob": b"\x01\x02",
        "signing_key_pubkey_hex": "ff" * 32,
        "certified_by": "maintainer:jasongagne-git",
    }
    kw.update(over)
    return repo.insert(**kw)


# ---- auto_check (the §6.7.2 machine subset) ----


def test_auto_check_passes_clean_starter():
    assert auto_check(_starter_manifest()).passed


@pytest.mark.parametrize(
    "over",
    [
        {"sensitive_content_flags": ["jailbreak"]},
        {"research_class": "refusal_boundary_mapping"},  # elevated
        {"research_class": "something_made_up"},  # unknown
        {"reducer": {"kind": "custom_subprocess"}},
        {"requires_real_execution": True},
    ],
)
def test_auto_check_rejects_non_starter(over):
    assert not auto_check(_starter_manifest(**over)).passed


# ---- envelope + signing ----


def test_envelope_from_manifest_extracts_locked_fields():
    env = envelope_from_manifest(
        _starter_manifest(),
        snapshot_version="vigiles-tenant@v0.1.0",
        profile_name="starter",
        certified_by="maintainer",
    )
    assert env.package_sha256 == "a" * 64
    assert env.tenant_id == "vigiles-lab"
    assert env.model_ids == ["gemma-3-1b-it-q4"]
    assert env.replication_floor == 2
    assert env.duration_hours_ceiling == 1.0
    assert env.sensitive_content_flags == [] and env.advisor is None


def test_canonical_bytes_deterministic_and_order_normalized():
    base = dict(
        package_sha256="a" * 64,
        snapshot_version="s",
        tenant_id="t",
        profile_name="starter",
        research_class="behavioral_drift",
        replication_floor=2,
        max_units_ceiling=None,
        duration_hours_ceiling=1.0,
        certified_by="m",
        advisor=None,
        certified_at="2026-06-21T00:00:00+00:00",
    )
    e1 = CertificateEnvelope(sensitive_content_flags=[], model_ids=["b", "a"], **base)
    e2 = CertificateEnvelope(sensitive_content_flags=[], model_ids=["a", "b"], **base)
    assert e1.canonical_bytes() == e2.canonical_bytes()  # list order normalized


def test_sign_verifies_and_wrong_key_fails():
    env = envelope_from_manifest(
        _starter_manifest(), snapshot_version="s", profile_name="starter", certified_by="m"
    )
    key, other = _key(), _key()
    blob = sign_certificate(env, signing_key=key)
    payload, kid = cose_sign1_decode(blob, expected_pubkey=key.public_key)
    assert payload == env.canonical_bytes()
    assert kid == key.pubkey_hex
    with pytest.raises(CoseVerificationError):
        cose_sign1_decode(blob, expected_pubkey=other.public_key)


# ---- repository ----


def test_repo_insert_get_revoke(db):
    repo = CertifiedProfileRepository(db)
    rec = _insert(repo)
    assert rec.is_active and rec.model_ids == ["gemma-3-1b-it-q4"]
    assert repo.get_by_package("a" * 64).is_active
    assert repo.get_active(tenant_id="vigiles-lab", profile_name="starter") is not None
    repo.revoke("a" * 64, reason="test revoke")
    assert not repo.get_by_package("a" * 64).is_active
    assert repo.get_active(tenant_id="vigiles-lab", profile_name="starter") is None


def test_repo_duplicate_raises(db):
    repo = CertifiedProfileRepository(db)
    _insert(repo)
    with pytest.raises(DuplicateCertificationError):
        _insert(repo)


def test_repo_supersede_others(db):
    repo = CertifiedProfileRepository(db)
    _insert(repo, package_sha256="a" * 64, snapshot_version="v0.1.0")
    _insert(repo, package_sha256="b" * 64, snapshot_version="v0.2.0")
    repo.supersede_others(tenant_id="vigiles-lab", profile_name="starter", keep_package="b" * 64)
    assert repo.get_by_package("a" * 64).status == "superseded"
    assert repo.get_by_package("b" * 64).is_active
    assert (
        repo.get_active(tenant_id="vigiles-lab", profile_name="starter").package_sha256 == "b" * 64
    )


# ---- match (the §6.7.3 locked-field check) ----


def test_match_passes_for_certified_profile(db):
    rec = _insert(CertifiedProfileRepository(db))
    # safe knobs (driver cadence/rounds) are not in the manifest → still matches
    assert match(_starter_manifest(), rec).passed


@pytest.mark.parametrize(
    "over",
    [
        {"sensitive_content_flags": ["jailbreak"]},
        {"models": [{"id": "other-model"}]},
        {"replication_factor": 1},  # below the certified floor
        {"expected_duration_hours": 8.0},  # exceeds the certified ceiling
        {"research_class": "eval_sweeps"},  # different (still routine) class
        {"executor": {"package_sha256": "b" * 64}},  # different package
    ],
)
def test_match_rejects_locked_field_changes(db, over):
    rec = _insert(CertifiedProfileRepository(db))
    assert not match(_starter_manifest(**over), rec).passed
