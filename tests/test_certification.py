"""Promotion-gate certification primitive + registry (RFC 0001 / Ethics §6.7)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.assessment import EnvelopeCheck, EnvelopeResult, decide
from auspexai_platform.certification import (
    CertificateEnvelope,
    auto_check,
    certified_match,
    envelope_from_manifest,
    is_newer_build,
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
from auspexai_platform.scheduler import resolve_replication


def _envelope(passed: bool = True) -> EnvelopeResult:
    return EnvelopeResult([EnvelopeCheck("x", passed)])


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


# ---- C7: the cert LOCKS the tolerance envelope (§9.2 enforceable) ----

_FS = {
    "lexical.type_token_ratio": {"kind": "numeric", "comparison": {"rule": "numeric", "rel": 0.02}},
    "lexical.top_tokens": {"kind": "set", "comparison": {"rule": "set_jaccard", "min": 0.9}},
}
_ENV = {
    "lexical.type_token_ratio": {"rule": "numeric", "rel": 0.02},
    "lexical.top_tokens": {"rule": "set_jaccard", "min": 0.9},
}


def test_comparison_envelope_extracted_and_bound():
    from auspexai_platform.certification import comparison_envelope_from_manifest

    assert comparison_envelope_from_manifest(_starter_manifest(feature_schema=_FS)) == _ENV
    assert comparison_envelope_from_manifest(_starter_manifest()) == {}  # no feature_schema
    env = envelope_from_manifest(
        _starter_manifest(feature_schema=_FS),
        snapshot_version="s",
        profile_name="starter",
        certified_by="m",
    )
    assert env.comparison_envelope == _ENV


def test_match_rejects_widened_envelope(db):
    """§9.2: a bound cert rejects a manifest that WIDENS the tolerance envelope
    (rel 0.02 → 0.5) — no silent 'certified' on a loosened agreement bar. Also
    verifies the envelope round-trips through the DB column."""
    rec = _insert(CertifiedProfileRepository(db), comparison_envelope=_ENV)
    assert rec.comparison_envelope == _ENV
    widened = dict(_FS)
    widened["lexical.type_token_ratio"] = {
        "kind": "numeric",
        "comparison": {"rule": "numeric", "rel": 0.5},
    }
    res = match(_starter_manifest(feature_schema=widened), rec)
    assert not res.passed
    assert any("tolerance envelope" in f for f in res.failures)


def test_match_accepts_exact_envelope(db):
    rec = _insert(CertifiedProfileRepository(db), comparison_envelope=_ENV)
    assert match(_starter_manifest(feature_schema=_FS), rec).passed


def test_match_legacy_cert_skips_envelope(db):
    """A cert issued before envelope-binding (comparison_envelope None) is not
    locked — match() skips the envelope check (backward compatible) until reissue."""
    rec = _insert(CertifiedProfileRepository(db))
    assert rec.comparison_envelope is None
    assert match(_starter_manifest(feature_schema=_FS), rec).passed


# ---- is_newer_build (the re-certification staleness signal) ----


def test_is_newer_build_only_for_package_only_change(db):
    rec = _insert(CertifiedProfileRepository(db))
    # same profile, NEW package digest only → a newer build → re-certify candidate
    assert is_newer_build(_starter_manifest(executor={"package_sha256": "b" * 64}), rec)
    # an exact-match run is already certified, not "newer"
    assert not is_newer_build(_starter_manifest(), rec)
    # a different package AND another locked field (model) → an unrelated run, not
    # a re-build of this profile → NOT flagged (avoids false positives)
    assert not is_newer_build(
        _starter_manifest(executor={"package_sha256": "b" * 64}, models=[{"id": "other"}]), rec
    )


# ---- certified_match (the combined lookup + match used by submit/assess) ----


def test_certified_match_resolves_active_cert(db):
    repo = CertifiedProfileRepository(db)
    _insert(repo)
    assert certified_match(_starter_manifest(), repo) is not None
    # not matching (locked field changed) → None
    assert certified_match(_starter_manifest(sensitive_content_flags=["x"]), repo) is None
    # revoked → None
    repo.revoke("a" * 64, reason="test")
    assert certified_match(_starter_manifest(), repo) is None


def test_certified_match_is_defensive(db):
    repo = CertifiedProfileRepository(db)
    # a legacy/loose manifest with a string executor (no content-addressed package)
    assert certified_match({"executor": "python -m x"}, repo) is None
    assert certified_match({}, repo) is None


# ---- decide(): certification substitutes for tier (§6.7.5) ----


def test_decide_certified_auto_clears_low_tier():
    # a T0/T1 newcomer who could never reach the T2 auto-approval floor...
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=0,
        envelope=_envelope(True),
        auto_approval_enabled=True,
        certified=True,
    )
    assert v.decision == "auto" and "certified" in v.rationale


def test_decide_certified_ignores_tier_gate():
    # Certification is DECOUPLED from the routine-tier gate: a certified run
    # auto-clears even with that gate OFF (certify = on, revoke = off). The
    # certification — per-profile + signed — is its own enable.
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=0,
        envelope=_envelope(True),
        auto_approval_enabled=False,  # routine-tier gate off
        certified=True,
    )
    assert v.decision == "auto"


def test_decide_certified_respects_envelope():
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=0,
        envelope=_envelope(False),  # an envelope check failed
        auto_approval_enabled=True,
        certified=True,
    )
    assert v.decision == "review"


def test_decide_uncertified_low_tier_still_reviews():
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=0,
        envelope=_envelope(True),
        auto_approval_enabled=True,
        certified=False,
    )
    assert v.decision == "review"


# ---- the certified-floor exemption (§6.7 / C14) ----


def test_resolve_replication_floor_exemption():
    # T0's tier floor is 3 → a 2-worker fleet would stall...
    t, f, _ = resolve_replication(requested_target=2, requested_floor=2, tenant_tier=0)
    assert (t, f) == (3, 3)
    # ...but a certified starter runs at its certified floor (2), no stall.
    t, f, _ = resolve_replication(
        requested_target=2, requested_floor=2, tenant_tier=0, tier_floor_override=2
    )
    assert (t, f) == (2, 2)


# ---- the maintainer CLI (issue / list / revoke) ----


def _write_starter_manifest(tmp_path):
    import json as _json

    p = tmp_path / "manifest.json"
    p.write_text(_json.dumps(_starter_manifest()))
    return p


def _run(args):
    from click.testing import CliRunner

    from auspexai_platform.cli import main

    return CliRunner().invoke(main, args)


def test_cli_issue_dry_run_then_apply_then_list(tmp_path):
    manifest = _write_starter_manifest(tmp_path)
    common = [
        "certification",
        "issue",
        "--state-dir",
        str(tmp_path),
        "--manifest",
        str(manifest),
        "--snapshot",
        "vigiles-tenant@v0.1.0",
        "--profile",
        "starter",
        "--certified-by",
        "maintainer:test",
    ]
    dry = _run(common)
    assert dry.exit_code == 0 and "DRY-RUN" in dry.output

    applied = _run([*common, "--apply"])
    assert applied.exit_code == 0 and "✓ certified" in applied.output

    listed = _run(["certification", "list", "--state-dir", str(tmp_path)])
    assert "vigiles-lab/starter" in listed.output and "certified" in listed.output

    # idempotent: re-issuing identical content is rejected
    again = _run([*common, "--apply"])
    assert again.exit_code == 1 and "Already certified" in again.output


def test_cli_issue_rejects_non_starter(tmp_path):
    import json as _json

    bad = tmp_path / "bad.json"
    bad.write_text(_json.dumps(_starter_manifest(sensitive_content_flags=["jailbreak"])))
    r = _run(
        [
            "certification",
            "issue",
            "--state-dir",
            str(tmp_path),
            "--manifest",
            str(bad),
            "--snapshot",
            "s",
            "--profile",
            "starter",
            "--certified-by",
            "m",
        ]
    )
    assert r.exit_code == 1 and "FAILED" in r.output


def test_cli_revoke(tmp_path):
    manifest = _write_starter_manifest(tmp_path)
    _run(
        [
            "certification",
            "issue",
            "--state-dir",
            str(tmp_path),
            "--manifest",
            str(manifest),
            "--snapshot",
            "s",
            "--profile",
            "starter",
            "--certified-by",
            "m",
            "--apply",
        ]
    )
    pkg = "a" * 64
    r = _run(
        [
            "certification",
            "revoke",
            "--state-dir",
            str(tmp_path),
            "--package",
            pkg,
            "--reason",
            "x",
            "--apply",
        ]
    )
    assert r.exit_code == 0 and "revoked" in r.output


# ---- Rekor backfill (§6.7.4 "publish") ----


class _FakeRekor:
    def record(self, _blob):
        from auspexai_platform.receipts.rekor import RekorEntry

        return RekorEntry(log_index=42, entry_uuid="uuid-x")


def test_backfill_cert_rekor_anchors_and_is_idempotent(db):
    from auspexai_platform.certification_backfill import backfill_cert_rekor

    repo = CertifiedProfileRepository(db)
    _insert(repo)  # rekor_log_index is NULL → a candidate
    # dry-run: counts, doesn't anchor
    dry = backfill_cert_rekor(db, rekor_client=_FakeRekor(), apply=False)
    assert dry.candidates == 1 and not dry.anchored
    assert repo.get_by_package("a" * 64).rekor_log_index is None
    # apply: anchors, records the log index
    done = backfill_cert_rekor(db, rekor_client=_FakeRekor(), apply=True)
    assert done.anchored == ["a" * 64]
    assert repo.get_by_package("a" * 64).rekor_log_index == 42
    # idempotent: already anchored → no candidates
    again = backfill_cert_rekor(db, rekor_client=_FakeRekor(), apply=True)
    assert again.candidates == 0 and not again.anchored


# ---- reissue (label correction / snapshot re-cut, §6.7) ----


def test_reissue_relabels_resigns_and_resets_anchor(db):
    repo = CertifiedProfileRepository(db)
    _insert(repo)  # snapshot vigiles-tenant@v0.1.0
    repo.set_rekor("a" * 64, log_index=999)  # pretend the v0.1.0 cert was anchored
    assert repo.get_by_package("a" * 64).rekor_log_index == 999

    old, _rec = repo.reissue(
        package_sha256="a" * 64,
        snapshot_version="vigiles-tenant@v0.1.1",
        tenant_id="vigiles-lab",
        profile_name="starter",
        research_class="behavioral_drift",
        sensitive_content_flags=[],
        model_ids=["gemma-3-1b-it-q4"],
        replication_floor=2,
        max_units_ceiling=None,
        duration_hours_ceiling=1.0,
        cose_signed_blob=b"\x09\x09",  # re-signed blob
        signing_key_pubkey_hex="ff" * 32,
        certified_by="maintainer:jasongagne-git",
    )
    assert old == "vigiles-tenant@v0.1.0"
    got = repo.get_by_package("a" * 64)
    assert got.snapshot_version == "vigiles-tenant@v0.1.1"  # re-labeled
    assert got.status == "certified"
    assert got.cose_signed_blob == b"\x09\x09"  # re-signed
    assert got.rekor_log_index is None  # reset → the new cert re-anchors
    # still exactly one row for this package (content key is the PK)
    assert len(repo.list_all()) == 1


def test_reissue_missing_raises(db):
    from auspexai_platform.db.repositories.certified_profiles import NoCertificationError

    repo = CertifiedProfileRepository(db)
    with pytest.raises(NoCertificationError):
        repo.reissue(
            package_sha256="b" * 64,
            snapshot_version="x",
            tenant_id="t",
            profile_name="p",
            research_class=None,
            sensitive_content_flags=[],
            model_ids=[],
            replication_floor=2,
            max_units_ceiling=None,
            duration_hours_ceiling=None,
            cose_signed_blob=b"x",
            signing_key_pubkey_hex="ff",
            certified_by="m",
        )
