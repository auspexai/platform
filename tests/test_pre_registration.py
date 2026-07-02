"""D16.2 — pre-registration: mirror validation, the submit-time anchor, the
attestation binding, and the backfill sweep (preregistration_design.md)."""

from __future__ import annotations

from pathlib import Path

import cbor2

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import PreRegistrationRepository
from auspexai_platform.db.repositories.pre_registrations import NOT_ANCHORED_ENTRY_UUID
from auspexai_platform.pre_registration import (
    build_pre_registration_predicate,
    validate_pre_registration,
)
from auspexai_platform.receipts.attestation import (
    ResultSetEntry,
    build_result_set_attestation,
    merkle_root,
)
from auspexai_platform.receipts.attestation_backfill import backfill_rekor_anchors
from auspexai_platform.receipts.rekor import REKOR_PLACEHOLDER_UUID, RekorEntry
from auspexai_platform.receipts.signing import cose_sign1_decode, load_or_generate_signing_key

# A minimal valid feature_schema + pre_registration pair (coordinator-mirror shapes).
FS = {
    "probe_id": {
        "meaning": "which probe",
        "kind": "categorical",
        "role": "key",
        "change_means": "different probe",
        "categories": ["p-a"],
    },
    "lexical.type_token_ratio": {
        "meaning": "ttr",
        "kind": "numeric",
        "role": "summary",
        "range": {"min": 0.0, "max": 1.0},
        "change_means": "vocab shift",
        "comparison": {"rule": "numeric", "rel": 0.02},
    },
    "eval_count": {
        "meaning": "tokens",
        "kind": "count",
        "role": "summary",
        "range": {"min": 0},
        "change_means": "length shift",
    },
}
PRE_REG = {
    "hypothesis": "responses to each fixed probe are stable across rounds",
    "analysis_method": "per probe_id, compare the consensus feature vector round-over-round",
    "features": ["lexical.type_token_ratio"],
    "timescale": "intra_experiment_rounds",
    "decision_rule": "drift IFF the consensus vector exits the declared envelope",
    "expected_result": "no probe drifts",
    "stopping_rule": "converge-on-stability; not data-peeking-dependent",
    "comparison_keys": ["probe_id"],
}


def _manifest(pre_reg: dict | None = None, schema_version: str = "0.4") -> dict:
    return {
        "schema_version": schema_version,
        "feature_schema": FS,
        "pre_registration": dict(pre_reg if pre_reg is not None else PRE_REG),
    }


# ── mirror validation ─────────────────────────────────────────────────────────


def test_valid_block_passes() -> None:
    assert validate_pre_registration(_manifest()) == []


def test_wrong_schema_version_rejected() -> None:
    errs = validate_pre_registration(_manifest(schema_version="0.3"))
    assert any("0.4" in e for e in errs)


def test_missing_stopping_rule_rejected() -> None:
    block = dict(PRE_REG)
    del block["stopping_rule"]
    errs = validate_pre_registration(_manifest(block))
    assert any("stopping_rule" in e for e in errs)


def test_undeclared_feature_rejected() -> None:
    errs = validate_pre_registration(_manifest({**PRE_REG, "features": ["nope"]}))
    assert any("not in feature_schema" in e for e in errs)


def test_feature_without_comparison_rejected() -> None:
    errs = validate_pre_registration(_manifest({**PRE_REG, "features": ["eval_count"]}))
    assert any("no 'comparison'" in e for e in errs)


def test_undeclared_comparison_key_rejected() -> None:
    errs = validate_pre_registration(_manifest({**PRE_REG, "comparison_keys": ["seed"]}))
    assert any("comparison_key" in e for e in errs)


def test_unknown_field_and_bad_timescale_rejected() -> None:
    errs = validate_pre_registration(
        _manifest({**PRE_REG, "post_hoc": "x", "timescale": "whenever"})
    )
    assert any("unknown fields" in e for e in errs)
    assert any("timescale" in e for e in errs)


def test_missing_feature_schema_rejected() -> None:
    m = _manifest()
    del m["feature_schema"]
    errs = validate_pre_registration(m)
    assert any("feature_schema" in e for e in errs)


# ── the anchor row + predicate determinism ────────────────────────────────────


def test_predicate_is_deterministic_and_decodes() -> None:
    kwargs = dict(
        manifest_hash="ab" * 32,
        tenant_id="lab",
        tenant_experiment_label="exp-x",
        pre_registration=PRE_REG,
        submitted_at="2026-07-02T00:00:00+00:00",
    )
    a = build_pre_registration_predicate(**kwargs)
    b = build_pre_registration_predicate(**kwargs)
    assert a == b
    body = cbor2.loads(a)
    assert body["manifest_hash"] == "ab" * 32
    assert body["pre_registration"]["stopping_rule"] == PRE_REG["stopping_rule"]


def test_repo_round_trip_and_immutability(db: Database) -> None:
    repo = PreRegistrationRepository(db)
    rec = repo.insert(
        experiment_id="exp-1",
        tenant_id="lab",
        tenant_experiment_label="label-1",
        manifest_hash="cd" * 32,
        cose_signed_blob=b"\x01",
        signing_key_pubkey_hex="ab" * 32,
        submitted_at="2026-07-02T00:00:00+00:00",
    )
    assert not rec.anchored and rec.rekor_entry_uuid == NOT_ANCHORED_ENTRY_UUID
    # INSERT OR IGNORE: a second write never mutates the original (immutable —
    # deviations are separate records, never edits).
    repo.insert(
        experiment_id="exp-1",
        tenant_id="lab",
        tenant_experiment_label="label-1",
        manifest_hash="ee" * 32,
        cose_signed_blob=b"\x02",
        signing_key_pubkey_hex="ab" * 32,
        submitted_at="2026-07-03T00:00:00+00:00",
    )
    again = repo.get("exp-1")
    assert again.manifest_hash == "cd" * 32 and again.cose_signed_blob == b"\x01"
    ref = again.predicate_ref()
    assert ref["manifest_hash"] == "cd" * 32 and "rekor_log_index" in ref


def test_prereg_sentinel_matches_rekor_placeholder() -> None:
    assert NOT_ANCHORED_ENTRY_UUID == REKOR_PLACEHOLDER_UUID


# ── attestation binding (maximal tier: predicate-only, root unchanged) ────────


def test_attestation_predicate_carries_pre_registration(tmp_path: Path) -> None:
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32)]
    ref = {
        "manifest_hash": "ab" * 32,
        "rekor_log_index": 123,
        "rekor_entry_uuid": "uuid-1",
        "submitted_at": "2026-07-02T00:00:00+00:00",
    }
    att = build_result_set_attestation(
        attestation_id="att-pr",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
        pre_registration=ref,
    )
    # Predicate-only: the Merkle root is unchanged by the binding.
    assert att.merkle_root == merkle_root(entries, schema_version=1)
    payload, _ = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    body = cbor2.loads(cbor2.loads(payload)["predicate"])
    assert body["pre_registration"] == ref
    # Omitted entirely when absent — pre-D16.2 predicates stay byte-identical.
    att2 = build_result_set_attestation(
        attestation_id="att-pr",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
    )
    payload2, _ = cose_sign1_decode(att2.cose_signed_blob, expected_pubkey=key.public_key)
    assert "pre_registration" not in cbor2.loads(cbor2.loads(payload2)["predicate"])


# ── the backfill sweep anchors prereg rows (Q1: reuse the hourly timer) ───────


class _FakeRekor:
    def __init__(self) -> None:
        self.calls = 0

    def record(self, cose_blob: bytes) -> RekorEntry:
        self.calls += 1
        return RekorEntry(log_index=5000 + self.calls, entry_uuid=f"pr-uuid-{self.calls}")


def test_backfill_anchors_pre_registrations(db: Database) -> None:
    repo = PreRegistrationRepository(db)
    repo.insert(
        experiment_id="exp-bf",
        tenant_id="lab",
        tenant_experiment_label="label-bf",
        manifest_hash="ab" * 32,
        cose_signed_blob=b"\x01\x02",
        signing_key_pubkey_hex="ab" * 32,
        submitted_at="2026-07-02T00:00:00+00:00",
    )
    client = _FakeRekor()
    # dry-run counts, never contacts Rekor
    dry = backfill_rekor_anchors(db, rekor_client=client, apply=True)
    assert dry.prereg_candidates == 1 and dry.prereg_anchored == ["exp-bf"]
    rec = repo.get("exp-bf")
    assert rec.anchored and rec.rekor_log_index >= 5000
    assert repo.list_unanchored() == []
    # idempotent
    again = _FakeRekor()
    rep2 = backfill_rekor_anchors(db, rekor_client=again, apply=True)
    assert rep2.prereg_candidates == 0 and again.calls == 0


def test_backfill_dry_run_counts_prereg(db: Database) -> None:
    repo = PreRegistrationRepository(db)
    repo.insert(
        experiment_id="exp-dry",
        tenant_id="lab",
        tenant_experiment_label="label-dry",
        manifest_hash="ab" * 32,
        cose_signed_blob=b"\x01",
        signing_key_pubkey_hex="ab" * 32,
        submitted_at="2026-07-02T00:00:00+00:00",
    )
    client = _FakeRekor()
    report = backfill_rekor_anchors(db, rekor_client=client, apply=False)
    assert report.prereg_candidates == 1 and client.calls == 0
    assert not repo.get("exp-dry").anchored
