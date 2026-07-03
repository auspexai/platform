"""Firewall #2 governance footprint — pure assembly, counts, provenance, F6 guard."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auspexai_platform.db.models import IntegrityPolicy, TrustTier
from auspexai_platform.db.repositories import ResultRepository
from auspexai_platform.footprint import (
    FOOTPRINT_SCHEMA_VERSION,
    INDEPENDENCE_BASIS_ACCOUNT,
    FootprintRecomputeError,
    assemble_governance_footprint,
    assert_footprint_recomputable,
    compute_independence,
    integrity_basis_counts,
    replication_footprint,
)
from auspexai_platform.receipts.attestation import (
    INTEGRITY_BASIS_DIVERGED,
    INTEGRITY_BASIS_EXACT,
    INTEGRITY_BASIS_PROCESS_ONLY,
    DivergedUnitEntry,
    ResultSetEntry,
)


def _entry(uid: str, basis: str) -> ResultSetEntry:
    return ResultSetEntry(uid, "h", "r", integrity_basis=basis)


def test_integrity_basis_counts():
    entries = [
        _entry("u1", INTEGRITY_BASIS_EXACT),
        _entry("u2", INTEGRITY_BASIS_EXACT),
        _entry("u3", INTEGRITY_BASIS_PROCESS_ONLY),
    ]
    diverged = [DivergedUnitEntry("u4", None, ["a", "b"])]
    counts = integrity_basis_counts(entries, diverged)
    assert counts[INTEGRITY_BASIS_EXACT] == 2
    assert counts[INTEGRITY_BASIS_PROCESS_ONLY] == 1
    assert counts[INTEGRITY_BASIS_DIVERGED] == 1


def test_replication_footprint_provenance():
    # trusted at T2 = exactly the tier floor → floored, not sub-floor.
    fp = replication_footprint(IntegrityPolicy.TRUSTED, TrustTier.T2_TRUSTED)
    assert fp["integrity_policy"] == "trusted"
    assert fp["replication_factor"] == 1
    assert fp["tier_floored"] is True
    assert fp["sub_floor"] is False
    # standard at T1 = the T1 floor.
    assert (
        replication_footprint(IntegrityPolicy.STANDARD, TrustTier.T1_AUTHENTICATED)["tier_floored"]
        is True
    )
    # trusted at T1 = BELOW the floor — only reachable via an A' force override.
    fp_forced = replication_footprint(IntegrityPolicy.TRUSTED, TrustTier.T1_AUTHENTICATED)
    assert fp_forced["sub_floor"] is True
    assert fp_forced["tier_floored"] is False


def test_assemble_governance_footprint_shape():
    fp = assemble_governance_footprint(
        tenant_tier=TrustTier.T2_TRUSTED,
        identity_gate="verified",
        integrity_policy=IntegrityPolicy.TRUSTED,
        approval_experiment="auto",
        assessment={"research_class": "drift", "tier": 2, "envelope": []},
        promotion_tier_set_by="system",
        independence={"basis": INDEPENDENCE_BASIS_ACCOUNT, "distinct_accounts": 1},
        containment={"required": "permissive", "ran_under": ["strict"]},
        entries=[_entry("u1", INTEGRITY_BASIS_EXACT)],
        diverged_units=[DivergedUnitEntry("u2", None, ["a", "b"])],
    )
    assert fp["schema_version"] == FOOTPRINT_SCHEMA_VERSION
    assert fp["tenant"] == {"tier": "T2", "identity_gate": "verified"}
    assert fp["replication"]["integrity_policy"] == "trusted"
    assert fp["approval"]["experiment"] == "auto"
    assert fp["approval"]["promotion"]["tier_set_by"] == "system"
    assert fp["containment"] == {"required": "permissive", "ran_under": ["strict"]}
    assert fp["integrity_basis"]["counts"][INTEGRITY_BASIS_EXACT] == 1
    assert fp["integrity_basis"]["counts"][INTEGRITY_BASIS_DIVERGED] == 1


def test_assert_footprint_recomputable_passes_and_raises():
    entries = [_entry("u1", INTEGRITY_BASIS_EXACT)]
    diverged: list[DivergedUnitEntry] = []
    good = {"integrity_basis": {"counts": integrity_basis_counts(entries, diverged)}}
    assert_footprint_recomputable(good, entries, diverged)  # no raise
    assert_footprint_recomputable(None, entries, diverged)  # no footprint → no-op
    bad = {"integrity_basis": {"counts": {INTEGRITY_BASIS_EXACT: 99}}}
    with pytest.raises(FootprintRecomputeError):
        assert_footprint_recomputable(bad, entries, diverged)


class TestIndependence:
    def test_account_level_independence(self, approved_experiment, per_job_factory):
        """Two distinct workers on two distinct accounts corroborate one unit →
        distinct_accounts=2, distinct_workers=2, basis stated account-level."""
        _, _, experiment, _ = approved_experiment
        db = per_job_factory.get_or_create(experiment.experiment_id)
        now = datetime.now(UTC)
        db.execute(
            "INSERT OR IGNORE INTO work_units "
            "(unit_id, payload_json, status, replication_target, completions_so_far, created_at) "
            "VALUES ('u1', '{}', 'completed', 2, 2, ?)",
            (now.isoformat(),),
        )
        repo = ResultRepository(db)
        r1 = repo.insert(
            result_id="r1",
            unit_id="u1",
            worker_id="w1",
            worker_pubkey_hex="aa" * 32,
            exit_code=0,
            payload={"v": 1},
            worker_signature="c2ln",
            completed_at=now,
        )
        repo.insert(
            result_id="r2",
            unit_id="u1",
            worker_id="w2",
            worker_pubkey_hex="bb" * 32,
            exit_code=0,
            payload={"v": 1},
            worker_signature="c2ln",
            completed_at=now,
        )
        repo.promote_consensus("u1", r1.result_id)
        ind = compute_independence(db, lambda wid: {"w1": "acctA", "w2": "acctB"}.get(wid))
        assert ind["basis"] == INDEPENDENCE_BASIS_ACCOUNT
        assert ind["distinct_workers"] == 2
        assert ind["distinct_accounts"] == 2
        assert ind["per_unit"]["min_distinct_accounts"] == 2


# ── v0.2 M1 Inc 3: the declared generation policy on the footprint ───────────


def test_generation_footprint_modes():
    from auspexai_platform.footprint import generation_footprint

    # No manifest / no block ⇒ the greedy default, stable shape.
    assert generation_footprint(None) == {"mode": "greedy"}
    assert generation_footprint({}) == {"mode": "greedy"}
    # Greedy with declared params keeps the params visible.
    fp = generation_footprint(
        {"inference_determinism": {"temperature": 0, "seed": 7, "serving_version_pin": "o/1"}}
    )
    assert fp["mode"] == "greedy"
    assert fp["params"] == {"temperature": 0, "seed": 7, "serving_version_pin": "o/1"}
    # Seeded sampling records the mode + the declared whitelist knobs.
    fp = generation_footprint(
        {"inference_determinism": {"temperature": 0.8, "seed": 42, "top_p": 0.9, "top_k": 40}}
    )
    assert fp["mode"] == "seeded_sampling"
    assert fp["params"] == {"temperature": 0.8, "seed": 42, "top_p": 0.9, "top_k": 40}
    # Malformed blocks read as greedy (nothing else could have been enforced).
    assert generation_footprint({"inference_determinism": "junk"})["mode"] == "greedy"


def test_assemble_footprint_carries_generation_block():
    from auspexai_platform.footprint import generation_footprint

    fp = assemble_governance_footprint(
        tenant_tier=TrustTier.T2_TRUSTED,
        identity_gate="verified",
        integrity_policy=IntegrityPolicy.TRUSTED,
        approval_experiment="auto",
        assessment=None,
        promotion_tier_set_by=None,
        independence={"basis": INDEPENDENCE_BASIS_ACCOUNT, "distinct_accounts": 1},
        containment={"required": "permissive", "ran_under": ["strict"]},
        entries=[_entry("u1", INTEGRITY_BASIS_EXACT)],
        diverged_units=[],
        generation=generation_footprint(
            {"inference_determinism": {"temperature": 0.8, "seed": 42}}
        ),
    )
    assert fp["generation"] == {
        "mode": "seeded_sampling",
        "params": {"temperature": 0.8, "seed": 42},
    }
    # Legacy callers (no generation kwarg) keep the pre-M1 shape.
    legacy = assemble_governance_footprint(
        tenant_tier=TrustTier.T2_TRUSTED,
        identity_gate="verified",
        integrity_policy=IntegrityPolicy.TRUSTED,
        approval_experiment="human",
        assessment=None,
        promotion_tier_set_by=None,
        independence={},
        containment={},
        entries=[],
        diverged_units=[],
    )
    assert "generation" not in legacy
