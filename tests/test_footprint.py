"""Firewall #2 governance footprint — pure assembly, counts, provenance, F6 guard."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auspexai_platform.db.models import IntegrityPolicy, TrustTier
from auspexai_platform.db.repositories import ResultRepository
from auspexai_platform.footprint import (
    FOOTPRINT_SCHEMA_VERSION,
    INDEPENDENCE_BASIS_ACCOUNT,
    FootprintBasisMismatchError,
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


def test_assert_footprint_recomputable_receipt_basis_self_check():
    """AUD-30 coordinator self-check: with a quorum map, a unit whose asserted
    basis diverges from its receipt-derived basis is refused at sign time — even
    when the aggregate COUNT check passes."""
    entries = [_entry("u1", INTEGRITY_BASIS_EXACT)]
    diverged: list[DivergedUnitEntry] = []
    good = {"integrity_basis": {"counts": integrity_basis_counts(entries, diverged)}}

    # Receipt quorum says 1 agreeing worker → process_only, NOT the within_cell_exact
    # the entry asserts. Counts match (so FootprintRecomputeError would NOT fire),
    # but the per-unit self-check catches the drift.
    with pytest.raises(FootprintBasisMismatchError):
        assert_footprint_recomputable(
            good, entries, diverged, quorum_by_unit={"u1": (1, "builtin_hash_agreement")}
        )

    # Consistent quorum (2 agreeing, hash-agreement → within_cell_exact) passes.
    assert_footprint_recomputable(
        good, entries, diverged, quorum_by_unit={"u1": (2, "builtin_hash_agreement")}
    )
    # No quorum map → the check is skipped (legacy/test callers), no raise.
    assert_footprint_recomputable(good, entries, diverged)


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

    # No manifest / no block ⇒ the greedy default, stable shape. v0.7 adds
    # `effective_source`: with no worker-signed chains it is `unrecorded`, so the
    # footprint never presents the DECLARATION as though it were what ran.
    assert generation_footprint(None) == {"mode": "greedy", "effective_source": "unrecorded"}
    assert generation_footprint({}) == {"mode": "greedy", "effective_source": "unrecorded"}
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
        "effective_source": "unrecorded",
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


# ── v0.7: declared vs effective ──────────────────────────────────────────────


def test_generation_footprint_separates_declared_from_effective():
    """The defect v0.7 closes: the footprint used to report the DECLARATION and
    describe it as the actual. `mode`/`params` stay the declaration; `effective`
    is what the workers signed."""
    from auspexai_platform.footprint import generation_footprint

    declared = {"inference_determinism": {"temperature": 0, "seed": 7}}
    chain = {"temperature": 0, "top_k": 1, "repeat_penalty": 1.0, "seed": 7}
    fp = generation_footprint(declared, observed_chains=[chain])
    assert fp["mode"] == "greedy"
    assert fp["params"] == {"temperature": 0, "seed": 7}
    assert fp["effective_source"] == "worker_signed"
    assert fp["effective"] == chain
    assert fp["effective_chains"] == [chain]


def test_generation_footprint_says_unrecorded_for_a_pre_v3_fleet():
    from auspexai_platform.footprint import generation_footprint

    fp = generation_footprint({"inference_determinism": {"temperature": 0}}, observed_chains=[])
    assert fp["effective_source"] == "unrecorded"
    assert "effective" not in fp
    assert "effective_chains" not in fp


def test_generation_footprint_enumerates_heterogeneous_chains():
    """A run whose replicas ran DIFFERENT chains is not the comparison the
    manifest described, so the footprint must not collapse them to one."""
    from auspexai_platform.footprint import generation_footprint

    chains = [{"top_k": 1, "seed": 0}, {"top_k": 1, "seed": 7}]
    fp = generation_footprint(None, observed_chains=chains)
    assert fp["effective_chains"] == chains
    assert "effective" not in fp, "no single effective chain when workers differed"


def test_generation_footprint_carries_the_penalty_knobs():
    from auspexai_platform.footprint import generation_footprint

    fp = generation_footprint(
        {"inference_determinism": {"temperature": 0, "repeat_penalty": 1.1, "repeat_last_n": 64}}
    )
    assert fp["params"]["repeat_penalty"] == 1.1
    assert fp["params"]["repeat_last_n"] == 64


class TestCollectGenerationChains:
    def test_collects_and_dedupes_across_results(self, approved_experiment, per_job_factory):
        from auspexai_platform.footprint import collect_generation_chains

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
        chain = {"temperature": 0, "top_k": 1}
        for rid, wid, env in (
            ("r1", "w1", {"generation_options": [chain]}),
            ("r2", "w2", {"generation_options": [chain]}),  # identical → deduped
            ("r3", "w3", {"generation_options": [{"temperature": 0, "top_k": 40}]}),
            ("r4", "w4", None),  # pre-v3 worker contributes nothing
        ):
            repo.insert(
                result_id=rid,
                unit_id="u1",
                worker_id=wid,
                worker_pubkey_hex="aa" * 32,
                exit_code=0,
                payload={"v": 1},
                worker_signature="c2ln",
                completed_at=now,
                environment=env,
            )
        chains = collect_generation_chains(db)
        assert len(chains) == 2
        assert chain in chains
        assert {"temperature": 0, "top_k": 40} in chains

    def test_empty_when_no_worker_reported_a_chain(self, approved_experiment, per_job_factory):
        from auspexai_platform.footprint import collect_generation_chains

        _, _, experiment, _ = approved_experiment
        db = per_job_factory.get_or_create(experiment.experiment_id)
        assert collect_generation_chains(db) == []
