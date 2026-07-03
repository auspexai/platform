"""C17 `builtin_process_only` — the observe-only collection mode
(process_only_reducer_and_provenance_v0_6_design.md, RATIFIED 2026-07-03).

No cross-replica agreement is ever claimed: every replica is an independent
observation earning a receipt that corroborates only itself (agreeing_workers=1
→ the EXISTING basis classifier yields `process_only` at any count, untouched).
The leaf binds the lexicographic-first observation hash (ratified Q3)."""

from __future__ import annotations

from types import SimpleNamespace

from auspexai_platform.hashing import semantic_hash
from auspexai_platform.receipts.attestation import (
    INTEGRITY_BASIS_PROCESS_ONLY,
    classify_consensus_basis,
)
from auspexai_platform.receipts.issuance import PROCESS_ONLY_METHOD, _reduce_unit

_PO_MANIFEST = {"reducer": {"kind": "builtin_process_only"}}
_EXP = SimpleNamespace(replication_floor=2)


def _r(payload: dict, exit_code: int = 0):
    return SimpleNamespace(payload=payload, exit_code=exit_code)


def test_every_replica_is_a_valid_observation_none_diverge() -> None:
    # Three wildly-different outputs (the seeded-sampling shape): ALL agree
    # (each with itself), none is an outlier, nothing is diverged.
    results = [_r({"x": i}) for i in range(3)]
    outcome, agreeing, outliers, evidence = _reduce_unit(
        results, experiment=_EXP, manifest=_PO_MANIFEST
    )
    assert outcome.agreed is True
    assert outcome.method == PROCESS_ONLY_METHOD
    assert agreeing == results and outliers == []
    assert evidence["outlier_count"] == 0


def test_receipts_record_honest_agreeing_workers_of_one() -> None:
    # The load-bearing invariant: quorum agreeing_workers=1 regardless of N —
    # each replica corroborates only itself, and the UNCHANGED classifier
    # therefore reads process_only at any replica count.
    outcome, *_ = _reduce_unit(
        [_r({"x": i}) for i in range(5)], experiment=_EXP, manifest=_PO_MANIFEST
    )
    assert outcome.agreeing_workers == 1
    assert (
        classify_consensus_basis(outcome.agreeing_workers, outcome.method)
        == INTEGRITY_BASIS_PROCESS_ONLY
    )


def test_leaf_binds_lexicographic_first_observation_hash() -> None:
    results = [_r({"x": i}) for i in range(4)]
    expected = min(semantic_hash(0, {"x": i}) for i in range(4))
    outcome, _, _, evidence = _reduce_unit(results, experiment=_EXP, manifest=_PO_MANIFEST)
    assert outcome.semantic_hash == expected
    assert evidence["representative_hash"] == expected
    assert evidence["representative"] is None  # no consensus value, by design


def test_evidence_row_carries_observation_count_not_a_quorum_claim() -> None:
    _, _, _, evidence = _reduce_unit(
        [_r({"x": i}) for i in range(4)], experiment=_EXP, manifest=_PO_MANIFEST
    )
    assert evidence["method"] == PROCESS_ONLY_METHOD
    assert evidence["agreeing_workers"] == 4  # display evidence (observation count)
    assert evidence["spread"] is None and evidence["envelope"] is None


def test_empty_results_defensive_no_agree() -> None:
    outcome, agreeing, outliers, evidence = _reduce_unit([], experiment=_EXP, manifest=_PO_MANIFEST)
    assert outcome.agreed is False and outcome.agreeing_workers == 0
    assert agreeing == [] and outliers == [] and evidence is None


def test_other_reducers_unchanged_by_the_new_branch() -> None:
    # Identical payloads under the default (hash-agreement) manifest still
    # agree exactly as before — the dispatch fall-through is untouched.
    results = [_r({"x": 1}), _r({"x": 1})]
    outcome, agreeing, outliers, _ = _reduce_unit(results, experiment=_EXP, manifest=None)
    assert outcome.agreed and outcome.agreeing_workers == 2
    assert agreeing == results and outliers == []
