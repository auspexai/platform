"""A6 — firewall-conformance suite (the NAMED invariant index).

Per a6_conformance_invariants_scope.md, A6 must prove *named* properties, not
"some tests." Most F1/F3 invariants are already proven by targeted tests; this
module is the auditable index that maps each named invariant to its proof, fills
the one gap (F1-b — no dedicated "disagreement earns/costs no trust" test), and
tracks the sole deferral (F1-c, which needs the equal-trust flip / A2, gated on
A7). The coverage test fails if an invariant is added/dropped without updating the
map — so the conformance set can't silently lose a property.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auspexai_platform.db.models import Result
from auspexai_platform.receipts.issuance import hash_agreement_reducer

# The named firewall invariants (a6 scope) → where each is proven, or DEFERRED.
_CONFORMANCE: dict[str, str] = {
    # Firewall #1 — decouple trust from conformity / divergence receipts
    "F1-a": "test_attestation.py::TestDivergedUnits + test_diverged_units_ride_predicate "
    "(divergence is recorded in the signed predicate, never silently dropped)",
    "F1-b": "this file::test_f1b_disagreement_earns_no_consensus_trust "
    "(disagreement → no agreement → no receipt/trust; demotion is maintainer-only, "
    "no auto-demote path exists — the no-cost half)",
    "F1-c": "DEFERRED — equal-trust flip (A2) not built (gated on A7). The 'trust path "
    "reads only process-attestation' invariant is proven WITH the flip.",
    "F1-d": "test_attestation.py::test_classify_consensus_basis + "
    "test_footprint.py::test_assert_footprint_recomputable_passes_and_raises "
    "(integrity_basis recorded AND consulted — the F6 recompute guard reads it)",
    "F1-e": "test_assignments_route.py::test_submit_result_with_invalid_worker_signature + "
    "test_weights.py::test_anti_fab_signed_weights_override_heartbeat "
    "(single-worker fabrication refused at submit, 422; served-weights bound)",
    # Firewall #3 — independence floor (account-weighted)
    "F3-a": "test_independence_floor_a4.py::test_within_account_same_unit_collapses_to_one "
    "(trust is account-weighted, not per-pubkey)",
    "F3-b": "test_independence_floor_a4.py + the T2 auto-promote / vouch gates "
    "(account_corroboration_summary is the metric the gates consult)",
    "F3-c": "test_independence_floor_a4.py::test_one_controller_many_pubkeys_is_bounded_per_account "
    "(M pubkeys across K accounts → bounded per account)",
}

_EXPECTED_INVARIANTS = {"F1-a", "F1-b", "F1-c", "F1-d", "F1-e", "F3-a", "F3-b", "F3-c"}


def test_a6_conformance_coverage_is_complete_and_tracks_the_sole_deferral():
    """The named-invariant index covers exactly the a6-scope set, and F1-c is the
    ONLY deferral — so adding/dropping an invariant (or quietly deferring another)
    breaks this test rather than silently eroding the conformance set."""
    assert set(_CONFORMANCE) == _EXPECTED_INVARIANTS
    deferred = sorted(k for k, v in _CONFORMANCE.items() if v.startswith("DEFERRED"))
    assert deferred == ["F1-c"]


def _result(payload: dict, *, pubkey: str, rid: str) -> Result:
    now = datetime.now(UTC)
    return Result(
        result_id=rid,
        unit_id="u-1",
        worker_id=f"wkr-{rid}",
        worker_pubkey_hex=pubkey,
        exit_code=0,
        payload=payload,
        worker_signature="dGVzdA==",
        completed_at=now,
        received_at=now,
    )


def test_f1b_disagreement_earns_no_consensus_trust():
    """F1-b (testable-now half): a divergent result earns NO agreement, so no
    receipt is issued and no trust is minted — and the converse, agreement still
    counts. (The full 'trust does not key on agreement' lands with the flip / F1-c;
    the no-DEMOTION half is structural — `demote()` is maintainer-only, no auto path.)
    """
    a = _result({"x": 1}, pubkey="aa" * 32, rid="res-a")
    diverging = _result({"x": 2}, pubkey="bb" * 32, rid="res-b")
    out = hash_agreement_reducer([a, diverging])
    assert out.agreed is False, "disagreement must not reach agreement"
    assert out.agreeing_workers == 0, "no worker earns consensus trust on divergence"

    # Sanity (the converse): genuine agreement still counts — the floor doesn't
    # break the normal path.
    agreeing = _result({"x": 1}, pubkey="cc" * 32, rid="res-c")
    ok = hash_agreement_reducer([a, agreeing])
    assert ok.agreed is True and ok.agreeing_workers == 2


@pytest.mark.skip(reason="F1-c deferred: equal-trust flip (A2) not built — gated on A7")
def test_f1c_equal_trust_flip_reads_only_process_attestation():
    """Placeholder so the deferred invariant is visible in the suite. Implement
    alongside the equal-trust flip (A2): assert the trust path consults containment
    / integrity_basis / attestation and never 'agreed-with-majority'."""
