"""A6 — firewall-conformance suite (the NAMED invariant index).

Per a6_conformance_invariants_scope.md, A6 must prove *named* properties, not
"some tests." Most F1/F3 invariants are already proven by targeted tests; this
module is the auditable index that maps each named invariant to its proof, fills
the F1-b gap (no dedicated "disagreement earns/costs no trust" test), and — now
that the equal-trust flip (A2) is built — proves F1-c here too (no deferrals
remain). The coverage test fails if an invariant is added/dropped without updating
the map — so the conformance set can't silently lose a property.
"""

from __future__ import annotations

from datetime import UTC, datetime

from auspexai_platform.db.models import IdentityProvider, Result, TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.receipts.issuance import hash_agreement_reducer

# The named firewall invariants (a6 scope) → where each is proven, or DEFERRED.
_CONFORMANCE: dict[str, str] = {
    # Firewall #1 — decouple trust from conformity / divergence receipts
    "F1-a": "test_attestation.py::TestDivergedUnits + test_diverged_units_ride_predicate "
    "(divergence is recorded in the signed predicate, never silently dropped)",
    "F1-b": "this file::test_f1b_disagreement_earns_no_consensus_trust "
    "(disagreement → no agreement → no receipt/trust; demotion is maintainer-only, "
    "no auto-demote path exists — the no-cost half)",
    "F1-c": "this file::test_f1c_agreement_and_divergence_earn_identical_trust_under_flip "
    "(equal-trust accrual keys on STRICT containment; agreement and divergence earn "
    "identical trust — the trust path never reads integrity_basis/agreement)",
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


def test_a6_conformance_coverage_is_complete_with_no_deferrals():
    """The named-invariant index covers exactly the a6-scope set, and — now that the
    equal-trust flip is built — NOTHING is deferred. Adding/dropping an invariant
    (or quietly deferring one) breaks this test rather than silently eroding the set."""
    assert set(_CONFORMANCE) == _EXPECTED_INVARIANTS
    deferred = sorted(k for k, v in _CONFORMANCE.items() if v.startswith("DEFERRED"))
    assert deferred == []


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


def test_f1c_agreement_and_divergence_earn_identical_trust_under_flip(db):
    """F1-c (now built): under the equal-trust flip, the trust path keys on the
    process bundle (STRICT containment) and NEVER on agreement. Proof — an account
    whose unit AGREED and an account whose unit DIVERGED, both STRICT, earn IDENTICAL
    trust. The accrual reads `ran_under_strict`, never `integrity_basis`/agreement."""
    accounts = AccountRepository(db)
    tenants = TenantRepository(db)
    workers = WorkerRepository(db)
    experiments = ExperimentRepository(db)
    manifests = ManifestRepository(db)
    receipts = ReceiptIndexRepository(db)

    tenants.register(tenant_id="t", maintainer_pubkey="aa" * 32)
    m = manifests.insert(
        tenant_id="t",
        manifest_json={"tenant_id": "t", "experiment_id": "e", "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    exp = experiments.create(
        tenant_id="t", tenant_experiment_label="e", manifest_hash=m.manifest_hash
    )
    for acct, sub, wid, pk in (
        ("agree", "1", "w-a", "11" * 32),
        ("diverge", "2", "w-d", "22" * 32),
    ):
        accounts.create(account_id=acct, idp=IdentityProvider.GITHUB, idp_sub=sub)
        workers.enroll(worker_id=wid, pubkey_hex=pk)
        workers.bind_account(wid, account_id=acct, trust_tier=TrustTier.T1_AUTHENTICATED)

    # Identical work, identical STRICT containment — only the agreement outcome differs.
    receipts.record(
        receipt_id="r",
        experiment_id=exp.experiment_id,
        worker_id="w-a",
        worker_pubkey="11" * 32,
        unit_id="u",
        ran_under_strict=True,
    )
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="w-d",
        worker_pubkey="22" * 32,
        unit_id="u",
        ran_under_strict=True,
    )
    agree = receipts.account_corroboration_summary("agree", equal_trust_enabled=True)[0]
    diverge = receipts.account_corroboration_summary("diverge", equal_trust_enabled=True)[0]
    assert agree == diverge == 1, "F1-c: agreement and divergence must earn identical trust"
