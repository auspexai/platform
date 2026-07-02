"""D16.5 — the epistemic-integrity conformance suite (pass #8 Push 2).

The A6 analog for the epistemic axis: NAMED invariants proving the composition
holds across every surface that touches the pre-registered design. Because
D16.2 built the envelope BY REFERENCE (pre_registration.features name
feature_schema paths; the envelope IS each feature's `comparison` in the same
signed manifest), the feared three-way seam (pre-reg comparison ≡ manifest
tolerance envelope ≡ feature-schema comparison) cannot drift — these tests pin
that structure and the one place it could regress: a second envelope sneaking
into the contract, a write-only epistemic field, or a surface serving a
different declaration than the manifest's.
"""

from __future__ import annotations

from base64 import b64decode

import cbor2
from fastapi.testclient import TestClient

from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import UnitConsensusRepository
from auspexai_platform.pre_registration import _KNOWN_FIELDS, validate_pre_registration
from auspexai_platform.receipts.issuance import TOLERANCE_METHOD
from auspexai_platform.receipts.signing import cose_sign1_decode
from tests.test_attestation import _seed_consensus_unit, _signed_get
from tests.test_experiments_route import _manifest, _submit_as_researcher
from tests.test_pre_registration import FS, PRE_REG

# The PUBLISHED v0.4 pre_registration member set (schemas/manifest_v0_4.json in
# tenant-sdk — the contract both sides implement independently). The SDK-side
# twin (tenant-sdk tests/test_epistemic_conformance.py) asserts its Pydantic
# model equals the schema file; THIS literal pins the coordinator mirror to the
# same contract. Change the contract → both suites fail together, by design.
_PUBLISHED_FIELDS = frozenset(
    {
        "version",
        "hypothesis",
        "analysis_method",
        "features",
        "timescale",
        "decision_rule",
        "expected_result",
        "stopping_rule",
        "comparison_keys",
        "min_replication",
    }
)


def test_invariant_mirror_matches_published_contract() -> None:
    """INVARIANT: the coordinator's mirror validates exactly the published
    member set — no phantom fields accepted, none silently dropped."""
    assert _KNOWN_FIELDS == _PUBLISHED_FIELDS


def test_invariant_no_second_envelope_can_enter() -> None:
    """INVARIANT (one-declaration): the pre-registration cannot carry its own
    comparison numbers — an attempted `comparison` member is an unknown field
    (the envelope lives ONLY in feature_schema, referenced by name)."""
    m = {
        "schema_version": "0.4",
        "feature_schema": FS,
        "pre_registration": {**PRE_REG, "comparison": {"lexical.type_token_ratio": {"rel": 0.5}}},
    }
    errs = validate_pre_registration(m)
    assert any("unknown fields" in e for e in errs)


def test_invariant_every_named_feature_is_enveloped() -> None:
    """INVARIANT: a design can only pre-register analyses over features whose
    envelope is DECLARED — naming an un-enveloped feature is rejected, so there
    is never a pre-registered analysis without its calibratable envelope."""
    m = {
        "schema_version": "0.4",
        "feature_schema": FS,
        "pre_registration": {**PRE_REG, "features": ["eval_count"]},  # no comparison
    }
    assert any("no 'comparison'" in e for e in validate_pre_registration(m))


def test_invariant_e2e_every_surface_reads_the_one_declaration(
    client: TestClient,
    registered_tenant,
    enrolled_worker,
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository,
    experiment_repository,
) -> None:
    """FLAGSHIP e2e: submit a pre-registered Vigiles-shaped experiment → a
    tolerance-consensus unit with its issuance evidence → the COMPLETED
    attestation. Assert the SIGNED predicate serves (a) the pre-registration
    reference binding this experiment's manifest hash, and (b) the per-unit
    tolerance envelope EQUAL to the manifest's feature_schema comparison — the
    envelope the pre-registration references. One declaration, every surface."""
    privkey, binding = registered_tenant
    _, worker = enrolled_worker

    resp = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "epistemic-e2e-001",
            schema_version="0.4",
            feature_schema=FS,
            pre_registration=dict(PRE_REG),
            reducer={"kind": TOLERANCE_METHOD},
        ),
    )
    assert resp.status_code == 201, resp.text
    exp_id = resp.json()["experiment_id"]
    manifest_hash = resp.json()["manifest_hash"]

    # The submit-time anchor row exists (placeholder sentinels until the sweep).
    prereg = client.app.state.pre_registration_repository.get(exp_id)
    assert prereg is not None and prereg.manifest_hash == manifest_hash

    # A tolerance-consensus unit whose issuance evidence carries THE MANIFEST'S
    # envelope (in production _reduce_unit reads it from the manifest — the C7
    # Inc 4 tests cover that link; here we pin the surface chain end-to-end).
    declared_envelope = {"lexical.type_token_ratio": FS["lexical.type_token_ratio"]["comparison"]}
    _seed_consensus_unit(
        per_job_factory,
        receipt_index_repository,
        exp_id,
        unit_id="u-pr",
        payload={"lexical": {"type_token_ratio": 0.5}},
        worker_id=worker.worker_id,
        replication_target=2,
        method=TOLERANCE_METHOD,
    )
    UnitConsensusRepository(per_job_factory.get_or_create(exp_id)).record(
        unit_id="u-pr",
        method=TOLERANCE_METHOD,
        representative={"lexical.type_token_ratio": 0.5},
        representative_hash="ab" * 32,
        spread={"lexical.type_token_ratio": 0.0},
        envelope=declared_envelope,
        agreeing_workers=2,
        outlier_count=0,
    )
    experiment_repository.update_status(exp_id, ExperimentStatus.APPROVED)
    experiment_repository.update_status(exp_id, ExperimentStatus.COMPLETED)

    resp = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path=f"/api/v0/experiments/{exp_id}/attestation",
    )
    assert resp.status_code == 200, resp.text
    key = client.app.state.receipt_signing_key
    payload, _ = cose_sign1_decode(
        b64decode(resp.json()["cose_b64"]), expected_pubkey=key.public_key
    )
    predicate = cbor2.loads(cbor2.loads(payload)["predicate"])

    # (a) the finding is bound to the design it claims to test
    assert predicate["pre_registration"]["manifest_hash"] == manifest_hash
    # (b) the unit's served envelope IS the manifest's declared comparison —
    # the same object the pre-registration references by feature name.
    unit = next(u for u in predicate["units"] if u["unit_id"] == "u-pr")
    assert unit["tolerance"]["envelope"] == declared_envelope
    assert unit["consensus_result_hash"] == "ab" * 32  # the representative leaf
