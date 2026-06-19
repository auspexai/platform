"""A2 #32 — the v2 submit path: the worker-SIGNED `ran_under` is verified, stored,
and used; and a result that signs WEAKER than the experiment requires is rejected
as provable misconduct (the demote/suspend lever). End-to-end through the route.
"""

from __future__ import annotations

import json

from tests._result_helpers import sign_result_body
from tests.test_assignments_route import _seed_units, _signed_get, _signed_post

_TS = "2026-05-19T12:00:00+00:00"


def _submit_v2(client, *, privkey, pubkey_hex, worker_id, ran_under, payload=None):
    payload = payload if payload is not None else {"output": 7}
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments",
    ).json()
    assert pick["work_unit"] is not None, "worker was not assigned a unit"
    unit_id = pick["work_unit"]["unit_id"]
    sig = sign_result_body(
        privkey,
        pubkey_hex,
        unit_id=unit_id,
        completed_at=_TS,
        exit_code=0,
        payload=payload,
        schema_version=2,
        ran_under=ran_under,
    )
    resp = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": pubkey_hex,
            "completed_at": _TS,
            "exit_code": 0,
            "payload": payload,
            "worker_signature": sig,
            "schema_version": 2,
            "ran_under": ran_under,
        },
    )
    return unit_id, resp


def _make_strict_capable(db, worker_id):
    db.execute(
        "UPDATE workers SET capabilities_json = ? WHERE worker_id = ?",
        (json.dumps({"os": "linux", "sandbox_policy": "strict"}), worker_id),
    )


def test_v2_strict_accepted_and_signed_value_stored(
    client, enrolled_worker, approved_experiment, per_job_factory
):
    """A v2 result verifies WITH ran_under and persists the SIGNED value — so
    issuance reads the signed containment, not the heartbeat capability. (Running
    STRICTER than a permissive-required experiment is allowed.)"""
    from auspexai_platform.db.repositories.results import ResultRepository

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    unit_id, resp = _submit_v2(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        ran_under="strict",
    )
    assert resp.status_code == 201, resp.text
    stored = ResultRepository(per_job_factory.get(experiment.experiment_id)).list_for_unit(unit_id)
    assert stored[0].ran_under == "strict"


def test_v2_permissive_on_strict_required_is_containment_violation(
    client, enrolled_worker, approved_experiment, per_job_factory, db
):
    """The misconduct lever: a worker assigned strict-REQUIRED work that SIGNS
    permissive has signed an admission of non-compliance → 409 + audited."""
    from auspexai_platform.db.repositories import ExperimentRepository

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _make_strict_capable(db, worker.worker_id)
    ExperimentRepository(db).set_required_containment(experiment.experiment_id, "strict")
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    _unit, resp = _submit_v2(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        ran_under="permissive",
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"]["code"] == "containment_violation"
    rows = db.execute("SELECT 1 FROM audit_log WHERE action = 'result.containment_violation'")
    assert len(rows) >= 1


def test_v2_strict_on_strict_required_is_compliant(
    client, enrolled_worker, approved_experiment, per_job_factory, db
):
    """The compliant case: strict-required + signed strict → accepted (no false
    positive from the contradiction check)."""
    from auspexai_platform.db.repositories import ExperimentRepository

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _make_strict_capable(db, worker.worker_id)
    ExperimentRepository(db).set_required_containment(experiment.experiment_id, "strict")
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    _unit, resp = _submit_v2(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        ran_under="strict",
    )
    assert resp.status_code == 201, resp.text


def test_result_ran_strict_prefers_signed_over_capability(db):
    """The trust resolver reads the SIGNED ran_under first; the worker's heartbeat
    capability is only a pre-v2 fallback. So a worker REPORTING strict can't make a
    permissive-SIGNED result count as strict — the signed (accountable) claim wins."""
    import types

    from auspexai_platform.api.assignments import _result_ran_strict
    from auspexai_platform.db.repositories import WorkerRepository

    workers = WorkerRepository(db)
    workers.enroll(worker_id="w1", pubkey_hex="11" * 32, capabilities={"sandbox_policy": "strict"})

    # Signed strict → strict.
    assert _result_ran_strict(workers, types.SimpleNamespace(ran_under="strict", worker_id="w1"))
    # Signed permissive BEATS a strict capability — the signed claim wins.
    assert not _result_ran_strict(
        workers, types.SimpleNamespace(ran_under="permissive", worker_id="w1")
    )
    # Pre-v2 (no signed value) → falls back to the reported capability (strict).
    assert _result_ran_strict(workers, types.SimpleNamespace(ran_under=None, worker_id="w1"))
