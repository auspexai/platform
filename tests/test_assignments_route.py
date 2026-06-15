"""End-to-end tests for /api/v0/workers/{id}/assignments[/...]."""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.assignments import AssignmentRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from tests._result_helpers import sign_result_body

AUTHORITY = "testserver"


def _signed_get(client, *, privkey, pubkey_hex, path):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _signed_post(client, *, privkey, pubkey_hex, path, payload: dict[str, Any]):
    body = json.dumps(payload).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=body)


def _seed_units(per_job_factory: PerJobDatabaseFactory, experiment_id: str, unit_ids: list[str]):
    db = per_job_factory.get_or_create(experiment_id)
    WorkUnitRepository(db).submit_batch(
        [{"unit_id": uid, "payload": {"input": i}} for i, uid in enumerate(unit_ids)]
    )


# ---- GET /workers/{id}/assignments ---------------------------------------


def test_get_assignment_returns_pending_unit(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, manifest_hash = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1", "u2"])

    response = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["assignment_id"].startswith("asg-")
    assert body["experiment_id"] == experiment.experiment_id
    assert body["work_unit"]["unit_id"] in {"u1", "u2"}
    assert body["work_unit"]["tenant_id"] == experiment.tenant_id
    assert body["work_unit"]["experiment_id"] == experiment.tenant_experiment_label
    assert body["work_unit"]["manifest_sha256"] == manifest_hash
    assert body["work_unit"]["payload"]["input"] in {0, 1}


def test_get_assignment_returns_null_when_no_work(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
) -> None:
    """Approved experiment exists but no work units submitted yet."""
    privkey, worker = enrolled_worker
    response = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["work_unit"] is None


def test_get_assignment_requires_worker_credential(
    client: TestClient,
    enrolled_worker,
) -> None:
    _, worker = enrolled_worker
    response = client.get(f"/api/v0/workers/{worker.worker_id}/assignments")
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_required"


def test_get_assignment_rejects_other_worker_id(
    client: TestClient,
    enrolled_worker,
    worker_repository,
) -> None:
    privkey, worker = enrolled_worker
    other = worker_repository.enroll(worker_id="wkr-other", pubkey_hex="b" * 64)
    response = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{other.worker_id}/assignments",
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_id_mismatch"


def test_repeated_get_does_not_reassign_same_unit(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """A worker that already holds an assignment for u1 should get a
    different unit (u2) on the next call."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1", "u2"])

    first = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()
    second = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()
    assert first["work_unit"]["unit_id"] != second["work_unit"]["unit_id"]


# ---- POST .../result -----------------------------------------------------


def _get_then_submit(
    client,
    *,
    privkey,
    pubkey_hex,
    worker_id,
    result_payload: dict[str, Any],
    exit_code: int = 0,
):
    """Helper: fetch an assignment, then submit a result for it."""
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    path = f"/api/v0/workers/{worker_id}/assignments/{unit_id}/result"
    completed_at = "2026-05-19T12:00:00+00:00"
    return _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=path,
        payload={
            "unit_id": unit_id,
            "worker_pubkey": pubkey_hex,
            "completed_at": completed_at,
            "exit_code": exit_code,
            "payload": result_payload,
            # §9 #13a: the coordinator now verifies the body signature at submit.
            "worker_signature": sign_result_body(
                privkey,
                pubkey_hex,
                unit_id=unit_id,
                completed_at=completed_at,
                exit_code=exit_code,
                payload=result_payload,
            ),
        },
    )


def test_submit_result_first_completion(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    response = _get_then_submit(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        result_payload={"output": 10},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["completions_so_far"] == 1
    assert body["replication_target"] == 3
    # 1 of 3 → still pending status-wise
    assert body["unit_status_after"] in {"pending", "in_progress"}


def test_submit_result_rejects_invalid_body_signature(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """§9 #13a: a body whose worker_signature does not verify is refused at
    submit — kept out of the consensus set — with worker_signature_invalid."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    completed_at = "2026-05-19T12:00:00+00:00"
    # A real Ed25519 signature, but over a DIFFERENT payload than the one sent —
    # valid base64, wrong bytes → must not verify.
    bad_sig = sign_result_body(
        privkey,
        worker.pubkey_hex,
        unit_id=unit_id,
        completed_at=completed_at,
        exit_code=0,
        payload={"tampered": True},
    )
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": completed_at,
            "exit_code": 0,
            "payload": {"output": 10},  # differs from the signed payload
            "worker_signature": bad_sig,
        },
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error"]["code"] == "worker_signature_invalid"


def test_submit_results_until_target_completes_unit(
    client: TestClient,
    enrolled_worker,
    worker_repository,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """Enroll three workers, each submits one result, unit transitions to
    completed when the third comes in."""
    _, w1 = enrolled_worker
    # Need the original priv to sign; using enrolled_worker for w1.
    priv1, _ = enrolled_worker

    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw().hex()
    w2 = worker_repository.enroll(worker_id="wkr-2", pubkey_hex=pub2)

    priv3 = Ed25519PrivateKey.generate()
    pub3 = priv3.public_key().public_bytes_raw().hex()
    w3 = worker_repository.enroll(worker_id="wkr-3", pubkey_hex=pub3)

    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u-quorum"])

    r1 = _get_then_submit(
        client,
        privkey=priv1,
        pubkey_hex=w1.pubkey_hex,
        worker_id=w1.worker_id,
        result_payload={"out": 1},
    )
    r2 = _get_then_submit(
        client,
        privkey=priv2,
        pubkey_hex=pub2,
        worker_id=w2.worker_id,
        result_payload={"out": 1},
    )
    r3 = _get_then_submit(
        client,
        privkey=priv3,
        pubkey_hex=pub3,
        worker_id=w3.worker_id,
        result_payload={"out": 1},
    )

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r3.status_code == 201
    assert r1.json()["completions_so_far"] == 1
    assert r2.json()["completions_so_far"] == 2
    assert r3.json()["completions_so_far"] == 3
    # Third completion crosses the target.
    assert r3.json()["unit_status_after"] == "completed"


def test_submit_result_rejects_wrong_pubkey_in_body(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """body.worker_pubkey must match the signing credential's pubkey."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    # Get an assignment first.
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()

    unit_id = pick["work_unit"]["unit_id"]
    path = f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result"
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=path,
        payload={
            "unit_id": unit_id,
            "worker_pubkey": "b" * 64,  # wrong
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {},
            "worker_signature": "Zm9v",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_pubkey_mismatch"


def test_submit_result_rejects_unit_id_mismatch(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]

    path = f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result"
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=path,
        payload={
            "unit_id": "different-unit",
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {},
            "worker_signature": "Zm9v",
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"]["code"] == "unit_id_mismatch"


def test_submit_result_rejects_without_assignment(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """A worker submitting a result for a unit they were never assigned."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u-never-assigned"])

    path = f"/api/v0/workers/{worker.worker_id}/assignments/u-never-assigned/result"
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=path,
        payload={
            "unit_id": "u-never-assigned",
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {},
            "worker_signature": "Zm9v",
        },
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "assignment_not_found"


def test_submit_result_rejects_double_submission(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    first = _get_then_submit(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        result_payload={"out": 1},
    )
    assert first.status_code == 201
    unit_id = first.json()["unit_id"]

    second = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"out": 2},
            "worker_signature": "Zm9v",
        },
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "result_already_submitted"


# ---- POST refuse ---------------------------------------------------------


def _refuse(client, *, privkey, pubkey_hex, worker_id, unit_id, kind, reason):
    return _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments/{unit_id}/refuse",
        payload={"kind": kind, "reason": reason},
    )


def test_refuse_marks_assignment_and_returns_200(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]

    response = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="manifest_swap",
        reason="testing refuse path",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["unit_id"] == unit_id
    assert body["refused_kind"] == "manifest_swap"
    assert body["refused_at"] is not None


def test_refuse_returns_404_when_no_assignment(
    client: TestClient,
    enrolled_worker,
) -> None:
    privkey, worker = enrolled_worker
    response = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id="u-nonexistent",
        kind="manual",
        reason="no assignment exists",
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "assignment_not_found"


def test_refuse_returns_409_on_double_refuse(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]

    first = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="manual",
        reason="first refusal",
    )
    assert first.status_code == 200

    second = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="manual",
        reason="second refusal",
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "assignment_already_resolved"


def test_refuse_returns_409_when_result_already_attached(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]

    result = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"out": 0},
            "worker_signature": sign_result_body(
                privkey,
                worker.pubkey_hex,
                unit_id=unit_id,
                completed_at="2026-05-19T12:00:00+00:00",
                exit_code=0,
                payload={"out": 0},
            ),
        },
    )
    assert result.status_code == 201

    refused = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="manual",
        reason="too late to refuse",
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["error"]["code"] == "assignment_already_resolved"


def test_refuse_then_other_worker_can_pick_up_unit(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    worker_repository,
) -> None:
    """Refused assignments don't permanently block re-assignment (Q-W4)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    # Single unit, replication_target=3 (default).
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]
    refused = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="tenant_deny",
        reason="this worker doesn't want this tenant",
    )
    assert refused.status_code == 200

    # Enroll a second worker; verify it can pick up the same unit.
    other_pk = Ed25519PrivateKey.generate()
    other_pub = other_pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    other = worker_repository.enroll(worker_id="wkr-other-a", pubkey_hex=other_pub)

    pulled2 = _signed_get(
        client,
        privkey=other_pk,
        pubkey_hex=other_pub,
        path=f"/api/v0/workers/{other.worker_id}/assignments",
    )
    assert pulled2.status_code == 200
    assert pulled2.json()["work_unit"] is not None
    assert pulled2.json()["work_unit"]["unit_id"] == unit_id


def test_retryable_refusal_reoffers_same_worker_via_get(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """§2.1 #8 dispatch-retry: a worker that refused for an environmental
    reason (runner crash) is re-offered the same unit on its next poll — the
    assignment row is reactivated (attempt_count bumped), not duplicated."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]
    refused = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="runner_failed",
        reason="sandbox runner crashed",
    )
    assert refused.status_code == 200

    # Same worker polls again → re-offered the same unit.
    repulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert repulled.status_code == 200
    assert repulled.json()["work_unit"] is not None
    assert repulled.json()["work_unit"]["unit_id"] == unit_id

    # The row was reactivated in place (single row, refusal cleared, attempt 2).
    db = per_job_factory.get_or_create(experiment.experiment_id)
    rows = AssignmentRepository(db).list_for_unit(unit_id)
    assert len(rows) == 1
    assert rows[0].refused_at is None
    assert rows[0].attempt_count == 2


def test_terminal_refusal_not_reoffered_to_same_worker_via_get(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
) -> None:
    """A policy refusal (tenant deny) keeps the refusing worker excluded — its
    next poll gets no work (re-offering would just refuse again)."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    unit_id = pulled.json()["work_unit"]["unit_id"]
    refused = _refuse(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        unit_id=unit_id,
        kind="refused_tenant_deny",
        reason="this worker denies this tenant",
    )
    assert refused.status_code == 200

    repulled = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert repulled.status_code == 200
    assert repulled.json()["work_unit"] is None


def test_late_result_does_not_refire_completion(
    client: TestClient,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    worker_repository,
) -> None:
    """M9 leg 3: a unit at replication_target=1 completes on the first result;
    a SECOND (late, e.g. rejoined-worker) result for the same unit is accepted +
    stored as a durable replica but must NOT re-fire the completion machinery —
    receipts are issued exactly once across both submissions."""
    from auspexai_platform.receipts.repository import ReceiptRepository

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)

    # Warm the APP-side per-job cache: submit_result's `_find_assignment` scans the
    # app factory's cached DBs, and a GET runs the scheduler (which get_or_creates the
    # experiment DB) even when it returns no work — here the T0 tier floor (3) refuses
    # the target=1 unit, so the GET is null but the cache is warmed.
    warm = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert warm.json()["work_unit"] is None

    # Pre-create worker A's assignment directly — leg 3 exercises the submit-path
    # idempotency, not scheduling, so we bypass pick_for_worker (whose T0 tier floor
    # of 3 would refuse a replication_target=1 unit anyway).
    AssignmentRepository(db).create(
        assignment_id="asg-a",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    first = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments/u1/result",
        payload={
            "unit_id": "u1",
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": "2026-06-06T11:00:00+00:00",
            "exit_code": 0,
            "payload": {"v": 1},
            "worker_signature": sign_result_body(
                privkey,
                worker.pubkey_hex,
                unit_id="u1",
                completed_at="2026-06-06T11:00:00+00:00",
                exit_code=0,
                payload={"v": 1},
            ),
        },
    )
    assert first.status_code == 201, first.text
    assert first.json()["unit_status_after"] == "completed"
    receipts_after_first = ReceiptRepository(db).list_for_unit("u1")

    # A late worker B (rejoined after a pause) still holds an open assignment for u1
    # — the unit completed on A while B was out. Pre-create B's assignment, then it
    # submits. The 409 guard is per-assignment (B's has no result yet), so the submit
    # is accepted; but `just_completed` is False, so no re-fire.
    other_pk = Ed25519PrivateKey.generate()
    other_pub = other_pk.public_key().public_bytes_raw().hex()
    other = worker_repository.enroll(worker_id="wkr-late", pubkey_hex=other_pub)
    AssignmentRepository(db).create(
        assignment_id="asg-late",
        unit_id="u1",
        worker_id=other.worker_id,
        worker_pubkey_hex=other_pub,
    )
    late = _signed_post(
        client,
        privkey=other_pk,
        pubkey_hex=other_pub,
        path=f"/api/v0/workers/{other.worker_id}/assignments/u1/result",
        payload={
            "unit_id": "u1",
            "worker_pubkey": other_pub,
            "completed_at": "2026-06-06T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"v": 1},
            "worker_signature": sign_result_body(
                other_pk,
                other_pub,
                unit_id="u1",
                completed_at="2026-06-06T12:00:00+00:00",
                exit_code=0,
                payload={"v": 1},
            ),
        },
    )
    assert late.status_code == 201, late.text
    # The late result is stored (durable extra replica) and completions ticked up,
    # but the unit stays completed and the completion machinery did NOT re-fire.
    final_unit = WorkUnitRepository(db).get_by_unit_id("u1")
    assert final_unit.status.value == "completed"
    assert final_unit.completions_so_far == 2  # both replicas counted (durable)
    assert ReceiptRepository(db).list_for_unit("u1") == receipts_after_first


def test_paused_worker_gets_423_with_reason(
    client: TestClient,
    enrolled_worker,
    worker_repository,
) -> None:
    """§2.1 #11: an operator-paused worker's /assignments poll returns 423
    worker_paused (no-fault) carrying the maintainer's reason — so the volunteer
    learns it was paused + why, just like quarantine."""
    privkey, worker = enrolled_worker
    worker_repository.pause(worker.worker_id, "rolling upgrade")
    resp = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    )
    assert resp.status_code == 423
    err = resp.json()["detail"]["error"]
    assert err["code"] == "worker_paused"
    assert err["details"]["pause_reason"] == "rolling upgrade"
    assert err["details"]["no_fault"] is True


def test_prestage_directs_auto_acquire_worker(
    client: TestClient,
    enrolled_worker,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    worker_repository,
) -> None:
    """M3b: GET /prestage returns the conductor's directives for an eligible
    auto-acquire worker (a model-gated approved experiment with manifest coords)."""
    from auspexai_platform.db.models import ExperimentStatus

    privkey, worker = enrolled_worker
    _, binding = registered_tenant
    worker_repository.record_heartbeat(
        worker.worker_id, capabilities={"os": "linux", "auto_acquire": True}
    )
    manifest = manifest_repository.insert(
        tenant_id=binding.tenant_id,
        manifest_json={
            "tenant_id": binding.tenant_id,
            "experiment_id": "exp-ps",
            "models": [
                {
                    "id": "m-x",
                    "version": "1",
                    "local_weights_required": True,
                    "hf_repo": "Org/M-GGUF",
                    "hf_filename": "M-Q4.gguf",
                }
            ],
        },
        signature_json={},
    )
    exp = experiment_repository.create(
        tenant_id=binding.tenant_id,
        tenant_experiment_label="exp-ps",
        manifest_hash=manifest.manifest_hash,
        required_capabilities={"models": ["m-x"]},
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)

    resp = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/prestage",
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["prestage"]
    assert [i["model_id"] for i in items] == ["m-x"]
    assert items[0]["hf_repo"] == "Org/M-GGUF"
    assert items[0]["hf_filename"] == "M-Q4.gguf"
