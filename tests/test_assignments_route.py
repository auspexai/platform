"""End-to-end tests for /api/v0/workers/{id}/assignments[/...]."""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.work_units import WorkUnitRepository

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
    return _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=path,
        payload={
            "unit_id": unit_id,
            "worker_pubkey": pubkey_hex,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": exit_code,
            "payload": result_payload,
            "worker_signature": "ZmFrZS1zaWc=",  # base64 placeholder
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
