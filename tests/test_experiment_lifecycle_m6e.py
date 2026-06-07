"""M6e tests — pause / resume / finalize-submissions + auto-complete."""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.work_units import WorkUnitRepository

AUTHORITY = "testserver"


def _signed_post(client, *, privkey, pubkey_hex, path, payload: dict[str, Any] | None = None):
    body = json.dumps(payload).encode() if payload is not None else b""
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    if body:
        headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=body)


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


# ---- pause / resume routes ----------------------------------------------


def test_researcher_can_pause_own_experiment(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "paused"
    assert body["last_action_by_class"] == "researcher"


def test_maintainer_can_pause(
    client: TestClient,
    approved_experiment,
    maintainer_token: str,
) -> None:
    _, _, experiment, _ = approved_experiment
    response = client.post(
        f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    assert response.json()["last_action_by_class"] == "maintainer"


def test_other_tenant_researcher_cannot_pause(
    client: TestClient,
    approved_experiment,
    tenant_registry,
) -> None:
    _, _, experiment, _ = approved_experiment
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
    response = _signed_post(
        client,
        privkey=other_priv,
        pubkey_hex=other_pub,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "experiment_action_forbidden"


def test_resume_returns_status_to_approved(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/resume",
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


def test_cannot_pause_already_paused(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    first = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )
    assert first.status_code == 200
    second = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "invalid_status_transition"


# ---- finalize-submissions route -----------------------------------------


def test_researcher_can_finalize_submissions(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["submissions_finalized"] is True
    assert body["status"] == "approved"  # status unchanged


def test_finalize_blocks_subsequent_work_unit_submissions(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    # Finalize first.
    _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )
    # Now try to submit work units.
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/work-units",
        payload={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-after-final",
                    "tenant_id": tenant_binding.tenant_id,
                    "experiment_id": experiment.tenant_experiment_label,
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {},
                }
            ]
        },
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "submissions_finalized"


def test_finalize_idempotent(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions"
    first = _signed_post(client, privkey=privkey, pubkey_hex=tenant_binding.pubkey_hex, path=path)
    second = _signed_post(client, privkey=privkey, pubkey_hex=tenant_binding.pubkey_hex, path=path)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["submissions_finalized"] is True


def test_finalize_rejected_on_aborted_experiment(
    client: TestClient,
    approved_experiment,
    experiment_repository,
) -> None:
    privkey, tenant_binding, experiment, _ = approved_experiment
    experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.ABORTED)
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "finalize_not_applicable"


# ---- auto-complete -------------------------------------------------------


def _seed_unit_and_complete(
    client: TestClient,
    per_job_factory: PerJobDatabaseFactory,
    experiment_id: str,
    worker_priv,
    worker_pub,
    worker_id: str,
    unit_id: str = "u1",
):
    """Helper: submit a unit, drive it to completion via 3 results from 3 workers."""
    db = per_job_factory.get_or_create(experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": unit_id, "payload": {}}])
    # First worker fetches + submits.
    pick = _signed_get(
        client,
        privkey=worker_priv,
        pubkey_hex=worker_pub,
        path=f"/api/v0/workers/{worker_id}/assignments",
    ).json()
    _signed_post(
        client,
        privkey=worker_priv,
        pubkey_hex=worker_pub,
        path=f"/api/v0/workers/{worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": worker_pub,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"out": 1},
            "worker_signature": "Zm9v",
        },
    )
    return pick


def test_auto_complete_fires_when_finalized_and_all_done(
    client: TestClient,
    enrolled_worker,
    worker_repository,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository,
) -> None:
    """Finalize + drive 3 workers' results to a single unit → experiment auto-completes."""
    priv1, w1 = enrolled_worker
    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw().hex()
    w2 = worker_repository.enroll(worker_id="wkr-2", pubkey_hex=pub2)
    priv3 = Ed25519PrivateKey.generate()
    pub3 = priv3.public_key().public_bytes_raw().hex()
    w3 = worker_repository.enroll(worker_id="wkr-3", pubkey_hex=pub3)

    res_privkey, tenant_binding, experiment, _ = approved_experiment

    # Submit one work unit.
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    # Finalize submissions.
    _signed_post(
        client,
        privkey=res_privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )

    # Three workers each submit a result.
    for priv, pub, wid in [
        (priv1, w1.pubkey_hex, w1.worker_id),
        (priv2, pub2, w2.worker_id),
        (priv3, pub3, w3.worker_id),
    ]:
        _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments",
        )
        _signed_post(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments/u1/result",
            payload={
                "unit_id": "u1",
                "worker_pubkey": pub,
                "completed_at": "2026-05-19T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"out": 1},
                "worker_signature": "Zm9v",
            },
        )

    final = experiment_repository.get_by_id(experiment.experiment_id)
    assert final.status is ExperimentStatus.COMPLETED
    assert final.last_action_by_class.value == "system"


def test_auto_complete_fires_when_finalize_arrives_after_all_units_done(
    client: TestClient,
    enrolled_worker,
    worker_repository,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository,
) -> None:
    """Regression (autonomic-loop finalize-on-convergence): all units complete
    *before* finalize, so the result-submission auto-complete trigger never
    re-fires — finalize must complete the experiment itself, else it's stuck
    APPROVED + finalized forever (no result-set attestation). Surfaced by the live
    M8 e2e 2026-06-07."""
    priv1, w1 = enrolled_worker
    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw().hex()
    w2 = worker_repository.enroll(worker_id="wkr-2", pubkey_hex=pub2)
    priv3 = Ed25519PrivateKey.generate()
    pub3 = priv3.public_key().public_bytes_raw().hex()
    w3 = worker_repository.enroll(worker_id="wkr-3", pubkey_hex=pub3)

    res_privkey, tenant_binding, experiment, _ = approved_experiment

    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    # All results arrive FIRST → the unit completes, but the experiment is not
    # finalized yet, so the result-path auto-complete correctly does NOT fire.
    for priv, pub, wid in [
        (priv1, w1.pubkey_hex, w1.worker_id),
        (priv2, pub2, w2.worker_id),
        (priv3, pub3, w3.worker_id),
    ]:
        _signed_get(client, privkey=priv, pubkey_hex=pub, path=f"/api/v0/workers/{wid}/assignments")
        _signed_post(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments/u1/result",
            payload={
                "unit_id": "u1",
                "worker_pubkey": pub,
                "completed_at": "2026-05-19T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"out": 1},
                "worker_signature": "Zm9v",
            },
        )

    mid = experiment_repository.get_by_id(experiment.experiment_id)
    assert mid.status is ExperimentStatus.APPROVED  # all units done, but not finalized

    # Finalize AFTER everything is already complete → the finalize path itself must
    # auto-complete (the fix).
    resp = _signed_post(
        client,
        privkey=res_privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )
    assert resp.status_code == 200

    final = experiment_repository.get_by_id(experiment.experiment_id)
    assert final.status is ExperimentStatus.COMPLETED
    assert final.last_action_by_class.value == "system"


def test_auto_complete_does_not_fire_if_not_finalized(
    client: TestClient,
    enrolled_worker,
    worker_repository,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository,
) -> None:
    """All units complete BUT submissions_finalized=False → experiment stays approved."""
    priv1, w1 = enrolled_worker
    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw().hex()
    w2 = worker_repository.enroll(worker_id="wkr-2", pubkey_hex=pub2)
    priv3 = Ed25519PrivateKey.generate()
    pub3 = priv3.public_key().public_bytes_raw().hex()
    w3 = worker_repository.enroll(worker_id="wkr-3", pubkey_hex=pub3)

    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    # DO NOT finalize.
    for priv, pub, wid in [
        (priv1, w1.pubkey_hex, w1.worker_id),
        (priv2, pub2, w2.worker_id),
        (priv3, pub3, w3.worker_id),
    ]:
        _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments",
        )
        _signed_post(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments/u1/result",
            payload={
                "unit_id": "u1",
                "worker_pubkey": pub,
                "completed_at": "2026-05-19T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"out": 1},
                "worker_signature": "Zm9v",
            },
        )

    final = experiment_repository.get_by_id(experiment.experiment_id)
    # Unit is completed, experiment is NOT.
    assert final.status is ExperimentStatus.APPROVED


def test_auto_complete_does_not_fire_when_paused(
    client: TestClient,
    enrolled_worker,
    worker_repository,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository,
) -> None:
    """Paused experiments with finalized=true don't auto-complete even when
    in-flight results finish the last unit."""
    priv1, w1 = enrolled_worker
    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw().hex()
    w2 = worker_repository.enroll(worker_id="wkr-2", pubkey_hex=pub2)
    priv3 = Ed25519PrivateKey.generate()
    pub3 = priv3.public_key().public_bytes_raw().hex()
    w3 = worker_repository.enroll(worker_id="wkr-3", pubkey_hex=pub3)

    res_privkey, tenant_binding, experiment, _ = approved_experiment

    # Submit, assign to all 3 workers first (while approved) so they hold
    # assignments. Then pause. Then results come in.
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    # Each worker grabs an assignment.
    for priv, pub, wid in [
        (priv1, w1.pubkey_hex, w1.worker_id),
        (priv2, pub2, w2.worker_id),
        (priv3, pub3, w3.worker_id),
    ]:
        _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments",
        )

    # Finalize + pause.
    _signed_post(
        client,
        privkey=res_privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions",
    )
    _signed_post(
        client,
        privkey=res_privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment.experiment_id}/actions/pause",
    )

    # Now all 3 results come in.
    for priv, pub, wid in [
        (priv1, w1.pubkey_hex, w1.worker_id),
        (priv2, pub2, w2.worker_id),
        (priv3, pub3, w3.worker_id),
    ]:
        _signed_post(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{wid}/assignments/u1/result",
            payload={
                "unit_id": "u1",
                "worker_pubkey": pub,
                "completed_at": "2026-05-19T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"out": 1},
                "worker_signature": "Zm9v",
            },
        )

    final = experiment_repository.get_by_id(experiment.experiment_id)
    # Unit is completed; experiment is still paused (auto-complete didn't fire).
    assert final.status is ExperimentStatus.PAUSED
