"""End-to-end tests for /api/v0/experiments/{id}/work-units."""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import ExperimentStatus

AUTHORITY = "testserver"


def _signed_post(
    client: TestClient,
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    path: str,
    payload: dict[str, Any],
):
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


def _signed_get(
    client: TestClient,
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    path: str,
):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _make_unit(
    *, unit_id: str, tenant_id: str, label: str, manifest_hash: str, payload: dict
) -> dict:
    return {
        "schema_version": "0.1",
        "unit_id": unit_id,
        "tenant_id": tenant_id,
        "experiment_id": label,
        "manifest_sha256": manifest_hash,
        "created_at": "2026-05-19T00:00:00Z",
        "payload": payload,
    }


# ---- POST /experiments/{id}/work-units ----------------------------------


def test_submit_batch_succeeds_for_researcher(
    client: TestClient,
    approved_experiment,
) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={"input": 5},
            ),
            _make_unit(
                unit_id="u2",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={"input": 7},
            ),
        ]
    }
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=payload,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["count"] == 2
    assert set(body["submitted_unit_ids"]) == {"u1", "u2"}


def test_submit_requires_researcher(client: TestClient, approved_experiment) -> None:
    _, tenant_binding, experiment, manifest_hash = approved_experiment
    response = client.post(
        f"/api/v0/experiments/{experiment.experiment_id}/work-units",
        json={
            "work_units": [
                _make_unit(
                    unit_id="u1",
                    tenant_id=tenant_binding.tenant_id,
                    label=experiment.tenant_experiment_label,
                    manifest_hash=manifest_hash,
                    payload={},
                )
            ]
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "researcher_required"


def test_submit_rejects_other_tenants_experiment(
    client: TestClient,
    approved_experiment,
    tenant_registry,
) -> None:
    """Different tenant's researcher cannot submit to this experiment."""
    _, _, experiment, manifest_hash = approved_experiment
    # Need a separate keypair + tenant from the fixture's tenant.
    fresh_priv = Ed25519PrivateKey.generate()
    fresh_pub = fresh_priv.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=fresh_pub)

    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id="other-tenant",
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={},
            )
        ]
    }
    response = _signed_post(
        client, privkey=fresh_priv, pubkey_hex=fresh_pub, path=path, payload=payload
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "experiment_tenant_mismatch"


def test_submit_rejects_when_experiment_submitted_status(
    client: TestClient,
    registered_tenant,
    manifest_repository,
    experiment_repository,
) -> None:
    """Experiments in 'submitted' status (pending approval) cannot receive
    work units."""
    privkey, tenant_binding = registered_tenant
    manifest = manifest_repository.insert(
        tenant_id=tenant_binding.tenant_id,
        manifest_json={"tenant_id": tenant_binding.tenant_id, "experiment_id": "exp-label"},
        signature_json={},
    )
    experiment = experiment_repository.create(
        tenant_id=tenant_binding.tenant_id,
        tenant_experiment_label="exp-label",
        manifest_hash=manifest.manifest_hash,
    )
    # status defaults to 'submitted' — DO NOT approve.

    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label="exp-label",
                manifest_hash=manifest.manifest_hash,
                payload={},
            )
        ]
    }
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=payload,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "experiment_not_open_for_submissions"


def test_submit_allows_paused_experiment(
    client: TestClient,
    approved_experiment,
    experiment_repository,
) -> None:
    """Paused experiments still accept new work-unit submissions; they just
    don't get scheduled until resumed."""
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    # M5 doesn't yet support paused transition route-side; do it at the repo
    # level. (M6e adds the route action.)
    experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.PAUSED)

    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u-pause",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={},
            )
        ]
    }
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=payload,
    )
    assert response.status_code == 201, response.text


def test_submit_rejects_manifest_swap(
    client: TestClient,
    approved_experiment,
) -> None:
    """§5.14 manifest-swap protection: the body's manifest_sha256 must match
    the experiment's manifest_hash."""
    privkey, tenant_binding, experiment, _ = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash="b" * 64,  # wrong hash
                payload={},
            )
        ]
    }
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=payload,
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"]["code"] == "work_unit_manifest_mismatch"


def test_submit_rejects_duplicate_unit_id_in_batch(client: TestClient, approved_experiment) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    payload = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={"a": 1},
            ),
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={"a": 2},
            ),
        ]
    }
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=payload,
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"]["code"] == "duplicate_unit_id_in_batch"


def test_submit_rejects_unit_id_collision_across_batches(
    client: TestClient, approved_experiment
) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    first = {
        "work_units": [
            _make_unit(
                unit_id="u1",
                tenant_id=tenant_binding.tenant_id,
                label=experiment.tenant_experiment_label,
                manifest_hash=manifest_hash,
                payload={},
            )
        ]
    }
    assert (
        _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=tenant_binding.pubkey_hex,
            path=path,
            payload=first,
        ).status_code
        == 201
    )

    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload=first,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "unit_id_already_submitted"


# ---- GET list -----------------------------------------------------------


def test_list_after_submit_shows_units(client: TestClient, approved_experiment) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
        payload={
            "work_units": [
                _make_unit(
                    unit_id="u1",
                    tenant_id=tenant_binding.tenant_id,
                    label=experiment.tenant_experiment_label,
                    manifest_hash=manifest_hash,
                    payload={"x": 1},
                )
            ]
        },
    )
    response = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=path,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["work_units"]) == 1
    assert body["work_units"][0]["unit_id"] == "u1"
    # Researcher (their own tenant) sees payload (TENANT_SCOPED).
    assert body["work_units"][0]["payload"] == {"x": 1}
    assert body["counts_by_status"] == {"pending": 1}


def test_list_before_any_submit_returns_empty(
    client: TestClient,
    approved_experiment,
    maintainer_token: str,
) -> None:
    """No work units submitted yet → empty list, no per-job DB created."""
    _, _, experiment, _ = approved_experiment
    response = client.get(
        f"/api/v0/experiments/{experiment.experiment_id}/work-units",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["work_units"] == []
    assert body["counts_by_status"] == {}


def test_list_rejects_other_tenant_researcher(
    client: TestClient,
    approved_experiment,
    tenant_registry,
) -> None:
    """Tenant-private (§3): a non-owning researcher gets the same 404 as a
    missing experiment, so work-units never confirm an experiment id exists."""
    _, _, experiment, _ = approved_experiment
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
    response = _signed_get(
        client,
        privkey=other_priv,
        pubkey_hex=other_pub,
        path=f"/api/v0/experiments/{experiment.experiment_id}/work-units",
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "experiment_not_found"


# ---- GET detail ---------------------------------------------------------


def test_get_detail_returns_unit(client: TestClient, approved_experiment) -> None:
    privkey, tenant_binding, experiment, manifest_hash = approved_experiment
    base_path = f"/api/v0/experiments/{experiment.experiment_id}/work-units"
    _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=base_path,
        payload={
            "work_units": [
                _make_unit(
                    unit_id="u-detail",
                    tenant_id=tenant_binding.tenant_id,
                    label=experiment.tenant_experiment_label,
                    manifest_hash=manifest_hash,
                    payload={"k": "v"},
                )
            ]
        },
    )
    response = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path=f"{base_path}/u-detail",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["unit_id"] == "u-detail"
    assert body["status"] == "pending"
    assert body["payload"] == {"k": "v"}


def test_get_detail_unknown_returns_404(
    client: TestClient, approved_experiment, maintainer_token: str
) -> None:
    _, _, experiment, _ = approved_experiment
    # No per-job DB exists yet at all.
    response = client.get(
        f"/api/v0/experiments/{experiment.experiment_id}/work-units/u-nope",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 404


def test_unknown_experiment_returns_404_on_submit(client: TestClient, registered_tenant) -> None:
    privkey, tenant_binding = registered_tenant
    response = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=tenant_binding.pubkey_hex,
        path="/api/v0/experiments/exp-nope/work-units",
        payload={
            "work_units": [
                _make_unit(
                    unit_id="u1",
                    tenant_id=tenant_binding.tenant_id,
                    label="some-label",
                    manifest_hash="a" * 64,
                    payload={},
                )
            ]
        },
    )
    assert response.status_code == 404
