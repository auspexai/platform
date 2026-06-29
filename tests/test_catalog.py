"""The model catalog route (GET /api/v0/models/catalog).

Restored after AUD-18 (1375456) deleted it as collateral with the model-request
queues — it's a read-only aggregate over active workers' declared models, with
live consumers (the SDK `model catalog` command + the R-D Requests page)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _mh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_catalog_route_is_mounted(client: TestClient, maintainer_token: str) -> None:
    r = client.get("/api/v0/models/catalog", headers=_mh(maintainer_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert "models" in body and "total_active_workers" in body


def test_catalog_reflects_active_worker_models(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    worker_repository.enroll(
        worker_id="wkr-cat1", pubkey_hex="a1" * 32, capabilities={"models": ["gemma-3-1b-it-q4"]}
    )
    worker_repository.record_heartbeat("wkr-cat1", capabilities={"models": ["gemma-3-1b-it-q4"]})
    r = client.get("/api/v0/models/catalog", headers=_mh(maintainer_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_active_workers"] >= 1
    assert any(
        m["model_id"] == "gemma-3-1b-it-q4" and m["worker_count"] >= 1 for m in body["models"]
    )


def test_catalog_requires_auth(client: TestClient) -> None:
    r = client.get("/api/v0/models/catalog")
    assert r.status_code in (401, 403), r.text
