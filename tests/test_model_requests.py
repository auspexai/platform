"""M2 — demand-board + 'new requirement' review queue (catalog, request, queue,
fulfil/decline). Researcher requests are RFC-9421 signed; the maintainer review
+ resolve actions use the maintainer bearer."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request


def _signed_post(client: TestClient, *, privkey, pubkey_hex: str, path: str, body: dict):
    raw = json.dumps(body).encode("utf-8")
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=raw)


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


def _mtnr(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


def _active_worker_with_models(
    worker_repository, *, worker_id: str, pubkey: str, models: list[str]
):
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=pubkey)
    worker_repository.record_heartbeat(worker_id, capabilities={"os": "linux", "models": models})


# ---- POST /model-requests --------------------------------------------------


def test_request_is_pending_when_no_worker_holds_it(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/model-requests",
        body={"model_id": "qwen3-q4", "hf_repo": "Qwen/Qwen3-GGUF", "reason": "need it for D6"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"  # no active worker holds it → review queue
    assert body["model_id"] == "qwen3-q4"
    assert body["tenant_id"] == binding.tenant_id
    assert body["request_id"].startswith("mrq-")


def test_request_is_available_when_a_worker_holds_it(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    worker_repository,
) -> None:
    _active_worker_with_models(
        worker_repository, worker_id="w-has", pubkey="1" * 64, models=["qwen3-q4"]
    )
    privkey, binding = registered_tenant
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/model-requests",
        body={"model_id": "qwen3-q4", "reason": "already on the network?"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "available"  # an active worker already holds it


def test_request_requires_researcher(client: TestClient, maintainer_token: str) -> None:
    # A maintainer bearer is not a researcher → cannot signal demand.
    r = client.post(
        "/api/v0/model-requests",
        json={"model_id": "m-x", "reason": "x"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 403


# ---- GET /model-requests (maintainer queue) --------------------------------


def test_queue_is_maintainer_only_and_filters_by_status(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    maintainer_token: str,
) -> None:
    privkey, binding = registered_tenant
    _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/model-requests",
        body={"model_id": "m-pending", "reason": "queue me"},
    )
    # anonymous → not maintainer
    assert client.get("/api/v0/model-requests").status_code in (401, 403)
    # maintainer sees the queue
    r = client.get("/api/v0/model-requests?status=pending", headers=_mtnr(maintainer_token))
    assert r.status_code == 200, r.text
    ids = [req["model_id"] for req in r.json()["requests"]]
    assert "m-pending" in ids


# ---- fulfil / decline (maintainer, mandatory reason, audited) ---------------


def _create_pending(client, privkey, binding, model_id="m-res") -> str:
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/model-requests",
        body={"model_id": model_id, "reason": "to resolve"},
    )
    assert r.status_code == 201, r.text
    return r.json()["request_id"]


def test_fulfil_sets_status_and_records_reason(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    maintainer_token: str,
) -> None:
    privkey, binding = registered_tenant
    rid = _create_pending(client, privkey, binding)
    r = client.post(
        f"/api/v0/model-requests/{rid}/actions/fulfil",
        json={"reason": "recruited a capable volunteer"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "fulfilled"
    assert body["resolution_reason"] == "recruited a capable volunteer"
    assert body["resolved_at"] is not None


def test_decline_sets_status(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    maintainer_token: str,
) -> None:
    privkey, binding = registered_tenant
    rid = _create_pending(client, privkey, binding, model_id="m-decline")
    r = client.post(
        f"/api/v0/model-requests/{rid}/actions/decline",
        json={"reason": "out of scope"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "declined"


def test_resolve_requires_reason(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    maintainer_token: str,
) -> None:
    privkey, binding = registered_tenant
    rid = _create_pending(client, privkey, binding, model_id="m-noreason")
    r = client.post(
        f"/api/v0/model-requests/{rid}/actions/fulfil",
        json={},  # missing reason → 422
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 422


def test_resolve_unknown_request_404(client: TestClient, maintainer_token: str) -> None:
    r = client.post(
        "/api/v0/model-requests/mrq-nope/actions/fulfil",
        json={"reason": "x"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 404


# ---- GET /models/catalog (bottom-up aggregate) -----------------------------


def test_catalog_aggregates_active_worker_inventory(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
    worker_repository,
) -> None:
    _active_worker_with_models(
        worker_repository, worker_id="w1", pubkey="a" * 64, models=["m-x", "m-y"]
    )
    _active_worker_with_models(worker_repository, worker_id="w2", pubkey="b" * 64, models=["m-x"])
    privkey, binding = registered_tenant
    r = _signed_get(
        client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path="/api/v0/models/catalog"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    counts = {e["model_id"]: e["worker_count"] for e in body["models"]}
    assert counts["m-x"] == 2
    assert counts["m-y"] == 1
    assert body["total_active_workers"] == 2
    # most-held first
    assert body["models"][0]["model_id"] == "m-x"
