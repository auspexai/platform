"""§9 #46 — release registry + fleet announcement.

Recording a release is a maintainer action that (a) flips the approved
software requests it fulfils to `released` (validate-first), (b) audits +
emits `release.published`, and (c) starts being relayed to workers in the
heartbeat response (`latest_release`, PUBLIC).
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.events import GLOBAL


def _mtnr(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


def _signed(
    client: TestClient,
    *,
    privkey,
    pubkey_hex: str,
    method: str,
    path: str,
    body: dict | None = None,
):
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method=method,
        path=path,
        authority="testserver",
        body=raw,
    )
    if raw:
        headers["Content-Type"] = "application/json"
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, headers=headers, content=raw)


_RELEASE = {
    "version": "0.2.0",
    "headline": "Worker flavors + official Ollama inference install",
    "notes": "Adds --flavor to the onramp; inference flavor installs Ollama.",
    "release_url": "https://github.com/auspexai/worker/releases/tag/v0.2.0",
}


def _approved_request(client: TestClient, registered_tenant, maintainer_token) -> str:
    privkey, binding = registered_tenant
    raw = json.dumps(
        {
            "title": "Ollama inference serving",
            "description": "Local LLM inference served by the worker.",
            "reason": "drift-probe tenant",
        }
    ).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="POST",
        path="/api/v0/software-requests",
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    r = client.post("/api/v0/software-requests", headers=headers, content=raw)
    assert r.status_code == 201, r.text
    rid = r.json()["request_id"]
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/approve",
        json={"reason": "first inference tenant needs it"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    return rid


# ---- POST /releases ----------------------------------------------------------


def test_record_release_announces_and_fulfils(
    client: TestClient, registered_tenant, maintainer_token, audit_repository
) -> None:
    rid = _approved_request(client, registered_tenant, maintainer_token)
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            "/api/v0/releases",
            json={**_RELEASE, "fulfils_request_ids": [rid]},
            headers=_mtnr(maintainer_token),
        )
        ev = q.get_nowait()
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == "0.2.0"
    assert body["channel"] == "worker"
    assert body["fulfilled_request_ids"] == [rid]
    assert ev.type == "release.published"
    assert ev.data["fulfils_request_ids"] == [rid]

    # The fulfilled request flipped to released with the version stamped.
    sr = client.get(f"/api/v0/software-requests/{rid}", headers=_mtnr(maintainer_token)).json()
    assert sr["status"] == "released"
    assert sr["release_version"] == "0.2.0"

    entries = [e for e in audit_repository.latest() if e.action == "release.publish"]
    assert entries and entries[0].payload["fulfils_request_ids"] == [rid]


def test_record_release_rejects_unapproved_request_with_no_writes(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    # A pending (not approved) request cannot be fulfilled — and the failed
    # call must not record the release row either.
    privkey, binding = registered_tenant
    raw = json.dumps({"title": "x", "description": "y", "reason": "z"}).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="POST",
        path="/api/v0/software-requests",
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    rid = client.post("/api/v0/software-requests", headers=headers, content=raw).json()[
        "request_id"
    ]

    r = client.post(
        "/api/v0/releases",
        json={**_RELEASE, "fulfils_request_ids": [rid]},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"]["code"] == "request_not_approved"
    listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
    assert listing["releases"] == []


def test_duplicate_release_version_conflicts(client: TestClient, maintainer_token) -> None:
    assert (
        client.post("/api/v0/releases", json=_RELEASE, headers=_mtnr(maintainer_token)).status_code
        == 201
    )
    r = client.post("/api/v0/releases", json=_RELEASE, headers=_mtnr(maintainer_token))
    assert r.status_code == 409
    assert r.json()["detail"]["error"]["code"] == "release_exists"


def test_record_release_requires_maintainer(client: TestClient, registered_tenant) -> None:
    privkey, binding = registered_tenant
    r = _signed(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="POST",
        path="/api/v0/releases",
        body=_RELEASE,
    )
    assert r.status_code == 403


# ---- GET /releases -----------------------------------------------------------


def test_researcher_can_list_releases(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    client.post("/api/v0/releases", json=_RELEASE, headers=_mtnr(maintainer_token))
    privkey, binding = registered_tenant
    r = _signed(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path="/api/v0/releases",
    )
    assert r.status_code == 200
    assert r.json()["releases"][0]["version"] == "0.2.0"


# ---- heartbeat relay ----------------------------------------------------------


def _heartbeat(client: TestClient, enrolled_worker):
    privkey, worker = enrolled_worker
    path = f"/api/v0/workers/{worker.worker_id}/heartbeat"
    payload = b"{}"
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=payload,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=payload)


def test_heartbeat_has_no_latest_release_before_announce(
    client: TestClient, enrolled_worker
) -> None:
    r = _heartbeat(client, enrolled_worker)
    assert r.status_code == 200, r.text
    assert "latest_release" not in r.json()


def test_heartbeat_relays_latest_release_to_worker(
    client: TestClient, enrolled_worker, maintainer_token
) -> None:
    client.post("/api/v0/releases", json=_RELEASE, headers=_mtnr(maintainer_token))
    # Announce a second, newer release: latest() must win.
    client.post(
        "/api/v0/releases",
        json={**_RELEASE, "version": "0.2.1", "headline": "Banner demo follow-up"},
        headers=_mtnr(maintainer_token),
    )
    r = _heartbeat(client, enrolled_worker)
    assert r.status_code == 200, r.text
    latest = r.json()["latest_release"]
    assert latest["version"] == "0.2.1"
    assert latest["headline"] == "Banner demo follow-up"
    assert latest["release_url"] == _RELEASE["release_url"]
