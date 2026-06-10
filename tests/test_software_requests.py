"""§9 #46 — software-requirements pipeline (code-plane demand board).

Researcher submission is RFC-9421 signed; assessment + approve/decline use the
maintainer bearer. Covers the assessment draft/ratify lifecycle, the
warn-but-allow approval gates, tenant-private scoping (incl. the negative
cross-tenant tests), and the firehose events.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.events import GLOBAL


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


_CREATE_BODY = {
    "title": "Ollama inference serving",
    "description": "Experiments need local LLM inference served by the worker.",
    "reason": "drift-probe tenant requires deterministic local inference",
}

_ASSESSMENT = {
    "dependencies": "Ollama binary (third-party installer), huggingface_hub extra.",
    "security": "Local HTTP service on 127.0.0.1; network-cut sandbox reaches it via broker socket only.",
    "alternatives": "llama.cpp server; vLLM (heavier); per-experiment vendored runtime.",
    "summary": "Low marginal surface; broker already mediates access.",
}


def _create(client: TestClient, registered_tenant) -> dict:
    privkey, binding = registered_tenant
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/software-requests",
        body=_CREATE_BODY,
    )
    assert r.status_code == 201, r.text
    return r.json()


# ---- POST /software-requests -------------------------------------------------


def test_create_enters_pending_queue_and_audits(
    client: TestClient, registered_tenant, audit_repository
) -> None:
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        created = _create(client, registered_tenant)
        ev = q.get_nowait()
    assert created["request_id"].startswith("swr-")
    assert created["status"] == "pending"
    assert created["tenant_id"] == "synth-doubler"
    assert created["assessment"] is None
    assert ev.type == "requirement.submitted"
    assert ev.data["request_id"] == created["request_id"]
    assert ev.data["kind"] == "software"
    entries = [e for e in audit_repository.latest() if e.action == "software_request.create"]
    assert entries and entries[0].resource_id == created["request_id"]


def test_create_rejected_for_maintainer_bearer(client: TestClient, maintainer_token) -> None:
    r = client.post("/api/v0/software-requests", json=_CREATE_BODY, headers=_mtnr(maintainer_token))
    assert r.status_code == 403


def test_create_rejected_for_anonymous(client: TestClient) -> None:
    r = client.post("/api/v0/software-requests", json=_CREATE_BODY)
    assert r.status_code in (401, 403)


# ---- GET /software-requests (queue + my-requests) -----------------------------


def test_maintainer_lists_all_with_status_filter(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    r = client.get("/api/v0/software-requests", headers=_mtnr(maintainer_token))
    assert r.status_code == 200
    assert [x["request_id"] for x in r.json()["requests"]] == [created["request_id"]]
    r = client.get("/api/v0/software-requests?status=approved", headers=_mtnr(maintainer_token))
    assert r.json()["requests"] == []


def test_researcher_list_is_tenant_scoped(
    client: TestClient, registered_tenant, tenant_registry
) -> None:
    created = _create(client, registered_tenant)
    privkey, binding = registered_tenant

    # Own list shows the request.
    r = _signed_get(
        client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path="/api/v0/software-requests"
    )
    assert r.status_code == 200
    assert [x["request_id"] for x in r.json()["requests"]] == [created["request_id"]]

    # NEGATIVE: a second tenant must see an empty list and 404 on get-by-id.
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
    r = _signed_get(
        client, privkey=other_priv, pubkey_hex=other_pub, path="/api/v0/software-requests"
    )
    assert r.status_code == 200
    assert r.json()["requests"] == []
    r = _signed_get(
        client,
        privkey=other_priv,
        pubkey_hex=other_pub,
        path=f"/api/v0/software-requests/{created['request_id']}",
    )
    assert r.status_code == 404


def test_model_requests_researcher_list_is_tenant_scoped(
    client: TestClient, registered_tenant, tenant_registry
) -> None:
    """The model-requests queue gained the same researcher branch — verify the
    cross-tenant negative there too."""
    privkey, binding = registered_tenant
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path="/api/v0/model-requests",
        body={"model_id": "gemma-3-1b-it-q4", "reason": "drift probes"},
    )
    assert r.status_code == 201, r.text

    r = _signed_get(
        client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path="/api/v0/model-requests"
    )
    assert r.status_code == 200
    assert len(r.json()["requests"]) == 1

    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
    r = _signed_get(client, privkey=other_priv, pubkey_hex=other_pub, path="/api/v0/model-requests")
    assert r.status_code == 200
    assert r.json()["requests"] == []


def test_get_by_id_visible_to_owner_and_maintainer(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    privkey, binding = registered_tenant
    path = f"/api/v0/software-requests/{created['request_id']}"
    r = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path)
    assert r.status_code == 200
    r = client.get(path, headers=_mtnr(maintainer_token))
    assert r.status_code == 200
    assert r.json()["title"] == _CREATE_BODY["title"]


# ---- assess -------------------------------------------------------------------


def test_assess_attaches_and_round_trips(
    client: TestClient, registered_tenant, maintainer_token, audit_repository
) -> None:
    created = _create(client, registered_tenant)
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"/api/v0/software-requests/{created['request_id']}/actions/assess",
            json={"assessment": _ASSESSMENT, "draft": True},
            headers=_mtnr(maintainer_token),
        )
        ev = q.get_nowait()
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "assessed"
    assert body["assessment_draft"] is True
    assert body["assessment"]["dependencies"] == _ASSESSMENT["dependencies"]
    assert body["assessed_by"]
    assert ev.type == "requirement.assessed"
    assert ev.data["draft"] is True
    entries = [e for e in audit_repository.latest() if e.action == "software_request.assess"]
    assert entries and entries[0].payload["draft"] is True


def test_ratify_reattaches_with_draft_false(
    client: TestClient, registered_tenant, maintainer_token, audit_repository
) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    for draft in (True, False):  # auto-draft, then human ratification
        r = client.post(
            f"/api/v0/software-requests/{rid}/actions/assess",
            json={"assessment": _ASSESSMENT, "draft": draft},
            headers=_mtnr(maintainer_token),
        )
        assert r.status_code == 200, r.text
    assert r.json()["assessment_draft"] is False
    entries = [e for e in audit_repository.latest() if e.action == "software_request.assess"]
    assert len(entries) == 2
    # latest() is newest-first: the ratification re-attach is flagged.
    assert entries[0].payload["re_assessment"] is True


def test_assess_requires_maintainer(client: TestClient, registered_tenant) -> None:
    created = _create(client, registered_tenant)
    privkey, binding = registered_tenant
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path=f"/api/v0/software-requests/{created['request_id']}/actions/assess",
        body={"assessment": _ASSESSMENT},
    )
    assert r.status_code == 403


def test_assess_after_resolution_conflicts(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/decline",
        json={"reason": "out of scope"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/assess",
        json={"assessment": _ASSESSMENT},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 409


# ---- approve / decline gates ----------------------------------------------------


def test_approve_without_assessment_is_gate_override(
    client: TestClient, registered_tenant, maintainer_token, audit_repository
) -> None:
    created = _create(client, registered_tenant)
    r = client.post(
        f"/api/v0/software-requests/{created['request_id']}/actions/approve",
        json={"reason": "needed for first inference tenant"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["gate_override"] is True
    assert any("no assessment" in w for w in body["gate_warnings"])
    entries = [e for e in audit_repository.latest() if e.action == "software_request.approve"]
    assert entries and entries[0].payload["gate_override"] is True


def test_approve_with_draft_assessment_warns_softer(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    client.post(
        f"/api/v0/software-requests/{rid}/actions/assess",
        json={"assessment": _ASSESSMENT, "draft": True},
        headers=_mtnr(maintainer_token),
    )
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/approve",
        json={"reason": "draft looks sound; proceeding"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["gate_override"] is True
    assert any("auto-draft" in w for w in body["gate_warnings"])


def test_approve_with_ratified_assessment_is_clean(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    client.post(
        f"/api/v0/software-requests/{rid}/actions/assess",
        json={"assessment": _ASSESSMENT, "draft": False},
        headers=_mtnr(maintainer_token),
    )
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"/api/v0/software-requests/{rid}/actions/approve",
            json={"reason": "assessment ratified; capability approved"},
            headers=_mtnr(maintainer_token),
        )
        ev = q.get_nowait()
    assert r.status_code == 200
    body = r.json()
    assert body["gate_override"] is False
    assert body["gate_warnings"] == []
    assert ev.type == "requirement.resolved"
    assert ev.data["gate_override"] is False


def test_decline_requires_reason(client: TestClient, registered_tenant, maintainer_token) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/decline",
        json={"reason": ""},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 422
    r = client.post(
        f"/api/v0/software-requests/{rid}/actions/decline",
        json={"reason": "duplicate of an existing capability"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "declined"


def test_resolve_twice_conflicts_and_unknown_id_404s(
    client: TestClient, registered_tenant, maintainer_token
) -> None:
    created = _create(client, registered_tenant)
    rid = created["request_id"]
    body = {"reason": "approved once"}
    assert (
        client.post(
            f"/api/v0/software-requests/{rid}/actions/approve",
            json=body,
            headers=_mtnr(maintainer_token),
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v0/software-requests/{rid}/actions/approve",
            json=body,
            headers=_mtnr(maintainer_token),
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/v0/software-requests/swr-missing0/actions/approve",
            json=body,
            headers=_mtnr(maintainer_token),
        ).status_code
        == 404
    )
