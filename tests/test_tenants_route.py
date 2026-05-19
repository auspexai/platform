"""End-to-end tests for /api/v0/tenants."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request


# ---- POST /tenants — operator only -----------------------------------------


def test_create_tenant_requires_maintainer(client: TestClient) -> None:
    response = client.post(
        "/api/v0/tenants",
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "a" * 64,
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "maintainer_required"


def test_create_tenant_succeeds_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    response = client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "a" * 64,
            "display_name": "Synthetic doubler",
            "contact_email": "contact@example.org",
            "contact_public": "https://example.org",
            "description": "Integer doubler test tenant.",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["tenant_id"] == "synth-doubler"
    assert body["display_name"] == "Synthetic doubler"
    # Maintainer sees all fields.
    assert body["maintainer_pubkey"] == "a" * 64
    assert body["contact_email"] == "contact@example.org"


def test_create_tenant_duplicate_id_returns_409(client: TestClient, maintainer_token: str) -> None:
    headers = {"Authorization": f"Bearer {maintainer_token}"}
    body = {"tenant_id": "synth-doubler", "maintainer_pubkey": "a" * 64}
    first = client.post("/api/v0/tenants", headers=headers, json=body)
    assert first.status_code == 201
    second = client.post(
        "/api/v0/tenants",
        headers=headers,
        json={"tenant_id": "synth-doubler", "maintainer_pubkey": "b" * 64},
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "duplicate_tenant"


def test_create_tenant_rejects_bad_pubkey_format(client: TestClient, maintainer_token: str) -> None:
    response = client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "not-hex",
        },
    )
    assert response.status_code == 422  # Pydantic validation


def test_create_tenant_rejects_bad_tenant_id_format(
    client: TestClient, maintainer_token: str
) -> None:
    response = client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={
            "tenant_id": "Synth Doubler",  # spaces + uppercase not allowed
            "maintainer_pubkey": "a" * 64,
        },
    )
    assert response.status_code == 422


def test_create_tenant_writes_audit_log(client: TestClient, maintainer_token: str) -> None:
    client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={"tenant_id": "synth-doubler", "maintainer_pubkey": "a" * 64},
    )
    audit_repo = client.app.state.audit_repository
    rows = audit_repo.latest(limit=1)
    assert rows[0].action == "tenant.register"
    assert rows[0].resource_id == "synth-doubler"


# ---- GET /tenants — list ---------------------------------------------------


def test_list_tenants_anonymous_sees_only_public_fields(
    client: TestClient, maintainer_token: str
) -> None:
    client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "a" * 64,
            "display_name": "Synthetic doubler",
            "contact_email": "contact@example.org",
        },
    )
    # Anonymous fetch.
    response = client.get("/api/v0/tenants")
    assert response.status_code == 200
    body = response.json()
    assert len(body["tenants"]) == 1
    t = body["tenants"][0]
    assert t["tenant_id"] == "synth-doubler"
    assert t["display_name"] == "Synthetic doubler"
    # Tenant-scoped fields filtered out for anonymous.
    assert "contact_email" not in t
    assert "maintainer_pubkey" not in t


def test_list_tenants_maintainer_sees_full_fields(
    client: TestClient, maintainer_token: str
) -> None:
    headers = {"Authorization": f"Bearer {maintainer_token}"}
    client.post(
        "/api/v0/tenants",
        headers=headers,
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "a" * 64,
            "contact_email": "contact@example.org",
        },
    )
    response = client.get("/api/v0/tenants", headers=headers)
    assert response.status_code == 200
    t = response.json()["tenants"][0]
    assert t["maintainer_pubkey"] == "a" * 64
    assert t["contact_email"] == "contact@example.org"


def test_list_tenants_researcher_sees_own_tenant_full_others_public_only(
    client: TestClient,
    maintainer_token: str,
    registered_tenant: tuple[Ed25519PrivateKey, object],
) -> None:
    """`registered_tenant` already inserted synth-doubler with pubkey 'a'*64.
    We add a second tenant; the researcher signing as synth-doubler should
    see their own fully + the second only at public fields."""
    op_headers = {"Authorization": f"Bearer {maintainer_token}"}
    privkey, own_binding = registered_tenant
    # Add a second tenant so we can verify the filter.
    second_pub = "b" * 64
    client.post(
        "/api/v0/tenants",
        headers=op_headers,
        json={
            "tenant_id": "other-tenant",
            "maintainer_pubkey": second_pub,
            "contact_email": "other@example.org",
        },
    )

    # Now list as researcher.
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=own_binding.pubkey_hex,
        method="GET",
        path="/api/v0/tenants",
        authority="testserver",
        body=b"",
    )
    response = client.get("/api/v0/tenants", headers=sig_headers)
    assert response.status_code == 200, response.text
    tenants = {t["tenant_id"]: t for t in response.json()["tenants"]}

    own = tenants[own_binding.tenant_id]
    assert own["maintainer_pubkey"] == own_binding.pubkey_hex  # tenant-scoped: visible
    other = tenants["other-tenant"]
    assert "maintainer_pubkey" not in other  # tenant-scoped: hidden
    assert "contact_email" not in other


# ---- GET /tenants/{id} — detail --------------------------------------------


def test_get_tenant_detail_404_when_absent(client: TestClient) -> None:
    response = client.get("/api/v0/tenants/missing")
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "tenant_not_found"


def test_get_tenant_detail_anonymous_filtered(client: TestClient, maintainer_token: str) -> None:
    client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": "a" * 64,
            "contact_email": "contact@example.org",
        },
    )
    response = client.get("/api/v0/tenants/synth-doubler")
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "synth-doubler"
    assert "maintainer_pubkey" not in body
    assert "contact_email" not in body


def test_get_tenant_detail_researcher_sees_own(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
) -> None:
    privkey, binding = registered_tenant
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path=f"/api/v0/tenants/{binding.tenant_id}",
        authority="testserver",
        body=b"",
    )
    response = client.get(f"/api/v0/tenants/{binding.tenant_id}", headers=sig_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["maintainer_pubkey"] == binding.pubkey_hex
