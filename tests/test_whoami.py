"""End-to-end tests for /api/v0/auth/whoami across all three credential classes.

M3 added field-exposure filtering. The behavioral consequence:

  - Anonymous sees only `credential_class` (public). `tenant_id` and `pubkey_hex`
    drop from the response (response_model_exclude_none=True).
  - Maintainer sees everything (operator union view).
  - Researcher sees `credential_class` + their own `tenant_id` + their own
    `pubkey_hex` (tenant-scoped against `resource_tenant_id = credential.tenant_id`).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request


def test_whoami_anonymous_returns_only_credential_class(client: TestClient) -> None:
    response = client.get("/api/v0/auth/whoami")
    assert response.status_code == 200
    body = response.json()
    assert body["credential_class"] == "anonymous"
    # tenant_id + pubkey_hex are tenant-scoped → filtered out for anonymous.
    assert "tenant_id" not in body
    assert "pubkey_hex" not in body


def test_whoami_maintainer_sees_only_class_when_token_unbound(
    client: TestClient, maintainer_token: str
) -> None:
    """Maintainer credential has no tenant_id of its own — the response model
    has nothing to populate those fields with, so they're naturally absent."""
    response = client.get(
        "/api/v0/auth/whoami",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["credential_class"] == "maintainer"
    # Maintainer COULD see tenant_id / pubkey_hex if they had values; in this
    # case the credential itself has None for those fields, so they drop via
    # exclude_none.
    assert "tenant_id" not in body
    assert "pubkey_hex" not in body


def test_whoami_researcher_sees_own_binding(
    client: TestClient,
    registered_tenant: tuple[Ed25519PrivateKey, object],
) -> None:
    privkey, binding = registered_tenant
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path="/api/v0/auth/whoami",
        authority="testserver",
        body=b"",
    )
    response = client.get("/api/v0/auth/whoami", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credential_class"] == "researcher"
    assert body["tenant_id"] == binding.tenant_id
    assert body["pubkey_hex"] == binding.pubkey_hex


def test_invalid_bearer_token_returns_401(client: TestClient) -> None:
    response = client.get(
        "/api/v0/auth/whoami",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["error"]["code"] == "invalid_maintainer_token"


def test_malformed_authorization_returns_401(client: TestClient) -> None:
    response = client.get(
        "/api/v0/auth/whoami",
        headers={"Authorization": "Basic not-bearer"},
    )
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["error"]["code"] == "malformed_authorization_header"


def test_unknown_researcher_pubkey_returns_401(client: TestClient) -> None:
    unregistered_priv = Ed25519PrivateKey.generate()
    unregistered_hex = unregistered_priv.public_key().public_bytes_raw().hex()
    headers = sign_request(
        privkey=unregistered_priv,
        pubkey_hex=unregistered_hex,
        method="GET",
        path="/api/v0/auth/whoami",
        authority="testserver",
        body=b"",
    )
    response = client.get("/api/v0/auth/whoami", headers=headers)
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["error"]["code"] == "invalid_signature"


def test_signature_without_signature_input_falls_through_to_anonymous(client: TestClient) -> None:
    response = client.get(
        "/api/v0/auth/whoami",
        headers={"Signature": "sig1=:abc:"},
    )
    assert response.status_code == 200
    assert response.json()["credential_class"] == "anonymous"


def test_signature_input_without_signature_returns_401(client: TestClient) -> None:
    response = client.get(
        "/api/v0/auth/whoami",
        headers={
            "Signature-Input": 'sig1=("@method");created=1;alg="ed25519";keyid="abc"',
        },
    )
    assert response.status_code == 401


def test_bearer_takes_precedence_over_signature(
    client: TestClient,
    maintainer_token: str,
    registered_tenant: tuple[Ed25519PrivateKey, object],
) -> None:
    privkey, binding = registered_tenant
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path="/api/v0/auth/whoami",
        authority="testserver",
        body=b"",
    )
    response = client.get(
        "/api/v0/auth/whoami",
        headers={
            "Authorization": f"Bearer {maintainer_token}",
            **sig_headers,
        },
    )
    assert response.status_code == 200
    assert response.json()["credential_class"] == "maintainer"
