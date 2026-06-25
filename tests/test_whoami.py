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
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import AccountRepository, TenantRepository


def _linked_researcher_headers(
    *,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    tenant_keypair: tuple[Ed25519PrivateKey, str],
    account_id: str,
    tenant_id: str,
) -> dict[str, str]:
    """Create an account, link a tenant to it, and return signed whoami headers
    for the tenant's key. The caller suspends the account as needed."""
    priv, pubkey_hex = tenant_keypair
    account_repository.create(
        account_id=account_id, idp=IdentityProvider.GITHUB, idp_sub=account_id
    )
    tenant_repository.register(
        tenant_id=tenant_id, maintainer_pubkey=pubkey_hex, account_id=account_id
    )
    return sign_request(
        privkey=priv,
        pubkey_hex=pubkey_hex,
        method="GET",
        path="/api/v0/auth/whoami",
        authority="testserver",
        body=b"",
    )


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
    # An unsuspended account exposes no suspension fields (None → exclude_none).
    assert "suspended_at" not in body
    assert "suspension_reason" not in body


def test_whoami_researcher_sees_own_account_suspension(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    tenant_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A suspended account's researcher sees their own suspension + the
    maintainer's reason via whoami (account-scoped, ratified 2026-05-30)."""
    reason = "policy review: unverified bulk experiment submissions"
    headers = _linked_researcher_headers(
        account_repository=account_repository,
        tenant_repository=tenant_repository,
        tenant_keypair=tenant_keypair,
        account_id="acct-susp01",
        tenant_id="t-susp01",
    )
    account_repository.suspend("acct-susp01", reason=reason)

    response = client.get("/api/v0/auth/whoami", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credential_class"] == "researcher"
    assert body["suspension_reason"] == reason
    assert body["suspended_at"] is not None


def test_whoami_unsuspended_account_clears_suspension_fields(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    tenant_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """unsuspend clears both the timestamp and the reason — whoami drops them."""
    headers = _linked_researcher_headers(
        account_repository=account_repository,
        tenant_repository=tenant_repository,
        tenant_keypair=tenant_keypair,
        account_id="acct-susp02",
        tenant_id="t-susp02",
    )
    account_repository.suspend("acct-susp02", reason="temporary hold")
    account_repository.unsuspend("acct-susp02")

    response = client.get("/api/v0/auth/whoami", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "suspended_at" not in body
    assert "suspension_reason" not in body


def test_whoami_account_holder_sees_github_identity_root(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    tenant_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """The account holder sees their identity root on whoami: display_name (the
    OAuth-verified GitHub login) + idp ('github'), so the dashboard Identity card
    can render the GitHub identity beside ORCID. Account-scoped."""
    priv, pubkey_hex = tenant_keypair
    account_repository.create(
        account_id="acct-gh01",
        idp=IdentityProvider.GITHUB,
        idp_sub="gh-12345",
        display_name="jasongagne-git",
    )
    tenant_repository.register(
        tenant_id="t-gh01", maintainer_pubkey=pubkey_hex, account_id="acct-gh01"
    )
    headers = sign_request(
        privkey=priv,
        pubkey_hex=pubkey_hex,
        method="GET",
        path="/api/v0/auth/whoami",
        authority="testserver",
        body=b"",
    )
    body = client.get("/api/v0/auth/whoami", headers=headers).json()
    assert body["display_name"] == "jasongagne-git"
    assert body["idp"] == "github"


def test_whoami_anonymous_does_not_see_account_identity(client: TestClient) -> None:
    """display_name + idp are ACCOUNT_SCOPED — they never leak to a third party."""
    body = client.get("/api/v0/auth/whoami").json()
    assert "display_name" not in body
    assert "idp" not in body


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
