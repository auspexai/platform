"""End-to-end tests for /api/v0/accounts/oauth/exchange."""

from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
)
from auspexai_platform.oauth.identity import IdentityClaim

from .conftest import FakeIdentityVerifier

# ---- happy path -----------------------------------------------------------


def test_exchange_creates_new_account_on_first_call(
    client: TestClient,
    identity_verifier: FakeIdentityVerifier,
    account_repository: AccountRepository,
) -> None:
    identity_verifier.register(
        "gho_new_user_token",
        IdentityClaim(
            idp=IdentityProvider.GITHUB,
            idp_sub="246774008",
            display_name="jasongagne-git",
            email="jason@example.org",
        ),
    )

    response = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_new_user_token"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["is_new_account"] is True
    assert body["account_id"].startswith("acct-")
    assert body["binding_token"]
    assert body["expires_at"]
    # expires_at is in the future
    assert datetime.fromisoformat(body["expires_at"]) > datetime.now().astimezone()

    # Account is persisted with the IdP fields.
    stored = account_repository.get_by_idp_subject(IdentityProvider.GITHUB, "246774008")
    assert stored is not None
    assert stored.display_name == "jasongagne-git"
    assert stored.email == "jason@example.org"


def test_exchange_returns_existing_account_on_repeat_call(
    client: TestClient,
    identity_verifier: FakeIdentityVerifier,
) -> None:
    identity_verifier.register(
        "gho_repeat",
        IdentityClaim(
            idp=IdentityProvider.GITHUB,
            idp_sub="42",
            display_name="repeat-user",
        ),
    )

    first = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_repeat"},
    ).json()
    second = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_repeat"},
    ).json()

    assert first["account_id"] == second["account_id"]
    assert first["is_new_account"] is True
    assert second["is_new_account"] is False
    # New binding token on each call — single-use semantics.
    assert first["binding_token"] != second["binding_token"]


def test_exchange_writes_audit_entry(
    client: TestClient,
    identity_verifier: FakeIdentityVerifier,
    audit_repository: AuditRepository,
) -> None:
    identity_verifier.register(
        "gho_audit",
        IdentityClaim(idp=IdentityProvider.GITHUB, idp_sub="7"),
    )
    response = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_audit"},
    )
    assert response.status_code == 200

    entries = audit_repository.latest(limit=10)
    matching = [e for e in entries if e.action == "account.oauth_exchange"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry.actor_class.value == "anonymous"
    assert entry.resource_type == "account"
    assert entry.resource_id == response.json()["account_id"]
    assert entry.payload is not None
    assert entry.payload["idp"] == "github"
    assert entry.payload["is_new_account"] is True


# ---- error paths ----------------------------------------------------------


def test_exchange_returns_401_for_invalid_token(
    client: TestClient,
) -> None:
    # No token registered → verifier raises InvalidAccessTokenError.
    response = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_bogus"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["error"]["code"] == "invalid_access_token"


def test_exchange_returns_422_on_missing_token(client: TestClient) -> None:
    response = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": ""},
    )
    assert response.status_code == 422  # Pydantic min_length validation


def test_exchange_returns_422_on_unknown_idp(client: TestClient) -> None:
    # 'foobar' is not in IdentityProvider; Pydantic rejects the request body.
    response = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "foobar", "access_token": "tok"},
    )
    assert response.status_code == 422
