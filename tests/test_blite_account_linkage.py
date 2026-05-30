"""b-lite account linkage — the tenant -> account join column and the
ACCOUNT_SCOPED exposure tag it brings to life.

Covers the whole vertical opened by migration 0013:
  - repository round-trip of tenants.account_id
  - the auth-layer TenantBinding carrying account_id
  - the researcher Credential carrying account_id (via the resolver)
  - is_visible() honouring ACCOUNT_SCOPED for same-account credentials
  - POST /api/v0/tenants accepting + validating an operator-set account_id

See researcher_dashboard_design.md §8.2/§11 and principles §6.9 / §9 #26.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.resolver import CredentialResolver
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import AccountRepository, TenantRepository
from auspexai_platform.exposure import ExposureTag, is_visible

# ---- helpers ---------------------------------------------------------------


def _make_account(account_repository: AccountRepository, account_id: str, sub: str) -> str:
    account_repository.create(
        account_id=account_id,
        idp=IdentityProvider.GITHUB,
        idp_sub=sub,
    )
    return account_id


# ---- repository round-trip -------------------------------------------------


def test_register_persists_account_id(
    tenant_repository: TenantRepository,
    account_repository: AccountRepository,
) -> None:
    acct = _make_account(account_repository, "acct-link01", "gh-1")
    tenant_repository.register(
        tenant_id="t-linked",
        maintainer_pubkey="a" * 64,
        account_id=acct,
    )
    got = tenant_repository.get_by_id("t-linked")
    assert got is not None
    assert got.account_id == acct


def test_register_without_account_id_leaves_it_none(
    tenant_repository: TenantRepository,
) -> None:
    tenant_repository.register(tenant_id="t-unlinked", maintainer_pubkey="b" * 64)
    got = tenant_repository.get_by_id("t-unlinked")
    assert got is not None
    assert got.account_id is None


# ---- auth-layer flow: binding -> credential --------------------------------


def test_tenant_binding_carries_account_id(
    tenant_repository: TenantRepository,
    account_repository: AccountRepository,
    tenant_registry,
) -> None:
    acct = _make_account(account_repository, "acct-link02", "gh-2")
    tenant_repository.register(tenant_id="t-bind", maintainer_pubkey="c" * 64, account_id=acct)
    binding = tenant_registry.get_tenant_for_pubkey("c" * 64)
    assert binding is not None
    assert binding.account_id == acct


def test_resolver_gives_researcher_credential_account_id(
    tenant_repository: TenantRepository,
    account_repository: AccountRepository,
    credential_resolver: CredentialResolver,
) -> None:
    acct = _make_account(account_repository, "acct-link03", "gh-3")
    tenant_repository.register(tenant_id="t-res", maintainer_pubkey="d" * 64, account_id=acct)
    cred = credential_resolver.resolve("d" * 64)
    assert cred is not None
    assert cred.is_researcher()
    assert cred.account_id == acct


def test_resolver_unlinked_tenant_has_no_account_id(
    tenant_repository: TenantRepository,
    credential_resolver: CredentialResolver,
) -> None:
    tenant_repository.register(tenant_id="t-res-none", maintainer_pubkey="e" * 64)
    cred = credential_resolver.resolve("e" * 64)
    assert cred is not None
    assert cred.is_researcher()
    assert cred.account_id is None


# ---- exposure: ACCOUNT_SCOPED is now live ----------------------------------


def test_account_scoped_visible_to_same_account_researcher() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64, account_id="acct-x")
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred, resource_account_id="acct-x") is True


def test_account_scoped_hidden_from_other_account_researcher() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64, account_id="acct-x")
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred, resource_account_id="acct-y") is False


def test_account_scoped_hidden_when_resource_unbound() -> None:
    """resource_account_id is None — the resource isn't account-bound, so even a
    credential with an account sees nothing (mirrors the tenant-scoped rule)."""
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64, account_id="acct-x")
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred, resource_account_id=None) is False


def test_account_scoped_hidden_from_unlinked_researcher() -> None:
    """A researcher whose tenant isn't account-linked (account_id None) still
    cannot see account-scoped fields — the b-lite change is additive."""
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred, resource_account_id="acct-x") is False


def test_account_scoped_visible_to_same_account_worker() -> None:
    """A worker bound to the account sees the account's account-scoped fields —
    the own-worker-visibility case b-lite unblocks."""
    cred = Credential.worker(
        worker_id="wkr-1", pubkey_hex="f" * 64, account_id="acct-x", trust_tier=1
    )
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred, resource_account_id="acct-x") is True


# ---- route: operator-set account_id ----------------------------------------


def _create_tenant(client: TestClient, token: str, body: dict):
    return client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )


def test_create_tenant_with_valid_account_id_links_it(
    client: TestClient,
    maintainer_token: str,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
) -> None:
    acct = _make_account(account_repository, "acct-route01", "gh-route-1")
    resp = _create_tenant(
        client,
        maintainer_token,
        {"tenant_id": "t-route-ok", "maintainer_pubkey": "1" * 64, "account_id": acct},
    )
    assert resp.status_code == 201, resp.text
    # account_id is not on the wire shape (operator/account-scoped, not public
    # tenant metadata) — verify the link landed in storage instead.
    stored = tenant_repository.get_by_id("t-route-ok")
    assert stored is not None
    assert stored.account_id == acct


def test_create_tenant_with_unknown_account_id_returns_400(
    client: TestClient,
    maintainer_token: str,
) -> None:
    resp = _create_tenant(
        client,
        maintainer_token,
        {
            "tenant_id": "t-route-bad",
            "maintainer_pubkey": "2" * 64,
            "account_id": "acct-does-not-exist",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["error"]["code"] == "unknown_account"


def test_create_tenant_without_account_id_still_works(
    client: TestClient,
    maintainer_token: str,
    tenant_repository: TenantRepository,
) -> None:
    resp = _create_tenant(
        client,
        maintainer_token,
        {"tenant_id": "t-route-none", "maintainer_pubkey": "3" * 64},
    )
    assert resp.status_code == 201, resp.text
    stored = tenant_repository.get_by_id("t-route-none")
    assert stored is not None
    assert stored.account_id is None
