"""D3 accountability cascade — a SUSPENDED account's linked tenants stop working.

The account is the accountability root: when a maintainer suspends an account,
signed researcher requests from any tenant linked to it (tenants.account_id)
are refused with 403 `account_suspended` carrying the maintainer's
suspension_reason — the same surfacing rule as the worker-side 423
`worker_quarantined` (worker-side precedent: suspend quarantines the account's
workers; quarantined workers still heartbeat/whoami but get no work).

Covered:
  - suspended account → linked tenant's signed request 403 w/ reason
  - unsuspend → the same request works again
  - tenant WITHOUT account_id (legacy) is unaffected
  - whoami stays read-only-working for the suspended account holder (the
    status surface that carries the suspension banner), matching the
    existing suspension philosophy
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import AccountRepository, TenantRepository

# A representative signed-researcher surface (researcher or maintainer only).
RESEARCHER_PATH = "/api/v0/model-requests"
WHOAMI_PATH = "/api/v0/auth/whoami"


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


def _linked_tenant(
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    *,
    account_id: str,
    tenant_id: str,
) -> tuple[Ed25519PrivateKey, str]:
    """Create an account + a tenant linked to it; return the tenant keypair."""
    priv = Ed25519PrivateKey.generate()
    pubkey_hex = priv.public_key().public_bytes_raw().hex()
    account_repository.create(
        account_id=account_id, idp=IdentityProvider.GITHUB, idp_sub=account_id
    )
    tenant_repository.register(
        tenant_id=tenant_id, maintainer_pubkey=pubkey_hex, account_id=account_id
    )
    return priv, pubkey_hex


def test_suspended_account_blocks_linked_tenant_with_reason(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
) -> None:
    priv, pub = _linked_tenant(
        account_repository,
        tenant_repository,
        account_id="acct-casc01",
        tenant_id="t-casc01",
    )
    # Pre-suspension: the signed researcher request works.
    r = _signed_get(client, privkey=priv, pubkey_hex=pub, path=RESEARCHER_PATH)
    assert r.status_code == 200, r.text

    reason = "ToS violation under review"
    account_repository.suspend("acct-casc01", reason=reason)

    r = _signed_get(client, privkey=priv, pubkey_hex=pub, path=RESEARCHER_PATH)
    assert r.status_code == 403, r.text
    err = r.json()["detail"]["error"]
    assert err["code"] == "account_suspended"
    assert err["details"]["suspension_reason"] == reason
    assert err["details"]["suspended_at"] is not None


def test_unsuspend_restores_linked_tenant(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
) -> None:
    priv, pub = _linked_tenant(
        account_repository,
        tenant_repository,
        account_id="acct-casc02",
        tenant_id="t-casc02",
    )
    account_repository.suspend("acct-casc02", reason="temporary hold")
    assert (
        _signed_get(client, privkey=priv, pubkey_hex=pub, path=RESEARCHER_PATH).status_code == 403
    )

    account_repository.unsuspend("acct-casc02")
    r = _signed_get(client, privkey=priv, pubkey_hex=pub, path=RESEARCHER_PATH)
    assert r.status_code == 200, r.text


def test_legacy_tenant_without_account_id_is_unaffected(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
) -> None:
    """A tenant predating tenants.account_id has no accountability root to
    cascade from — its signed requests keep working even while some other
    account is suspended."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    tenant_repository.register(tenant_id="t-legacy", maintainer_pubkey=pub)

    # An unrelated suspended account must not bleed over.
    account_repository.create(
        account_id="acct-other", idp=IdentityProvider.GITHUB, idp_sub="acct-other"
    )
    account_repository.suspend("acct-other", reason="unrelated")

    r = _signed_get(client, privkey=priv, pubkey_hex=pub, path=RESEARCHER_PATH)
    assert r.status_code == 200, r.text


def test_whoami_stays_readable_while_suspended(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
) -> None:
    """whoami is the status surface that tells the account holder they are
    suspended — and why. It must keep answering (read-only) under suspension,
    mirroring the worker-side philosophy (quarantined workers still see their
    quarantine reason; they just get no work)."""
    priv, pub = _linked_tenant(
        account_repository,
        tenant_repository,
        account_id="acct-casc03",
        tenant_id="t-casc03",
    )
    account_repository.suspend("acct-casc03", reason="pending appeal")

    r = _signed_get(client, privkey=priv, pubkey_hex=pub, path=WHOAMI_PATH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["credential_class"] == "researcher"
    assert body["suspension_reason"] == "pending appeal"
    assert body["suspended_at"] is not None
