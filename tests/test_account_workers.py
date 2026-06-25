"""GET /api/v0/accounts/me/workers — the caller's own-account workers + derived
liveness, for the dashboard Overview "Your workers" panel.

Account-scoped by construction: the route resolves the account from the caller's
credential (here a tenant linked to the account) and returns only that account's
CURRENTLY-bound workers, each with a derived status (active / offline /
quarantined / retired). A different account's workers never appear; an anonymous
caller gets an empty list.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AccountRepository, TenantRepository
from auspexai_platform.db.repositories.workers import WorkerRepository

AUTHORITY = "testserver"
PATH = "/api/v0/accounts/me/workers"


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _account_with_tenant(
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    *,
    account_id: str,
    tenant_id: str,
) -> tuple[Ed25519PrivateKey, str]:
    """Account + a tenant linked to it; returns the tenant keypair (its credential
    resolves to account_id, so it can call /accounts/me/workers)."""
    account_repository.create(
        account_id=account_id, idp=IdentityProvider.GITHUB, idp_sub=account_id
    )
    priv, pub = _new_keypair()
    tenant_repository.register(tenant_id=tenant_id, maintainer_pubkey=pub, account_id=account_id)
    return priv, pub


def _bind_worker(
    worker_repository: WorkerRepository, *, worker_id: str, account_id: str, heartbeat: bool
) -> str:
    _priv, pub = _new_keypair()
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=pub, capabilities={"os": "linux"})
    worker_repository.bind_account(
        worker_id, account_id=account_id, trust_tier=TrustTier.T1_AUTHENTICATED
    )
    if heartbeat:
        worker_repository.record_heartbeat(worker_id)
    return pub


def _get(client: TestClient, *, privkey=None, pubkey_hex=None):
    if privkey is None:  # unsigned → anonymous
        return client.get(PATH)
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=PATH,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(PATH, headers=headers)


def test_returns_only_callers_own_account_workers(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    worker_repository: WorkerRepository,
) -> None:
    priv_a, pub_a = _account_with_tenant(
        account_repository, tenant_repository, account_id="acct-A", tenant_id="t-A"
    )
    _bind_worker(worker_repository, worker_id="wkr-A1", account_id="acct-A", heartbeat=True)
    _bind_worker(worker_repository, worker_id="wkr-A2", account_id="acct-A", heartbeat=False)
    # A different account's worker must never appear in A's list.
    _account_with_tenant(
        account_repository, tenant_repository, account_id="acct-B", tenant_id="t-B"
    )
    _bind_worker(worker_repository, worker_id="wkr-B1", account_id="acct-B", heartbeat=True)

    resp = _get(client, privkey=priv_a, pubkey_hex=pub_a)
    assert resp.status_code == 200, resp.text
    workers = resp.json()["workers"]
    assert [w["worker_id"] for w in workers] == ["wkr-A1", "wkr-A2"]  # sorted, account-A only
    by_id = {w["worker_id"]: w for w in workers}
    # Fresh heartbeat → active; never heartbeated → offline (derived status surfaces).
    assert by_id["wkr-A1"]["status"] == "active"
    assert by_id["wkr-A2"]["status"] == "offline"
    # No receipts yet → 0 lifetime results.
    assert by_id["wkr-A1"]["result_count"] == 0


def test_quarantine_surfaces_status_and_reason(
    client: TestClient,
    account_repository: AccountRepository,
    tenant_repository: TenantRepository,
    worker_repository: WorkerRepository,
) -> None:
    """A quarantined own-worker reads `quarantined` with the maintainer's reason —
    the researcher only ever sees their own account's workers, so the reason is
    surfaced here (not operator-only)."""
    priv, pub = _account_with_tenant(
        account_repository, tenant_repository, account_id="acct-Q", tenant_id="t-Q"
    )
    _bind_worker(worker_repository, worker_id="wkr-Q1", account_id="acct-Q", heartbeat=True)
    worker_repository.quarantine("wkr-Q1", reason="sandbox policy violation")

    resp = _get(client, privkey=priv, pubkey_hex=pub)
    assert resp.status_code == 200, resp.text
    w = resp.json()["workers"][0]
    assert w["status"] == "quarantined"
    assert w["quarantine_reason"] == "sandbox policy violation"


def test_anonymous_caller_gets_empty_list(client: TestClient) -> None:
    """No account (anonymous / unbound key) → an empty list, never a leak."""
    resp = _get(client)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"workers": []}
