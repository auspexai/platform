"""Ops worker↔tenant association — GET /api/v0/tenants/{id}/linkage.

The operator's all-linkages view: for one tenant, its bound account (b-lite
tenants.account_id) and the workers under that account. Operator-only — the
whole view is account_id / worker-pubkey / account↔worker-mapping data, all
operator-only per operator_console_design.md §8. Access:
  - maintainer → 200 with {tenant, account, workers[]}
  - researcher / anonymous → 403 (require_maintainer)
  - unknown tenant (as maintainer) → 404
  - unlinked tenant → 200 with account=null, workers omitted/empty

See operator_console_design.md §11 and principles §6.9 / §9 #26.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider, TrustTier

AUTHORITY = "testserver"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _enroll_bound_worker(worker_repository, worker_id: str, account_id: str) -> str:
    _priv, pub = _new_keypair()
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=pub, capabilities={"os": "linux"})
    worker_repository.bind_account(
        worker_id, account_id=account_id, trust_tier=TrustTier.T1_AUTHENTICATED
    )
    return pub


def test_maintainer_sees_full_linkage(
    client: TestClient,
    maintainer_token: str,
    account_repository,
    tenant_repository,
    worker_repository,
) -> None:
    account_repository.create(
        account_id="acct-link", idp=IdentityProvider.GITHUB, idp_sub="gh-link"
    )
    _priv, pub = _new_keypair()
    tenant_repository.register(tenant_id="t-linked", maintainer_pubkey=pub, account_id="acct-link")
    w1 = _enroll_bound_worker(worker_repository, "wkr-1", "acct-link")
    _enroll_bound_worker(worker_repository, "wkr-2", "acct-link")
    # A worker on a DIFFERENT account must not appear under this tenant.
    account_repository.create(
        account_id="acct-other", idp=IdentityProvider.GITHUB, idp_sub="gh-other"
    )
    _enroll_bound_worker(worker_repository, "wkr-other", "acct-other")

    resp = client.get("/api/v0/tenants/t-linked/linkage", headers=_bearer(maintainer_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "t-linked"
    assert body["maintainer_pubkey"] == pub
    assert body["account_id"] == "acct-link"
    assert body["account"]["account_id"] == "acct-link"
    assert body["account"]["trust_tier"] == int(TrustTier.T1_AUTHENTICATED)
    worker_ids = {w["worker_id"] for w in body["workers"]}
    assert worker_ids == {"wkr-1", "wkr-2"}
    assert "wkr-other" not in worker_ids
    by_id = {w["worker_id"]: w for w in body["workers"]}
    assert by_id["wkr-1"]["pubkey_hex"] == w1
    assert by_id["wkr-1"]["trust_tier"] == int(TrustTier.T1_AUTHENTICATED)


def test_unlinked_tenant_has_null_account_and_no_workers(
    client: TestClient,
    maintainer_token: str,
    tenant_repository,
    worker_repository,
) -> None:
    _priv, pub = _new_keypair()
    tenant_repository.register(tenant_id="t-unlinked", maintainer_pubkey=pub)
    resp = client.get("/api/v0/tenants/t-unlinked/linkage", headers=_bearer(maintainer_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "t-unlinked"
    # response_model_exclude_none drops the null account_id + null account +
    # empty-list workers. Check membership before subscripting (an unlinked
    # tenant has no account_id key at all).
    assert "account_id" not in body or body["account_id"] is None
    assert body.get("account") is None
    assert body.get("workers") in (None, [])


def test_researcher_gets_403(
    client: TestClient,
    tenant_repository,
) -> None:
    priv, pub = _new_keypair()
    tenant_repository.register(tenant_id="t-self", maintainer_pubkey=pub)
    # Even the tenant's OWN researcher credential cannot read the linkage view —
    # it's operator-only (the ops all-linkages counterpart, not a self view).
    resp = _signed_get(client, privkey=priv, pubkey_hex=pub, path="/api/v0/tenants/t-self/linkage")
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"]["code"] == "maintainer_required"


def test_anonymous_gets_403(client: TestClient, tenant_repository) -> None:
    _priv, pub = _new_keypair()
    tenant_repository.register(tenant_id="t-anon", maintainer_pubkey=pub)
    resp = client.get("/api/v0/tenants/t-anon/linkage")
    assert resp.status_code == 403, resp.text


def test_unknown_tenant_404_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    resp = client.get("/api/v0/tenants/t-does-not-exist/linkage", headers=_bearer(maintainer_token))
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["error"]["code"] == "tenant_not_found"
