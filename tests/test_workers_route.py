"""End-to-end tests for /api/v0/workers."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AccountRepository, WorkerRepository
from auspexai_platform.oauth.identity import IdentityClaim

from .conftest import FakeIdentityVerifier

AUTHORITY = "testserver"  # TestClient sets this on every request


def _signed_headers(
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method=method,
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    # TestClient doesn't set Content-Type when callers pass `content=`. JSON
    # bodies need it set explicitly so FastAPI parses them. Content-Type is
    # not signature-covered (only @method/@path/@authority/content-digest),
    # so adding it here doesn't affect verification.
    if body:
        headers["Content-Type"] = "application/json"
    return headers


# ---- POST /workers/enroll -------------------------------------------------


def test_enroll_creates_t0_worker(
    client: TestClient,
    worker_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    _, pubkey_hex = worker_keypair
    response = client.post(
        "/api/v0/workers/enroll",
        json={
            "pubkey_hex": pubkey_hex,
            "capabilities": {"os": "linux", "ram_gb": 32},
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["worker_id"].startswith("wkr-")
    assert body["trust_tier"] == int(TrustTier.T0_ANONYMOUS)


def test_enroll_rejects_pubkey_already_a_tenant(
    client: TestClient,
    registered_tenant,
) -> None:
    _, binding = registered_tenant
    response = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": binding.pubkey_hex},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "pubkey_already_tenant"


def test_enroll_rejects_duplicate_worker_pubkey(
    client: TestClient,
    worker_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    _, pubkey_hex = worker_keypair
    first = client.post("/api/v0/workers/enroll", json={"pubkey_hex": pubkey_hex})
    assert first.status_code == 201
    second = client.post("/api/v0/workers/enroll", json={"pubkey_hex": pubkey_hex})
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "pubkey_already_enrolled"


def test_enroll_rejects_bad_pubkey_format(client: TestClient) -> None:
    response = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": "not-hex"},
    )
    assert response.status_code == 422


# ---- POST /workers/{id}/upgrade ------------------------------------------


def test_upgrade_binds_account_and_promotes_to_t1(
    client: TestClient,
    enrolled_worker,
    identity_verifier: FakeIdentityVerifier,
    account_repository: AccountRepository,
    worker_repository: WorkerRepository,
) -> None:
    privkey, worker = enrolled_worker

    # Worker completes the device flow; the OAuth exchange mints a binding.
    identity_verifier.register(
        "gho_upgrade",
        IdentityClaim(idp=IdentityProvider.GITHUB, idp_sub="100"),
    )
    exchange = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_upgrade"},
    ).json()
    binding_token = exchange["binding_token"]
    account_id = exchange["account_id"]

    path = f"/api/v0/workers/{worker.worker_id}/upgrade"
    payload = b'{"binding_token": "%s"}' % binding_token.encode()
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["worker_id"] == worker.worker_id
    assert body["trust_tier"] == int(TrustTier.T1_VERIFIED)

    # DB reflects the upgrade.
    reread = worker_repository.get_by_id(worker.worker_id)
    assert reread is not None
    assert reread.trust_tier is TrustTier.T1_VERIFIED
    assert reread.account_id == account_id


def test_upgrade_requires_worker_credential(
    client: TestClient,
    enrolled_worker,
) -> None:
    _, worker = enrolled_worker
    response = client.post(
        f"/api/v0/workers/{worker.worker_id}/upgrade",
        json={"binding_token": "anything"},
    )
    # Anonymous → 403 worker_required
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_required"


def test_upgrade_rejects_wrong_worker_id(
    client: TestClient,
    enrolled_worker,
    worker_repository: WorkerRepository,
    worker_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    """A worker can only upgrade itself, not someone else's worker_id."""
    privkey, worker = enrolled_worker
    # Enroll a second worker with a different pubkey + worker_id.
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    other_worker = worker_repository.enroll(worker_id="wkr-other", pubkey_hex=other_pub)

    # First worker signs a request targeting the *other* worker's URL.
    path = f"/api/v0/workers/{other_worker.worker_id}/upgrade"
    payload = b'{"binding_token": "tok"}'
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_id_mismatch"


def test_upgrade_rejects_unknown_binding_token(
    client: TestClient,
    enrolled_worker,
) -> None:
    privkey, worker = enrolled_worker
    path = f"/api/v0/workers/{worker.worker_id}/upgrade"
    payload = b'{"binding_token": "does-not-exist"}'
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "binding_token_not_found"


def test_upgrade_rejects_consumed_binding_token(
    client: TestClient,
    enrolled_worker,
    identity_verifier: FakeIdentityVerifier,
    account_repository: AccountRepository,
) -> None:
    privkey, worker = enrolled_worker
    identity_verifier.register(
        "gho_consume",
        IdentityClaim(idp=IdentityProvider.GITHUB, idp_sub="200"),
    )
    exchange = client.post(
        "/api/v0/accounts/oauth/exchange",
        json={"idp": "github", "access_token": "gho_consume"},
    ).json()
    binding_token = exchange["binding_token"]
    account_repository.consume_binding(binding_token)

    path = f"/api/v0/workers/{worker.worker_id}/upgrade"
    payload = b'{"binding_token": "%s"}' % binding_token.encode()
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 409
    assert response.json()["detail"]["error"]["code"] == "binding_token_consumed"


# ---- POST /workers/{id}/heartbeat -----------------------------------------


def test_heartbeat_updates_timestamp(
    client: TestClient,
    enrolled_worker,
    worker_repository: WorkerRepository,
) -> None:
    privkey, worker = enrolled_worker
    assert worker.last_heartbeat_at is None

    path = f"/api/v0/workers/{worker.worker_id}/heartbeat"
    payload = b"{}"
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 200, response.text

    reread = worker_repository.get_by_id(worker.worker_id)
    assert reread is not None
    assert reread.last_heartbeat_at is not None


def test_heartbeat_updates_capabilities_when_supplied(
    client: TestClient,
    enrolled_worker,
    worker_repository: WorkerRepository,
) -> None:
    privkey, worker = enrolled_worker
    path = f"/api/v0/workers/{worker.worker_id}/heartbeat"
    payload = b'{"capabilities": {"os": "linux", "ram_gb": 64, "gpus": ["rtx-4090"]}}'
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=payload,
    )
    response = client.post(path, headers=headers, content=payload)
    assert response.status_code == 200

    reread = worker_repository.get_by_id(worker.worker_id)
    assert reread is not None
    assert reread.capabilities == {
        "os": "linux",
        "ram_gb": 64,
        "gpus": ["rtx-4090"],
    }


# ---- GET /workers (maintainer list) --------------------------------------


def test_list_workers_requires_maintainer(client: TestClient, enrolled_worker) -> None:
    response = client.get("/api/v0/workers")
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "maintainer_required"


def test_list_workers_returns_all_for_maintainer(
    client: TestClient,
    maintainer_token: str,
    enrolled_worker,
) -> None:
    response = client.get(
        "/api/v0/workers",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    workers = response.json()["workers"]
    assert len(workers) == 1
    # Maintainer sees operator-only fields too.
    assert workers[0]["pubkey_hex"]


# ---- GET /workers/{id} (self or maintainer) ------------------------------


def test_get_worker_self_filters_operator_fields(
    client: TestClient,
    enrolled_worker,
) -> None:
    privkey, worker = enrolled_worker
    path = f"/api/v0/workers/{worker.worker_id}"
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="GET",
        path=path,
        body=b"",
    )
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["worker_id"] == worker.worker_id
    # Self is NOT a maintainer; operator-only fields filtered out.
    assert "pubkey_hex" not in body
    assert "capabilities" not in body


def test_get_worker_anonymous_is_forbidden(client: TestClient, enrolled_worker) -> None:
    _, worker = enrolled_worker
    response = client.get(f"/api/v0/workers/{worker.worker_id}")
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "worker_self_or_maintainer_required"


def test_get_worker_other_worker_is_forbidden(
    client: TestClient,
    enrolled_worker,
    worker_repository: WorkerRepository,
) -> None:
    privkey, worker = enrolled_worker
    other = worker_repository.enroll(worker_id="wkr-other", pubkey_hex="b" * 64)

    path = f"/api/v0/workers/{other.worker_id}"
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="GET",
        path=path,
        body=b"",
    )
    response = client.get(path, headers=headers)
    assert response.status_code == 403


# ---- POST /workers/{id}/actions/retire -----------------------------------


def test_retire_by_self_succeeds(
    client: TestClient,
    enrolled_worker,
    worker_repository: WorkerRepository,
) -> None:
    privkey, worker = enrolled_worker
    path = f"/api/v0/workers/{worker.worker_id}/actions/retire"
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=b"",
    )
    response = client.post(path, headers=headers)
    assert response.status_code == 200, response.text

    reread = worker_repository.get_by_id(worker.worker_id)
    assert reread is not None
    assert reread.retired_at is not None


def test_retire_by_maintainer_succeeds(
    client: TestClient,
    maintainer_token: str,
    enrolled_worker,
    worker_repository: WorkerRepository,
) -> None:
    _, worker = enrolled_worker
    response = client.post(
        f"/api/v0/workers/{worker.worker_id}/actions/retire",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200

    reread = worker_repository.get_by_id(worker.worker_id)
    assert reread is not None
    assert reread.retired_at is not None


def test_retired_worker_cannot_sign_subsequent_requests(
    client: TestClient,
    enrolled_worker,
    maintainer_token: str,
) -> None:
    """Retired workers fall out of the CredentialResolver (worker_registry
    filters retired). Signed requests after retire → 401 unknown keyid."""
    privkey, worker = enrolled_worker

    # Maintainer retires the worker.
    client.post(
        f"/api/v0/workers/{worker.worker_id}/actions/retire",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )

    # Worker tries to heartbeat; signature verifies but keyid is unknown now.
    path = f"/api/v0/workers/{worker.worker_id}/heartbeat"
    headers = _signed_headers(
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        method="POST",
        path=path,
        body=b"{}",
    )
    response = client.post(path, headers=headers, content=b"{}")
    assert response.status_code == 401
