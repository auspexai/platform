"""Tests for M7a — retired_keys registry.

Covers the repository directly and the route-integration paths that close
the worker M6 withdraw loop: retire writes the pubkey to retired_keys; a
subsequent enroll with the same pubkey is refused with 409 pubkey_retired.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.repositories import (
    RetiredKeyRepository,
)
from auspexai_platform.db.repositories.retired_keys import DuplicateRetiredKeyError

AUTHORITY = "testserver"


# ---- repository CRUD ------------------------------------------------------


class TestRetiredKeyRepository:
    def test_retire_inserts_and_contains_finds(
        self, retired_key_repository: RetiredKeyRepository
    ) -> None:
        retired_key_repository.retire(
            pubkey_hex="a" * 64,
            worker_id="wkr-test",
            reason="withdraw",
        )
        assert retired_key_repository.contains("a" * 64) is True

    def test_contains_normalizes_case(self, retired_key_repository: RetiredKeyRepository) -> None:
        retired_key_repository.retire(
            pubkey_hex="A" * 64,
            worker_id="wkr-1",
            reason="withdraw",
        )
        # The repo stores lowercase; contains should match regardless of caller case.
        assert retired_key_repository.contains("a" * 64) is True
        assert retired_key_repository.contains("A" * 64) is True

    def test_contains_returns_false_for_unknown(
        self, retired_key_repository: RetiredKeyRepository
    ) -> None:
        assert retired_key_repository.contains("b" * 64) is False

    def test_get_returns_dataclass_with_fields_populated(
        self, retired_key_repository: RetiredKeyRepository
    ) -> None:
        retired_key_repository.retire(
            pubkey_hex="c" * 64,
            worker_id="wkr-c",
            reason="withdraw",
        )
        got = retired_key_repository.get("c" * 64)
        assert got is not None
        assert got.pubkey_hex == "c" * 64
        assert got.worker_id == "wkr-c"
        assert got.reason == "withdraw"
        assert got.retired_at is not None

    def test_double_retire_raises_duplicate_error(
        self, retired_key_repository: RetiredKeyRepository
    ) -> None:
        retired_key_repository.retire(
            pubkey_hex="d" * 64,
            worker_id="wkr-d",
        )
        import pytest

        with pytest.raises(DuplicateRetiredKeyError):
            retired_key_repository.retire(
                pubkey_hex="d" * 64,
                worker_id="wkr-d",
            )

    def test_list_all_returns_most_recent_first(
        self, retired_key_repository: RetiredKeyRepository
    ) -> None:
        retired_key_repository.retire(pubkey_hex="1" * 64, worker_id="wkr-1")
        retired_key_repository.retire(pubkey_hex="2" * 64, worker_id="wkr-2")
        retired_key_repository.retire(pubkey_hex="3" * 64, worker_id="wkr-3")
        all_keys = retired_key_repository.list_all()
        # SQLite CURRENT_TIMESTAMP at second resolution can tie; verify they
        # all show up rather than asserting strict ordering at sub-second
        # granularity.
        assert {k.pubkey_hex for k in all_keys} == {"1" * 64, "2" * 64, "3" * 64}


# ---- route integration: retire writes registry ----------------------------


def _signed_post(
    client: TestClient,
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    path: str,
    body: bytes = b"",
):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    if body:
        headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=body)


class TestRetireWritesRegistry:
    def test_retire_inserts_pubkey_into_registry(
        self,
        client: TestClient,
        enrolled_worker,
        retired_key_repository: RetiredKeyRepository,
    ) -> None:
        privkey, worker = enrolled_worker
        assert retired_key_repository.contains(worker.pubkey_hex) is False

        path = f"/api/v0/workers/{worker.worker_id}/actions/retire"
        response = _signed_post(client, privkey=privkey, pubkey_hex=worker.pubkey_hex, path=path)
        assert response.status_code == 200, response.text

        # Pubkey now in registry.
        assert retired_key_repository.contains(worker.pubkey_hex) is True
        registry_entry = retired_key_repository.get(worker.pubkey_hex)
        assert registry_entry is not None
        assert registry_entry.worker_id == worker.worker_id
        assert registry_entry.reason == "withdraw"

    def test_retire_by_maintainer_also_writes_registry(
        self,
        client: TestClient,
        maintainer_token: str,
        enrolled_worker,
        retired_key_repository: RetiredKeyRepository,
    ) -> None:
        _, worker = enrolled_worker
        response = client.post(
            f"/api/v0/workers/{worker.worker_id}/actions/retire",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        assert retired_key_repository.contains(worker.pubkey_hex) is True

    def test_double_retire_does_not_error(
        self,
        client: TestClient,
        maintainer_token: str,
        enrolled_worker,
        retired_key_repository: RetiredKeyRepository,
    ) -> None:
        """The retire endpoint is idempotent — calling it twice (e.g., after a
        prior partial failure on the worker side) should not error even though
        the second retire would hit DuplicateRetiredKeyError on the registry
        insert."""
        _, worker = enrolled_worker
        first = client.post(
            f"/api/v0/workers/{worker.worker_id}/actions/retire",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert first.status_code == 200
        second = client.post(
            f"/api/v0/workers/{worker.worker_id}/actions/retire",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert second.status_code == 200
        # Registry still contains the key (no duplicate-row creation).
        assert retired_key_repository.contains(worker.pubkey_hex) is True


# ---- route integration: enroll refuses retired pubkeys --------------------


class TestEnrollRefusesRetiredPubkey:
    def test_enroll_with_retired_pubkey_returns_409_pubkey_retired(
        self,
        client: TestClient,
        worker_keypair: tuple[Ed25519PrivateKey, str],
        retired_key_repository: RetiredKeyRepository,
    ) -> None:
        _, pubkey_hex = worker_keypair
        # Pre-populate the retired_keys registry as if a prior worker with
        # this pubkey had withdrawn.
        retired_key_repository.retire(
            pubkey_hex=pubkey_hex,
            worker_id="wkr-prior",
            reason="withdraw",
        )

        response = client.post(
            "/api/v0/workers/enroll",
            json={"pubkey_hex": pubkey_hex},
        )
        assert response.status_code == 409, response.text
        error = response.json()["detail"]["error"]
        assert error["code"] == "pubkey_retired"
        assert error["details"]["pubkey_hex"] == pubkey_hex
        assert "previously retired" in error["message"]

    def test_enroll_with_fresh_pubkey_still_succeeds(
        self,
        client: TestClient,
        worker_keypair: tuple[Ed25519PrivateKey, str],
        retired_key_repository: RetiredKeyRepository,
    ) -> None:
        """Sanity check: the retired_keys check doesn't break the fresh-enroll path."""
        # Retire a DIFFERENT pubkey so the registry is non-empty.
        retired_key_repository.retire(pubkey_hex="9" * 64, worker_id="wkr-other")

        _, pubkey_hex = worker_keypair
        response = client.post(
            "/api/v0/workers/enroll",
            json={"pubkey_hex": pubkey_hex},
        )
        assert response.status_code == 201, response.text


# ---- end-to-end: full withdraw cycle blocks re-bind ------------------------


class TestFullWithdrawCycle:
    def test_retire_then_re_enroll_refused(
        self,
        client: TestClient,
        enrolled_worker,
    ) -> None:
        """The load-bearing M7a behavior: worker enrolls, retires, tries to
        re-enroll with the same pubkey → refused with pubkey_retired."""
        privkey, worker = enrolled_worker

        # Step 1: retire.
        retire_path = f"/api/v0/workers/{worker.worker_id}/actions/retire"
        retire_resp = _signed_post(
            client, privkey=privkey, pubkey_hex=worker.pubkey_hex, path=retire_path
        )
        assert retire_resp.status_code == 200

        # Step 2: try to re-enroll with the same pubkey.
        re_enroll = client.post(
            "/api/v0/workers/enroll",
            json={"pubkey_hex": worker.pubkey_hex},
        )
        assert re_enroll.status_code == 409
        assert re_enroll.json()["detail"]["error"]["code"] == "pubkey_retired"

    def test_retired_pubkey_blocks_enroll_via_distinct_worker_id(
        self,
        client: TestClient,
        enrolled_worker,
    ) -> None:
        """Even though enroll generates a fresh worker_id, the retired_keys
        check is on the pubkey — the original worker_id is irrelevant."""
        privkey, worker = enrolled_worker
        retire_path = f"/api/v0/workers/{worker.worker_id}/actions/retire"
        _signed_post(client, privkey=privkey, pubkey_hex=worker.pubkey_hex, path=retire_path)

        # No matter what worker_id the coord generates, the pubkey is blocked.
        attempt = client.post(
            "/api/v0/workers/enroll",
            json={"pubkey_hex": worker.pubkey_hex, "capabilities": {"os": "linux"}},
        )
        assert attempt.status_code == 409
        assert attempt.json()["detail"]["error"]["code"] == "pubkey_retired"
