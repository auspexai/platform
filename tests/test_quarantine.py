"""Tests for the maintainer-only worker quarantine endpoints (B3).

  POST /api/v0/workers/{id}/actions/quarantine    — maintainer
  POST /api/v0/workers/{id}/actions/unquarantine  — maintainer

Quarantine is reversible (vs. retire which is permanent and writes to
the retired_keys registry). A quarantined worker can still heartbeat
but cannot fetch new assignments (GET /assignments returns 423 Locked).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def _enroll(client: TestClient) -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    r = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": pub_hex, "capabilities": {"os": "linux"}},
    )
    assert r.status_code == 201, r.text
    return priv, r.json()["worker_id"]


class TestQuarantineEndpoint:
    def test_maintainer_can_quarantine_a_worker(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        _, worker_id = _enroll(client)
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "test pause"},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["worker_id"] == worker_id
        assert body["quarantined_at"] is not None
        # quarantine_reason is OPERATOR_ONLY; maintainer sees it.
        assert body.get("quarantine_reason") == "test pause"

    def test_quarantine_without_reason_is_allowed(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        _, worker_id = _enroll(client)
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200, r.text

    def test_anonymous_cannot_quarantine(self, client: TestClient) -> None:
        _, worker_id = _enroll(client)
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "x"},
        )
        assert r.status_code == 403, r.text

    def test_quarantine_unknown_worker_is_404(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        r = client.post(
            "/api/v0/workers/wkr-does-not-exist/actions/quarantine",
            json={"reason": "x"},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"]["code"] == "worker_not_found"

    def test_quarantine_is_idempotent(self, client: TestClient, maintainer_token: str) -> None:
        _, worker_id = _enroll(client)
        h = {"Authorization": f"Bearer {maintainer_token}"}
        r1 = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "first"},
            headers=h,
        )
        assert r1.status_code == 200
        first_ts = r1.json()["quarantined_at"]
        r2 = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "second"},
            headers=h,
        )
        assert r2.status_code == 200
        assert r2.json()["quarantined_at"] == first_ts
        assert r2.json()["quarantine_reason"] == "second"

    def test_quarantine_a_retired_worker_is_409(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        from auspexai_platform.db.repositories import WorkerRepository

        _, worker_id = _enroll(client)
        repo = WorkerRepository(client.app.state.db)
        repo.retire(worker_id)
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "too late"},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"]["code"] == "worker_retired"


class TestUnquarantineEndpoint:
    def test_unquarantine_clears_both_fields(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        _, worker_id = _enroll(client)
        h = {"Authorization": f"Bearer {maintainer_token}"}
        client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "x"},
            headers=h,
        )
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/unquarantine",
            headers=h,
        )
        assert r.status_code == 200
        body = r.json()
        # response_model_exclude_none drops None fields; absence == cleared.
        assert "quarantined_at" not in body
        assert "quarantine_reason" not in body

    def test_unquarantine_unknown_worker_is_404(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        r = client.post(
            "/api/v0/workers/wkr-does-not-exist/actions/unquarantine",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 404

    def test_unquarantine_unquarantined_worker_is_noop(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        _, worker_id = _enroll(client)
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/unquarantine",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200


class TestAssignmentBlockedWhileQuarantined:
    """The load-bearing behavior: a quarantined worker's GET /assignments
    call must return 423 Locked, and unquarantining restores it to 200."""

    def test_assignment_fetch_returns_423_when_quarantined(
        self, client: TestClient, maintainer_token: str, enrolled_worker
    ) -> None:
        from auspexai_platform.auth.signature import sign_request

        privkey, worker = enrolled_worker
        path = f"/api/v0/workers/{worker.worker_id}/assignments"
        h_maint = {"Authorization": f"Bearer {maintainer_token}"}

        # Quarantine via maintainer route.
        client.post(
            f"/api/v0/workers/{worker.worker_id}/actions/quarantine",
            json={"reason": "test"},
            headers=h_maint,
        )

        # Worker (signed) tries to fetch an assignment → 423.
        sig_headers = sign_request(
            privkey=privkey,
            pubkey_hex=worker.pubkey_hex,
            method="GET",
            path=path,
            authority="testserver",
            body=b"",
        )
        r = client.get(path, headers=sig_headers)
        assert r.status_code == 423, r.text
        body = r.json()
        assert body["detail"]["error"]["code"] == "worker_quarantined"
        # Quarantine reason IS surfaced to the worker itself: a volunteer is
        # entitled to know why its own machine was paused (trust-boundary
        # transparency). The reason travels with the status wherever the worker
        # surfaces — here in the worker-facing 423 envelope, and to the worker's
        # own-account researcher in the activity API. It is never shown to third
        # parties (other tenants / anonymous callers).
        assert body["detail"]["error"]["details"]["quarantine_reason"] == "test"

        # Unquarantine, then the same fetch should succeed (200, work_unit=null
        # because no experiments registered).
        client.post(
            f"/api/v0/workers/{worker.worker_id}/actions/unquarantine",
            headers=h_maint,
        )
        sig_headers = sign_request(
            privkey=privkey,
            pubkey_hex=worker.pubkey_hex,
            method="GET",
            path=path,
            authority="testserver",
            body=b"",
        )
        r = client.get(path, headers=sig_headers)
        assert r.status_code == 200, r.text
        assert r.json()["work_unit"] is None
