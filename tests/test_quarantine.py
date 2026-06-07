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

from auspexai_platform.events import GLOBAL


def _enroll(client: TestClient) -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    r = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": pub_hex, "capabilities": {"os": "linux"}},
    )
    assert r.status_code == 201, r.text
    return priv, r.json()["worker_id"]


def test_quarantine_publishes_worker_status(client: TestClient, maintainer_token: str) -> None:
    """M6 (step 4): a worker-state transition emits worker.status on the maintainer
    firehose → the operator console reflects fleet changes live. Full detail, fleet
    event (experiment_id=None → firehose only)."""
    _, worker_id = _enroll(client)
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "m6 step4 test"},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200, r.text
        ev = q.get_nowait()  # publish ran during the synchronous POST
    assert ev.type == "worker.status"
    assert ev.experiment_id is None
    assert ev.data["worker_id"] == worker_id
    assert ev.data["status"] == "quarantined"
    assert ev.data["quarantine_reason"] == "m6 step4 test"
    assert ev.data["trigger"] == "quarantine"


def test_quarantine_publishes_network_status(client: TestClient, maintainer_token: str) -> None:
    """M6 #2a: a worker-state transition also emits network.status — an
    identity-free PUBLIC fleet count (network_active_workers) on the firehose, so
    a network-size surface updates without enumerating workers. Anonymized: no
    worker_id in the payload."""
    _, worker_id = _enroll(client)
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"/api/v0/workers/{worker_id}/actions/quarantine",
            json={"reason": "m6 #2a test"},
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200, r.text
        events = []
        while not q.empty():
            events.append(q.get_nowait())
    by_type = {e.type: e for e in events}
    assert "worker.status" in by_type
    assert "network.status" in by_type
    net = by_type["network.status"]
    assert net.experiment_id is None  # fleet-wide → firehose
    assert net.data["trigger"] == "quarantine"
    assert isinstance(net.data["network_active_workers"], int)
    assert "worker_id" not in net.data  # anonymized count, no identity


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
