"""Worker-write credential propagation (audit findings F1/F2/F3).

A QUARANTINED worker — or a worker whose linked account is SUSPENDED — must not
have its output ingested. Before this fix, quarantine only gated assignment
DISPATCH (`GET /assignments` → 423); a worker quarantined while already holding
an assignment could still POST a result into consensus (and trigger receipt
issuance + tier auto-promotion). That is the same shape as the account-
suspension cascade bug, on the worker plane.

Pinned here:
  - F1: `submit_result` from a quarantined worker → 423; the held work is not
    lost (unquarantine → the same submit succeeds).
  - deliberate non-coverage of `refuse`: it releases a held unit back to the
    pool, which is harmless and better than stalling it to timeout.
  - F2/F3: the shared `enforce_worker_active` helper (used by submit_result and
    both vouch handlers) raises 423 on quarantine and 403 on account suspension,
    with quarantine taking precedence.
  - `pause` is intentionally NOT enforced (the open M9 pause-integrity question).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import HTTPException

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import enforce_worker_active
from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.work_units import WorkUnitRepository

AUTHORITY = "testserver"
_TS = datetime(2026, 6, 13, tzinfo=UTC)


def _signed_get(client, *, privkey, pubkey_hex, path):
    return client.get(
        path,
        headers=sign_request(
            privkey=privkey,
            pubkey_hex=pubkey_hex,
            method="GET",
            path=path,
            authority=AUTHORITY,
            body=b"",
        ),
    )


def _signed_post(client, *, privkey, pubkey_hex, path, payload: dict[str, Any]):
    body = json.dumps(payload).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=body)


def _seed_units(per_job_factory: PerJobDatabaseFactory, experiment_id: str, unit_ids: list[str]):
    db = per_job_factory.get_or_create(experiment_id)
    WorkUnitRepository(db).submit_batch(
        [{"unit_id": uid, "payload": {"input": i}} for i, uid in enumerate(unit_ids)]
    )


def _result_payload(unit_id: str, pubkey_hex: str) -> dict[str, Any]:
    return {
        "unit_id": unit_id,
        "worker_pubkey": pubkey_hex,
        "completed_at": "2026-05-19T12:00:00+00:00",
        "exit_code": 0,
        "payload": {"out": 1},
        "worker_signature": "ZmFrZS1zaWc=",  # base64 placeholder
    }


def _quarantine(client, worker_id, maintainer_token, reason="bad output"):
    return client.post(
        f"/api/v0/workers/{worker_id}/actions/quarantine",
        json={"reason": reason},
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )


# ---- F1: ingestion-path enforcement (integration) -------------------------


def test_quarantined_worker_result_is_rejected_then_recovers(
    client,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    maintainer_token: str,
) -> None:
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])
    wid = worker.worker_id

    # Worker takes the assignment, THEN the operator quarantines it mid-flight.
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    assert _quarantine(client, wid, maintainer_token).status_code == 200

    # The result POST must now be refused — the ingestion lever finally bites.
    path = f"/api/v0/workers/{wid}/assignments/{unit_id}/result"
    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=path,
        payload=_result_payload(unit_id, worker.pubkey_hex),
    )
    assert r.status_code == 423, r.text
    err = r.json()["detail"]["error"]
    assert err["code"] == "worker_quarantined"
    assert err["details"]["quarantine_reason"] == "bad output"

    # Unquarantine → the same work submits cleanly (it was held, not lost).
    client.post(
        f"/api/v0/workers/{wid}/actions/unquarantine",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    r2 = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=path,
        payload=_result_payload(unit_id, worker.pubkey_hex),
    )
    assert r2.status_code == 201, r2.text


def test_quarantined_worker_can_still_refuse(
    client,
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    maintainer_token: str,
) -> None:
    """Deliberate scope: `refuse` releases a held unit back to the pool, so a
    quarantined worker declining its in-flight work is harmless (and better
    than stalling it to assignment-timeout). It must NOT be gated."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])
    wid = worker.worker_id

    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    assert _quarantine(client, wid, maintainer_token).status_code == 200

    r = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/refuse",
        payload={"kind": "manual", "reason": "quarantined; releasing the unit"},
    )
    assert r.status_code == 200, r.text


# ---- F2/F3: the shared helper, in isolation -------------------------------


def _worker_cred() -> Credential:
    return Credential(
        kind=CredentialClass.WORKER, worker_id="wkr-x", account_id="acct-x", pubkey_hex="aa"
    )


class _Repo:
    def __init__(self, obj: Any) -> None:
        self._obj = obj

    def get_by_id(self, _id: str) -> Any:
        return self._obj


class _Worker:
    def __init__(self, quarantined_at=None, reason=None) -> None:
        self.quarantined_at = quarantined_at
        self.quarantine_reason = reason


class _Account:
    def __init__(self, suspended_at=None, reason=None) -> None:
        self.suspended_at = suspended_at
        self.suspension_reason = reason


def test_enforce_worker_active_passes_for_healthy() -> None:
    enforce_worker_active(_worker_cred(), _Repo(_Worker()), _Repo(_Account()))  # no raise


def test_enforce_worker_active_blocks_quarantined() -> None:
    with pytest.raises(HTTPException) as ei:
        enforce_worker_active(_worker_cred(), _Repo(_Worker(_TS, "bad")), _Repo(_Account()))
    assert ei.value.status_code == 423
    assert ei.value.detail["error"]["code"] == "worker_quarantined"


def test_enforce_worker_active_blocks_suspended_account() -> None:
    with pytest.raises(HTTPException) as ei:
        enforce_worker_active(_worker_cred(), _Repo(_Worker()), _Repo(_Account(_TS, "fraud")))
    assert ei.value.status_code == 403
    assert ei.value.detail["error"]["code"] == "account_suspended"


def test_enforce_worker_active_quarantine_precedes_suspension() -> None:
    with pytest.raises(HTTPException) as ei:
        enforce_worker_active(_worker_cred(), _Repo(_Worker(_TS, "q")), _Repo(_Account(_TS, "s")))
    assert ei.value.status_code == 423


def test_enforce_worker_active_tolerates_missing_repos() -> None:
    # account_repository=None (legacy wiring) must not crash the write path.
    enforce_worker_active(_worker_cred(), _Repo(_Worker()), None)
