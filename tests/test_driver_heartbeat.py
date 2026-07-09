"""Driver liveness telemetry (0059) — the off-coordinator tenant driver reports
its heartbeat / exit reason so a stalled or stranded run is a timestamped,
queryable server-side fact instead of a silent mystery (it was only ever visible
in the Mac-side driver.log)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.config import Config
from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import AuditRepository
from tests.test_integration_full_flow import _ed25519, _signed_request


def _approved_experiment(client, mh, rp, rpub, tenant: str, exp: str) -> str:
    client.post(
        "/api/v0/tenants",
        headers=mh,
        json={"tenant_id": tenant, "maintainer_pubkey": rpub, "display_name": tenant},
    )
    r = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "manifest": {
                "tenant_id": tenant,
                "experiment_id": exp,
                "executor": "python -m x",
                "replication_factor": 1,
            },
            "signature": {"alg": "ed25519", "sig": "x"},
        },
    )
    assert r.status_code == 201, r.text
    exp_id = r.json()["experiment_id"]
    assert (
        client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh).status_code == 200
    )
    return exp_id


def _get(client, rp, rpub, exp_id):
    return _signed_request(
        client, method="GET", path=f"/api/v0/experiments/{exp_id}", privkey=rp, pubkey_hex=rpub
    ).json()


def test_driving_heartbeat_surfaces_on_the_experiment(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    """A `driving` heartbeat is stored and surfaced on the experiment detail with a
    non-negative silence gap — the owning researcher can see their driver is live."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    exp_id = _approved_experiment(client, mh, rp, rpub, "synth-drv", "drv-1")

    # No driver has reported yet → no driver block.
    assert _get(client, rp, rpub, exp_id).get("driver") is None

    r = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/driver-heartbeat",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={"status": "driving", "run_id": "run-1", "round": 3},
    )
    assert r.status_code == 204, r.text

    driver = _get(client, rp, rpub, exp_id)["driver"]
    assert driver["status"] == "driving"
    assert driver["run_id"] == "run-1"
    assert driver["round"] == 3
    assert driver["silent_for_seconds"] is not None and driver["silent_for_seconds"] >= 0


def test_exit_heartbeat_is_audited_with_its_reason(
    client: TestClient, config: Config, maintainer_token: str, db: Database
) -> None:
    """An `exiting` heartbeat records WHY the driver stopped — surfaced on the
    experiment AND written to the audit log as `driver.exit`, so the death cause
    (e.g. http_502) is a durable, queryable fact."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    exp_id = _approved_experiment(client, mh, rp, rpub, "synth-drv2", "drv-2")

    r = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/driver-heartbeat",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={"status": "exiting", "reason": "http_502", "run_id": "run-2"},
    )
    assert r.status_code == 204, r.text

    driver = _get(client, rp, rpub, exp_id)["driver"]
    assert driver["status"] == "exiting"
    assert driver["reason"] == "http_502"

    entries, total = AuditRepository(db).list(action="driver.exit")
    assert total >= 1
    hit = [e for e in entries if e.resource_id == exp_id]
    assert hit, "driver.exit audit entry missing for the experiment"


def test_heartbeat_rejects_unknown_status(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    """The status is a bounded enum — a garbage status is a 422, not stored."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    exp_id = _approved_experiment(client, mh, rp, rpub, "synth-drv3", "drv-3")
    r = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/driver-heartbeat",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={"status": "banana"},
    )
    assert r.status_code == 422, r.text
