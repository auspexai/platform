"""C14 regime-2 settle-sweep — capacity-aware completion of capacity-stuck units.

A unit aiming for more replicas than the eligible fleet can supply would otherwise stall
forever. Once the fleet is exhausted AND quiescent, `settle_sweep` completes it at its
achieved replication, running the SAME post-completion path as a normal completion.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from auspexai_platform.completion import CAP_ROUND_MARGIN, reached_unit_cap
from auspexai_platform.config import Config
from auspexai_platform.db.database import Database
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.maintenance import settle_sweep
from tests._result_helpers import sign_result_body
from tests.test_integration_full_flow import _ed25519, _enroll_worker, _signed_request


def test_reached_unit_cap_boundaries() -> None:
    m = CAP_ROUND_MARGIN
    # No cap, or a cap too small to tell a round from the whole run → never capped.
    assert reached_unit_cap(None, 10_000) is False
    assert reached_unit_cap(0, 0) is False
    assert reached_unit_cap(2 * m, 2 * m) is False  # cap must be > 2*margin
    # A real cap: within a final round → capped; short by more than a round → not.
    cap = 500
    assert reached_unit_cap(cap, cap) is True
    assert reached_unit_cap(cap, cap - m) is True  # exactly one round short still counts
    assert reached_unit_cap(cap, cap - m - 1) is False  # more than a round short
    assert reached_unit_cap(cap, 0) is False


def _submit_result(client: TestClient, wid: str, wp, wpub: str, unit_id: str) -> None:
    resp = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        privkey=wp,
        pubkey_hex=wpub,
        json_body={
            "unit_id": unit_id,
            "worker_pubkey": wpub,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"output": 2},
            "worker_signature": sign_result_body(
                wp,
                wpub,
                unit_id=unit_id,
                completed_at="2026-05-19T12:00:00+00:00",
                exit_code=0,
                payload={"output": 2},
            ),
        },
    )
    assert resp.status_code == 201, resp.text


def test_settle_sweep_completes_capacity_stuck_unit_at_floor(
    client: TestClient, config: Config, maintainer_token: str, db: Database
) -> None:
    """A repl-3 unit on a 2-worker fleet stalls at 2 (regime 2). Once the fleet is exhausted
    and quiescent, the settle-sweep completes it at its achieved replication (2) and runs the
    full post-completion path → the experiment auto-completes."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    assert (
        client.post(
            "/api/v0/tenants",
            headers=mh,
            json={
                "tenant_id": "synth-settle",
                "maintainer_pubkey": rpub,
                "display_name": "Settle",
            },
        ).status_code
        == 201
    )
    r = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "manifest": {
                "tenant_id": "synth-settle",
                "experiment_id": "settle-1",
                "executor": "python -m x",
                "replication_factor": 3,  # aim for 3 on a fleet that only supplies 2
            },
            "signature": {"alg": "ed25519", "sig": "x"},
        },
    )
    assert r.status_code == 201, r.text
    exp_id = r.json()["experiment_id"]
    manifest_hash = r.json()["manifest_hash"]
    assert (
        client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh).status_code == 200
    )
    r = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-settle",
                    "tenant_id": "synth-settle",
                    "experiment_id": "settle-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 1},
                }
            ]
        },
    )
    assert r.status_code == 201, r.text
    assert (
        _signed_request(
            client,
            method="POST",
            path=f"/api/v0/experiments/{exp_id}/actions/finalize-submissions",
            privkey=rp,
            pubkey_hex=rpub,
        ).status_code
        == 200
    )

    # Only TWO workers contribute though the target is 3 → unit stalls IN_PROGRESS at 2.
    for _ in range(2):
        wp, wpub, wid = _enroll_worker(client)
        pick = _signed_request(
            client,
            method="GET",
            path=f"/api/v0/workers/{wid}/assignments",
            privkey=wp,
            pubkey_hex=wpub,
        ).json()
        assert pick["work_unit"]["unit_id"] == "u-settle"
        _submit_result(client, wid, wp, wpub, "u-settle")

    # Stuck at 2 of 3 → the experiment has NOT auto-completed.
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "approved"

    now = datetime.now(UTC)
    # The fleet is live (fresh heartbeats) but has delivered all it will — every eligible
    # worker already has a result, so the unit is fleet-exhausted.
    with db.transaction() as cur:
        cur.execute("UPDATE workers SET last_heartbeat_at = ?", (now.isoformat(),))
    # Results were just submitted → not quiescent yet → the sweep settles nothing.
    assert settle_sweep(config, apply=False, now=now).settled == []

    # Age the results past the quiescence window (server-side received_at).
    pj = PerJobDatabaseFactory(config.jobs_dir).get(exp_id)
    assert pj is not None
    with pj.transaction() as cur:
        cur.execute(
            "UPDATE results SET received_at = ?", ((now - timedelta(minutes=30)).isoformat(),)
        )

    # Now quiescent + the live fleet has all contributed → settle at the achieved 2.
    report = settle_sweep(config, apply=True, now=now)
    settled = [s for s in report.settled if s.unit_id == "u-settle"]
    assert settled, report.summary()
    assert settled[0].achieved == 2
    assert settled[0].target == 3
    assert settled[0].floor == 2

    # The settle ran the full post-completion path → the experiment auto-completed.
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "completed"


def test_settle_sweep_waits_while_a_worker_can_still_contribute(
    client: TestClient, config: Config, maintainer_token: str, db: Database
) -> None:
    """If a schedulable eligible worker has NOT yet contributed, the unit is not fleet-exhausted
    — the sweep leaves it alone even when quiescent (it may still reach its target)."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    client.post(
        "/api/v0/tenants",
        headers=mh,
        json={"tenant_id": "synth-wait", "maintainer_pubkey": rpub, "display_name": "Wait"},
    )
    r = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "manifest": {
                "tenant_id": "synth-wait",
                "experiment_id": "wait-1",
                "executor": "python -m x",
                "replication_factor": 3,
            },
            "signature": {"alg": "ed25519", "sig": "x"},
        },
    )
    exp_id = r.json()["experiment_id"]
    manifest_hash = r.json()["manifest_hash"]
    client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh)
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-wait",
                    "tenant_id": "synth-wait",
                    "experiment_id": "wait-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 1},
                }
            ]
        },
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/finalize-submissions",
        privkey=rp,
        pubkey_hex=rpub,
    )
    # Two workers contribute (stuck at 2 of 3) ...
    for _ in range(2):
        wp, wpub, wid = _enroll_worker(client)
        _signed_request(
            client,
            method="GET",
            path=f"/api/v0/workers/{wid}/assignments",
            privkey=wp,
            pubkey_hex=wpub,
        )
        _submit_result(client, wid, wp, wpub, "u-wait")
    # ... but a THIRD eligible worker FETCHES the unit (in-flight, live + heartbeating) — its
    # result is still pending, so the fleet is NOT exhausted.
    wp3, wpub3, wid3 = _enroll_worker(client)
    pick3 = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid3}/assignments",
        privkey=wp3,
        pubkey_hex=wpub3,
    ).json()
    assert pick3["work_unit"]["unit_id"] == "u-wait"

    now = datetime.now(UTC)
    # All three workers are live (fresh heartbeats); worker 3 holds the unit in-flight.
    with db.transaction() as cur:
        cur.execute("UPDATE workers SET last_heartbeat_at = ?", (now.isoformat(),))
    pj = PerJobDatabaseFactory(config.jobs_dir).get(exp_id)
    assert pj is not None
    with pj.transaction() as cur:
        cur.execute(
            "UPDATE results SET received_at = ?", ((now - timedelta(minutes=30)).isoformat(),)
        )

    # Quiescent, but the fleet is NOT exhausted (worker 3 could still take it) → no settle.
    assert settle_sweep(config, apply=True, now=now).settled == []
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "approved"


def _make_experiment(client, mh, rp, rpub, tenant: str, exp: str) -> tuple[str, str]:
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
                "replication_factor": 3,
            },
            "signature": {"alg": "ed25519", "sig": "x"},
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["experiment_id"], r.json()["manifest_hash"]


def test_regime3_pauses_below_floor_then_resumes_when_capacity_recovers(
    client: TestClient, config: Config, maintainer_token: str, db: Database
) -> None:
    """C14 regime 3: a repl-3 experiment with only ONE worker delivers 1 result (< floor 2) and
    the fleet is exhausted → the sweep PAUSES the experiment; when a second worker enrolls (the
    floor becomes achievable again) the sweep RESUMES it."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    exp_id, manifest_hash = _make_experiment(client, mh, rp, rpub, "synth-r3", "r3-1")
    client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh)
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-r3",
                    "tenant_id": "synth-r3",
                    "experiment_id": "r3-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 1},
                }
            ]
        },
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/finalize-submissions",
        privkey=rp,
        pubkey_hex=rpub,
    )

    # ONE worker delivers (completions=1 < floor 2); no other eligible worker exists.
    wp1, wpub1, wid1 = _enroll_worker(client)
    _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid1}/assignments",
        privkey=wp1,
        pubkey_hex=wpub1,
    )
    _submit_result(client, wid1, wp1, wpub1, "u-r3")

    now = datetime.now(UTC)
    with db.transaction() as cur:
        cur.execute("UPDATE workers SET last_heartbeat_at = ?", (now.isoformat(),))
    pj = PerJobDatabaseFactory(config.jobs_dir).get(exp_id)
    assert pj is not None
    with pj.transaction() as cur:
        cur.execute(
            "UPDATE results SET received_at = ?", ((now - timedelta(minutes=30)).isoformat(),)
        )

    # Below floor + fleet exhausted + quiescent → PAUSE the experiment.
    report = settle_sweep(config, apply=True, now=now)
    assert any(p.unit_id == "u-r3" for p in report.paused), report.summary()
    assert report.settled == []
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "paused"

    # The pause audit distinguishes STRUCTURAL starvation (only 1 capable worker in the
    # fleet, below floor 2) from a transient dip — so the operator can tell them apart.
    rows = db.execute("SELECT payload FROM audit_log WHERE action = 'experiment.regime3_pause'")
    payloads = [json.loads(r["payload"]) for r in rows]
    assert any(
        p.get("structural") is True and p.get("eligible_capable_workers") == 1 for p in payloads
    ), payloads
    assert any(p.get("trigger") == "structural_under_replication" for p in payloads)

    # A SECOND worker enrolls — the floor (2) is achievable again → RESUME.
    _enroll_worker(client)
    now2 = datetime.now(UTC)
    with db.transaction() as cur:
        cur.execute("UPDATE workers SET last_heartbeat_at = ?", (now2.isoformat(),))
    report2 = settle_sweep(config, apply=True, now=now2)
    assert exp_id in report2.resumed, report2.summary()
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "approved"


def test_regime3_never_resumes_an_operator_pause(
    client: TestClient, config: Config, maintainer_token: str, db: Database
) -> None:
    """The auto-resume only un-pauses experiments the SWEEP paused (last_action_by_class=SYSTEM).
    An operator pause is left alone, even when capacity is fine."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    exp_id, _ = _make_experiment(client, mh, rp, rpub, "synth-op", "op-1")
    client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh)
    # The researcher (an operator, not SYSTEM) pauses it.
    assert (
        _signed_request(
            client,
            method="POST",
            path=f"/api/v0/experiments/{exp_id}/actions/pause",
            privkey=rp,
            pubkey_hex=rpub,
        ).status_code
        == 200
    )
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "paused"

    # The sweep must NOT resume an operator pause.
    report = settle_sweep(config, apply=True, now=datetime.now(UTC))
    assert report.resumed == []
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "paused"


# --- Auto-wrap: cap-reached auto-complete + below-cap driverless auto-abort ---
#
# A run whose driver dies/interrupts without sending the finalize signal must not
# strand in APPROVED forever. Reaching the maintainer max_units cap completes it
# (a clean quota end); falling short with the driver gone aborts it (it didn't
# meet the maintainer default). See `completion.reached_unit_cap`.


def _cap_experiment(client, mh, rp, rpub, tenant: str, exp: str, *, max_units: int, n_units: int):
    """An experiment approved with `max_units`, fed `n_units` work units. No
    finalize call. Returns (exp_id, replication_target) — the target is clamped
    to the integrity-policy floor, so the caller enrolls that many workers."""
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
    manifest_hash = r.json()["manifest_hash"]
    assert (
        client.post(
            f"/api/v0/experiments/{exp_id}/actions/approve?max_units={max_units}",
            headers=mh,
        ).status_code
        == 200
    )
    units = [
        {
            "schema_version": "0.1",
            "unit_id": f"u{i}",
            "tenant_id": tenant,
            "experiment_id": exp,
            "manifest_sha256": manifest_hash,
            "created_at": "2026-05-19T00:00:00Z",  # server re-stamps; age via _age_units
            "payload": {"input": i},
        }
        for i in range(n_units)
    ]
    r = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=rp,
        pubkey_hex=rpub,
        json_body={"work_units": units},
    )
    assert r.status_code == 201, r.text
    rt = client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["replication_target"]
    return exp_id, rt


def _complete_units(client, *, replication_target: int) -> None:
    """Complete every offered unit to its replication target: enroll one worker
    per replica and drain its queue (identical payloads → hash agreement)."""
    for _ in range(replication_target):
        wp, wpub, wid = _enroll_worker(client)
        while True:
            pick = _signed_request(
                client,
                method="GET",
                path=f"/api/v0/workers/{wid}/assignments",
                privkey=wp,
                pubkey_hex=wpub,
            ).json()
            wu = pick.get("work_unit")
            if not wu:
                break
            _submit_result(client, wid, wp, wpub, wu["unit_id"])


def _age_units(config: Config, exp_id: str, when: datetime) -> None:
    """Backdate every work unit's server-stamped created_at — the driver-idle
    signal the auto-wrap reads (units are fed by the driver, so this is when it
    last acted)."""
    pj = PerJobDatabaseFactory(config.jobs_dir).get(exp_id)
    assert pj is not None
    with pj.transaction() as cur:
        cur.execute("UPDATE work_units SET created_at = ?", (when.isoformat(),))


def test_auto_completes_at_cap_without_finalize(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    """A run that reaches its max_units cap auto-completes the moment its last unit
    lands — WITHOUT the driver ever calling finalize-submissions. This is the fix
    for the stranded-driver failure: completion no longer hangs on a live driver."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    # max_units=49 (> 2*margin) so 25 units (>= 49-24) reads as "capped".
    exp_id, rt = _cap_experiment(
        client, mh, rp, rpub, "synth-capd", "capd-1", max_units=49, n_units=25
    )
    _complete_units(client, replication_target=rt)

    # No finalize was ever sent, yet the run is COMPLETE (cap reached).
    got = client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()
    assert got["status"] == "completed", got
    assert got["submissions_finalized"] is False


def test_settle_auto_aborts_below_cap_when_driver_idle(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    """A run that fell short of its cap with the driver gone quiet is auto-aborted
    by the sweep — it didn't meet the maintainer default (operator policy (a):
    below-cap driverless → abort, not a silent partial)."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    now = datetime.now(UTC)
    exp_id, rt = _cap_experiment(
        client, mh, rp, rpub, "synth-short", "short-1", max_units=49, n_units=3
    )
    _complete_units(client, replication_target=rt)
    _age_units(config, exp_id, now - timedelta(hours=1))  # driver fed an hour ago → gone

    # Below cap → NOT auto-completed; it sits APPROVED until the sweep aborts it.
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "approved"
    report = settle_sweep(config, apply=True, now=now)
    assert exp_id in report.auto_aborted, report.summary()
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "aborted"


def test_settle_holds_below_cap_run_while_driver_active(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    """A below-cap run whose driver is merely between rounds (recent work-unit
    feed) is left alone — the idle grace prevents aborting a live run out from
    under it."""
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    rp, rpub = _ed25519()
    now = datetime.now(UTC)
    exp_id, rt = _cap_experiment(
        client, mh, rp, rpub, "synth-live", "live-1", max_units=49, n_units=3
    )
    _complete_units(client, replication_target=rt)
    _age_units(config, exp_id, now - timedelta(minutes=1))  # driver fed a minute ago → active

    report = settle_sweep(config, apply=True, now=now)
    assert exp_id not in report.auto_aborted, report.summary()
    assert client.get(f"/api/v0/experiments/{exp_id}", headers=mh).json()["status"] == "approved"
