"""M4 — scheduler view: GET /scheduler/state (blocked/starved triage + worker
eligibility), the pause/unpause lever, and the set-integrity-policy override."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.db.models import ExperimentStatus, IntegrityPolicy
from auspexai_platform.db.repositories.work_units import WorkUnitRepository


def _mtnr(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


def _approved_exp(
    manifest_repository,
    experiment_repository,
    per_job_factory,
    *,
    tenant_id: str,
    label: str,
    required: dict | None = None,
    integrity: IntegrityPolicy | None = None,
    n_units: int = 1,
):
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label},
        signature_json={},
    )
    exp = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label=label,
        manifest_hash=manifest.manifest_hash,
        required_capabilities=required,
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    if integrity is not None:
        experiment_repository.set_integrity_policy(exp.experiment_id, integrity)
    if n_units:
        db = per_job_factory.get_or_create(exp.experiment_id)
        WorkUnitRepository(db).submit_batch(
            [{"unit_id": f"u{i}", "payload": {}} for i in range(n_units)]
        )
    return experiment_repository.get_by_id(exp.experiment_id)


def _active_worker(worker_repository, *, worker_id: str, pubkey: str, models: list[str]):
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=pubkey)
    worker_repository.record_heartbeat(worker_id, capabilities={"os": "linux", "models": models})


def _exp_state(body: dict, experiment_id: str) -> dict:
    return next(e for e in body["experiments"] if e["experiment_id"] == experiment_id)


# ---- GET /scheduler/state --------------------------------------------------


def test_scheduler_state_maintainer_only(client: TestClient) -> None:
    assert client.get("/api/v0/scheduler/state").status_code in (401, 403)


def test_blocked_missing_capability(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
) -> None:
    _, binding = registered_tenant
    _active_worker(worker_repository, worker_id="w-other", pubkey="1" * 64, models=["m-other"])
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="needs-mx",
        required={"models": ["m-x"]},
    )
    r = client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token))
    assert r.status_code == 200, r.text
    e = _exp_state(r.json(), exp.experiment_id)
    assert e["blocked"] is True
    assert e["block_reason"] == "missing_capability"
    assert e["capable_worker_count"] == 0
    # the worker is shown, idle (eligible for nothing)
    w = next(x for x in r.json()["workers"] if x["worker_id"] == "w-other")
    assert w["eligible_experiment_count"] == 0


def test_not_blocked_when_capable_and_tier_eligible(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
) -> None:
    _, binding = registered_tenant
    # T0 worker holds m-x; STANDARD (repl 3) → T0 floor 3 ≤ 3 → eligible.
    _active_worker(worker_repository, worker_id="w-cap", pubkey="2" * 64, models=["m-x"])
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="ok-mx",
        required={"models": ["m-x"]},
    )
    body = client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json()
    e = _exp_state(body, exp.experiment_id)
    assert e["blocked"] is False
    assert e["eligible_worker_count"] == 1
    w = next(x for x in body["workers"] if x["worker_id"] == "w-cap")
    assert w["eligible_experiment_count"] == 1


def test_blocked_below_tier_floor(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
) -> None:
    _, binding = registered_tenant
    # T0 worker holds m-x, but TRUSTED (repl 1) needs T2+ → capable, not eligible.
    _active_worker(worker_repository, worker_id="w-t0", pubkey="3" * 64, models=["m-x"])
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="trusted-mx",
        required={"models": ["m-x"]},
        integrity=IntegrityPolicy.TRUSTED,
    )
    e = _exp_state(
        client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json(),
        exp.experiment_id,
    )
    assert e["blocked"] is True
    assert e["block_reason"] == "below_tier_floor"
    assert e["capable_worker_count"] == 1  # capable but not tier-eligible
    assert e["eligible_worker_count"] == 0


def test_blocked_empty_pool(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
) -> None:
    _, binding = registered_tenant
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="no-workers",
    )
    e = _exp_state(
        client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json(),
        exp.experiment_id,
    )
    assert e["blocked"] is True
    assert e["block_reason"] == "empty_pool"


def test_paused_worker_excluded_from_workforce(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
) -> None:
    _, binding = registered_tenant
    # The only capable worker is paused → experiment is blocked (missing_capability),
    # and the worker is shown flagged paused.
    _active_worker(worker_repository, worker_id="w-paused", pubkey="4" * 64, models=["m-x"])
    worker_repository.pause("w-paused")
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="paused-cap",
        required={"models": ["m-x"]},
    )
    body = client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json()
    e = _exp_state(body, exp.experiment_id)
    assert e["blocked"] is True
    assert e["capable_worker_count"] == 0  # paused worker not counted
    assert body["active_worker_count"] == 0
    w = next(x for x in body["workers"] if x["worker_id"] == "w-paused")
    assert w["paused"] is True


def test_degraded_worker_excluded_and_flagged(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
) -> None:
    # M5: a thermal-critical worker is routed around — excluded from the
    # workforce (so the experiment is blocked) and flagged `degraded` on /scheduler.
    _, binding = registered_tenant
    worker_repository.enroll(worker_id="w-hot", pubkey_hex="7" * 64)
    worker_repository.record_heartbeat(
        "w-hot",
        capabilities={"os": "linux", "models": ["m-x"], "thermal": {"state": "critical"}},
    )
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="hot-cap",
        required={"models": ["m-x"]},
    )
    body = client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json()
    e = _exp_state(body, exp.experiment_id)
    assert e["blocked"] is True
    assert e["capable_worker_count"] == 0  # degraded worker not counted
    assert body["active_worker_count"] == 0
    w = next(x for x in body["workers"] if x["worker_id"] == "w-hot")
    assert w["degraded"] is True


def test_stalled_unit_surfaced(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
):
    """§2.1 #8-tail: an in-progress unit whose only assignment is a terminal
    refusal shows up as stalled (stranded — no active, none re-offerable)."""
    from auspexai_platform.db.repositories import AssignmentRepository, WorkUnitRepository

    _, binding = registered_tenant
    exp = _approved_exp(
        manifest_repository, experiment_repository, per_job_factory,
        tenant_id=binding.tenant_id, label="stall", n_units=1,
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).mark_in_progress("u0")
    ar = AssignmentRepository(db)
    ar.create(assignment_id="asg-1", unit_id="u0", worker_id="wkr-x", worker_pubkey_hex="a" * 64)
    ar.mark_refused(assignment_id="asg-1", kind="refused_tenant_deny", reason="terminal")

    body = client.get("/api/v0/scheduler/state", headers=_mtnr(maintainer_token)).json()
    assert _exp_state(body, exp.experiment_id)["stalled_units"] == 1


def test_pin_unit_endpoint(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
):
    """M4-tail: pin force-assigns a unit to a worker (sets pinned_worker_id);
    reason is mandatory."""
    from auspexai_platform.db.repositories import WorkUnitRepository

    _, binding = registered_tenant
    worker_repository.enroll(worker_id="wkr-pin", pubkey_hex="9" * 64)
    exp = _approved_exp(
        manifest_repository, experiment_repository, per_job_factory,
        tenant_id=binding.tenant_id, label="pin", n_units=1,
    )
    no_reason = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/units/u0/actions/pin",
        json={"worker_id": "wkr-pin", "reason": ""},
        headers=_mtnr(maintainer_token),
    )
    assert no_reason.status_code == 422
    ok = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/units/u0/actions/pin",
        json={"worker_id": "wkr-pin", "reason": "repro a failure"},
        headers=_mtnr(maintainer_token),
    )
    assert ok.status_code == 200, ok.text
    db = per_job_factory.get(exp.experiment_id)
    assert WorkUnitRepository(db).get_by_unit_id("u0").pinned_worker_id == "wkr-pin"


def test_trigger_prestage_endpoint(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    worker_repository,
    db,
):
    """M4-tail: trigger-prestage creates prestage rows for an eligible
    auto-acquire worker that lacks a required (coords-bearing) model."""
    from auspexai_platform.db.repositories import ModelPrestageRepository

    _, binding = registered_tenant
    worker_repository.enroll(worker_id="wkr-aa", pubkey_hex="b" * 64)
    worker_repository.record_heartbeat("wkr-aa", capabilities={"os": "linux", "auto_acquire": True})
    manifest = manifest_repository.insert(
        tenant_id=binding.tenant_id,
        manifest_json={
            "tenant_id": binding.tenant_id,
            "experiment_id": "tp",
            "models": [
                {
                    "id": "m-x",
                    "version": "1",
                    "local_weights_required": True,
                    "hf_repo": "Org/M-GGUF",
                    "hf_filename": "M-Q4.gguf",
                }
            ],
        },
        signature_json={},
    )
    exp = experiment_repository.create(
        tenant_id=binding.tenant_id,
        tenant_experiment_label="tp",
        manifest_hash=manifest.manifest_hash,
        required_capabilities={"models": ["m-x"]},
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)

    r = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/actions/trigger-prestage",
        json={"reason": "warm the fleet"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["rows_created"] == 1
    assert ModelPrestageRepository(db).count_open_for_model("m-x") == 1


# ---- pause / unpause + set-integrity-policy --------------------------------


def test_pause_and_unpause_worker(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    worker_repository.enroll(worker_id="w-p", pubkey_hex="5" * 64)
    r = client.post(
        "/api/v0/workers/w-p/actions/pause",
        json={"reason": "host maintenance"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["paused_at"] is not None
    r2 = client.post("/api/v0/workers/w-p/actions/unpause", headers=_mtnr(maintainer_token))
    assert r2.status_code == 200, r2.text
    assert r2.json().get("paused_at") is None


def test_pause_requires_reason(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    worker_repository.enroll(worker_id="w-nr", pubkey_hex="6" * 64)
    r = client.post("/api/v0/workers/w-nr/actions/pause", json={}, headers=_mtnr(maintainer_token))
    assert r.status_code == 422


def test_set_integrity_policy(
    client: TestClient,
    maintainer_token: str,
    registered_tenant,
    manifest_repository,
    experiment_repository,
    per_job_factory,
) -> None:
    _, binding = registered_tenant
    exp = _approved_exp(
        manifest_repository,
        experiment_repository,
        per_job_factory,
        tenant_id=binding.tenant_id,
        label="setpol",
        n_units=0,
    )
    r = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/actions/set-integrity-policy",
        json={"integrity_policy": "trusted", "reason": "single-replica trusted run"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["integrity_policy"] == "trusted"
    # invalid policy → 422
    bad = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/actions/set-integrity-policy",
        json={"integrity_policy": "bogus", "reason": "x"},
        headers=_mtnr(maintainer_token),
    )
    assert bad.status_code == 422
