"""Scheduler unit tests — pure-Python picking logic over fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

from auspexai_platform.db.models import Assignment, ExperimentStatus, TrustTier, Worker
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    ManifestRepository,
    WorkUnitRepository,
)
from auspexai_platform.scheduler import (
    MAX_ASSIGNMENT_ATTEMPTS,
    Scheduler,
    is_retryable_refusal,
    reoffer_eligible,
    worker_is_degraded,
    worker_is_self_paused,
    worker_satisfies,
)


def _make_experiment(
    *,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
    tenant_id: str,
    label: str,
    approved: bool = True,
    required_capabilities: dict[str, list[str]] | None = None,
):
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label},
        signature_json={},
    )
    experiment = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label=label,
        manifest_hash=manifest.manifest_hash,
        required_capabilities=required_capabilities,
    )
    if approved:
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.APPROVED)
        experiment = experiment_repository.get_by_id(experiment.experiment_id)
    return experiment


def _worker(
    *,
    worker_id: str,
    models: list[str] | None,
    tier: TrustTier = TrustTier.T2_TRUSTED,
    execute_tenant_code: str | None = "provisioned",
):
    # M9 leg 4: a model-holding worker that's meant to RUN real units declares
    # provisioned mode (the default here); pass execute_tenant_code="synthetic"/None
    # to exercise the consensus-safe exclusion.
    caps: dict = {"os": "linux"}
    if models is not None:
        caps["models"] = models
    if execute_tenant_code is not None:
        caps["execute_tenant_code"] = execute_tenant_code
    return Worker(
        worker_id=worker_id,
        pubkey_hex="a" * 64,
        trust_tier=tier,
        capabilities=caps,
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


# ---- #30 (M1) capability matching -----------------------------------------


def test_worker_satisfies_empty_requirement_is_always_true():
    assert worker_satisfies(_worker(worker_id="w", models=[]), {}) is True
    assert worker_satisfies(_worker(worker_id="w", models=None), {"models": []}) is True


def test_worker_satisfies_requires_all_models():
    assert worker_satisfies(_worker(worker_id="w", models=["m-a", "m-b"]), {"models": ["m-a"]})
    assert not worker_satisfies(_worker(worker_id="w", models=["m-a"]), {"models": ["m-a", "m-b"]})
    assert not worker_satisfies(_worker(worker_id="w", models=None), {"models": ["m-a"]})


def test_worker_satisfies_auto_acquire_matches_any_model():
    """M3 lazy auto-acquire: an auto_acquire worker satisfies a model
    requirement it doesn't yet hold (it'll pull on assignment); a worker without
    the model and without auto_acquire does not."""
    aa = Worker(
        worker_id="wkr-aa",
        pubkey_hex="a" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        # auto_acquire is only meaningful under provisioned (the daemon only
        # declares it then) — so an auto_acquire worker is provisioned.
        capabilities={"os": "linux", "auto_acquire": True, "execute_tenant_code": "provisioned"},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert worker_satisfies(aa, {"models": ["m-x"]}) is True
    # auto_acquire must be exactly True, not just any truthy junk in the dict.
    assert worker_satisfies(_worker(worker_id="w", models=["m-y"]), {"models": ["m-x"]}) is False


def test_worker_satisfies_excludes_synthetic_mode_worker():
    """M9 leg 4 (consensus-safe routing): a synthetic/off-mode worker is NOT
    eligible for a model-gated (real-execution) experiment even if it holds the
    exact model — its echo would pollute consensus. A no-requirement experiment
    is still open to it (the doubler/test-tenant path)."""
    synth = _worker(worker_id="w-synth", models=["m-x"], execute_tenant_code="synthetic")
    off = _worker(worker_id="w-off", models=["m-x"], execute_tenant_code="off")
    undeclared = _worker(worker_id="w-bare", models=["m-x"], execute_tenant_code=None)
    for w in (synth, off, undeclared):
        assert worker_satisfies(w, {"models": ["m-x"]}) is False  # excluded from real work
        assert worker_satisfies(w, {}) is True  # but still eligible for unrequired work


def test_scheduler_routes_only_to_capable_workers(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="cap-1",
        required_capabilities={"models": ["m-x"]},
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    # Worker that holds m-x is offered the unit; one that doesn't is skipped
    # (the requirement is experiment-level — pick_for_worker is read-only, so the
    # two calls are independent).
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-has", models=["m-x"])) is not None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-not", models=["m-y"])) is None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-bare", models=None)) is None


def test_scheduler_no_requirement_is_open_to_all(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # Backward-compat: an experiment with no required_capabilities behaves exactly
    # as pre-M1 — every worker (with no models declared) is eligible.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="open-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-any", models=None)) is not None


def test_scheduler_skips_paused_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # M4: a paused worker (operational pause) is offered no work.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="pause-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    paused = Worker(
        worker_id="wkr-paused",
        pubkey_hex="p" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux"},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        paused_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert scheduler.pick_for_worker(paused) is None
    # sanity: an identical but un-paused worker is offered the unit
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-live", models=None)) is not None


def test_worker_is_degraded_reads_thermal_state():
    """M5: a worker is degraded iff its heartbeat thermal snapshot is critical."""
    base = dict(
        pubkey_hex="a" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    crit = Worker(worker_id="w", capabilities={"thermal": {"state": "critical"}}, **base)
    warm = Worker(worker_id="w", capabilities={"thermal": {"state": "warm"}}, **base)
    none = Worker(worker_id="w", capabilities={"os": "linux"}, **base)
    assert worker_is_degraded(crit) is True
    assert worker_is_degraded(warm) is False  # warm still works
    assert worker_is_degraded(none) is False  # no sensor → not excluded


def test_scheduler_skips_thermal_critical_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # M5 (W-H increment 2): the coordinator routes around a degraded worker.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="therm-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    hot = Worker(
        worker_id="wkr-hot",
        pubkey_hex="h" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux", "thermal": {"state": "critical", "current_temp_c": 95.0}},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert scheduler.pick_for_worker(hot) is None
    # a cool worker (no thermal-critical) is offered the unit
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-cool", models=None)) is not None


def test_scheduler_skips_self_paused_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # §2.1 #11: a volunteer-self-paused worker is routed around (owner hold).
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="sp-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    sp = Worker(
        worker_id="wkr-sp",
        pubkey_hex="s" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux", "self_paused": True},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert worker_is_self_paused(sp) is True
    assert scheduler.pick_for_worker(sp) is None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-live", models=None)) is not None


def test_picks_pending_unit_for_eligible_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {"input": 5}}])

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"
    assert pick.experiment_id == experiment.experiment_id
    assert pick.tenant_id == experiment.tenant_id


def test_skips_units_worker_already_assigned(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    AssignmentRepository(db).create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_skips_units_at_replication_target(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """Default replication_target = 3. If 3 other workers are already
    assigned, this worker should get nothing for that unit."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    for i, other in enumerate(["wkr-other-1", "wkr-other-2", "wkr-other-3"]):
        assignments.create(
            assignment_id=f"asg-{i}",
            unit_id="u1",
            worker_id=other,
            worker_pubkey_hex=f"{chr(ord('a') + i) * 64}",
        )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_returns_none_when_no_approved_experiments(
    enrolled_worker,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_skips_unapproved_experiments(
    enrolled_worker,
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    """Submitted-but-not-approved experiment doesn't get scheduled."""
    _, worker = enrolled_worker
    _, tenant_binding = registered_tenant
    experiment = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=tenant_binding.tenant_id,
        label="submitted-label",
        approved=False,
    )
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_picks_in_progress_unit_that_still_needs_replicas(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """In-progress units (already assigned to ≥1 worker, but not yet at
    target) should still be picked for additional workers."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    WorkUnitRepository(db).mark_in_progress("u1")
    # Only ONE other worker assigned; target is 3 → 2 slots left.
    AssignmentRepository(db).create(
        assignment_id="asg-other",
        unit_id="u1",
        worker_id="wkr-other",
        worker_pubkey_hex="a" * 64,
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"


# ---- §2.1 #8 dispatch-retry: refusal classification + re-offer ------------


def _refused_assignment(*, kind: str | None, attempt_count: int = 1, result_id=None) -> Assignment:
    return Assignment(
        assignment_id="asg-x",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="a" * 64,
        assigned_at=datetime(2026, 6, 1, tzinfo=UTC),
        result_id=result_id,
        refused_at=(None if kind is None and result_id else datetime(2026, 6, 1, tzinfo=UTC)),
        refused_kind=kind,
        attempt_count=attempt_count,
    )


def test_is_retryable_refusal_classification():
    # Environmental / transient → retryable (the M0 failure classes).
    for kind in (
        "runner_failed",
        "sandbox_unavailable",
        "thermal_critical",
        "submit_failed_transient",
    ):
        assert is_retryable_refusal(kind) is True, kind
    # Policy / capability / integrity → terminal.
    for kind in (
        "refused_tenant_deny",
        "refused_tenant_allow_list_miss",
        "refused_sensitive",
        "refused_manifest_swap",
        "executor_refused",
        "submit_failed_terminal",
        "manual",
    ):
        assert is_retryable_refusal(kind) is False, kind
    # Unknown / None default to terminal (no surprise retry loops).
    assert is_retryable_refusal("something_new") is False
    assert is_retryable_refusal(None) is False


def test_reoffer_eligible_logic():
    # Retryable + under cap → re-offerable.
    assert reoffer_eligible(_refused_assignment(kind="runner_failed", attempt_count=1)) is True
    assert (
        reoffer_eligible(
            _refused_assignment(kind="runner_failed", attempt_count=MAX_ASSIGNMENT_ATTEMPTS - 1)
        )
        is True
    )
    # At the cap → not re-offerable.
    assert (
        reoffer_eligible(
            _refused_assignment(kind="runner_failed", attempt_count=MAX_ASSIGNMENT_ATTEMPTS)
        )
        is False
    )
    # Terminal kind → never re-offerable, regardless of attempts.
    assert (
        reoffer_eligible(_refused_assignment(kind="refused_tenant_deny", attempt_count=1)) is False
    )
    # A result-bearing (completed) assignment is never re-offerable.
    assert reoffer_eligible(_refused_assignment(kind=None, result_id="res-1")) is False


def test_retryable_refusal_reoffers_same_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """The M0 scenario: a worker refuses for an environmental reason
    (runner crash). On a small fleet it must remain eligible for re-offer
    rather than being permanently barred from the unit."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="sandbox boom")

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"


def test_terminal_refusal_excludes_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """A policy refusal (tenant deny) keeps the worker excluded — re-offering
    would just refuse again."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    assignments.mark_refused(
        assignment_id="asg-1", kind="refused_tenant_deny", reason="tenant denied"
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_retryable_refusal_excluded_once_attempts_exhausted(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """A retryable refusal that keeps recurring is bounded: after
    MAX_ASSIGNMENT_ATTEMPTS the worker is excluded like a terminal refusal."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    scheduler = Scheduler(experiment_repository, per_job_factory)
    # Drive attempts up to the cap: refuse → (scheduler re-offers) → reactivate.
    for _attempt in range(1, MAX_ASSIGNMENT_ATTEMPTS):
        assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="boom")
        assert scheduler.pick_for_worker(worker) is not None  # still eligible
        assignments.reactivate("asg-1")
    # Final refusal brings attempt_count to the cap → no more re-offers.
    assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="boom")
    assert assignments.get_by_id("asg-1").attempt_count == MAX_ASSIGNMENT_ATTEMPTS
    assert scheduler.pick_for_worker(worker) is None


def test_pinned_unit_offered_only_to_pinned_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """M4-tail pin / force-assign: a pinned unit is offered only to its pinned
    worker; others skip it."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    wu = WorkUnitRepository(db)
    wu.submit_batch([{"unit_id": "u1", "payload": {}}])
    scheduler = Scheduler(experiment_repository, per_job_factory)

    wu.pin("u1", "wkr-someone-else")
    assert scheduler.pick_for_worker(worker) is None  # not the pinned worker

    wu.pin("u1", worker.worker_id)  # pin to this worker
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None and pick.work_unit.unit_id == "u1"


def test_skips_experiment_with_no_per_job_db(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """An approved experiment with no work-unit submissions has no per-job
    DB — scheduler must skip it without erroring."""
    _, worker = enrolled_worker
    # Don't create a per-job DB.
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_worker_satisfies_requires_real_execution_gates_synthetic():
    """Audit 2026-06-08: a real-execution experiment with NO model requirement
    must still exclude synthetic-mode workers (an all-synthetic fleet would echo
    identically → a FALSE consensus). The experiment-level requires_real_execution
    flag gates such units to provisioned-mode workers only."""
    syn = _worker(worker_id="s", models=[], execute_tenant_code="synthetic")
    prov = _worker(worker_id="p", models=[], execute_tenant_code="provisioned")
    # No model requirement + requires_real_execution → only provisioned eligible.
    assert worker_satisfies(syn, {}, requires_real_execution=True) is False
    assert worker_satisfies(prov, {}, requires_real_execution=True) is True
    # Flag off → both eligible (pre-existing behavior, unchanged).
    assert worker_satisfies(syn, {}, requires_real_execution=False) is True
    assert worker_satisfies(prov, {}, requires_real_execution=False) is True
