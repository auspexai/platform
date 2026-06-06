"""Scheduler unit tests — pure-Python picking logic over fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

from auspexai_platform.db.models import ExperimentStatus, TrustTier, Worker
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    ManifestRepository,
    WorkUnitRepository,
)
from auspexai_platform.scheduler import Scheduler, worker_satisfies


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


def _worker(*, worker_id: str, models: list[str] | None, tier: TrustTier = TrustTier.T2_TRUSTED):
    caps: dict = {"os": "linux"}
    if models is not None:
        caps["models"] = models
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
