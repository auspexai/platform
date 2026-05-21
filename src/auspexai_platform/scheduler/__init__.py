"""Scheduler — picks the next work unit for a worker on demand (M6d).

Pull model: workers call `GET /workers/{id}/assignments` after each
heartbeat; the scheduler returns at most one assignment per call (one
unit at a time per worker for v0). No background loops, no push, no
SSE — those are M8 concerns.

Algorithm: **first-fit-with-capability filtering**. Walk approved
experiments in registration order; for each, walk pending + in_progress
work units in creation order; pick the first one this worker is
eligible for and not already assigned to.

Eligibility (v0):
  - Worker not retired (filtered upstream by CredentialResolver)
  - Worker hasn't already been assigned this unit
  - Unit's total assignment count < unit.replication_target
    (no over-assignment beyond the quorum target)

**Capability matching is deferred to M6d-polish or M7.** Per §5.8 the
scheduler should match worker capabilities (OS, GPU, locally-installed
models) to work-unit requirements. v0 ignores this — every worker is
eligible for every unit. The infrastructure (`Worker.capabilities` dict)
is in place; the matching logic is left for when there's a concrete
tenant whose units carry capability requirements.

**Tier-driven replication adjustment is deferred** similarly. Per §6.1
T0 workers need N≥3 replicas, T1 N=2, T2+ N=1 — but v0 uses the unit's
static `replication_target` (default 3) without dynamic per-assignment
adjustment. Effect: when a T2+ worker handles a T0-default unit, we
over-replicate by 2 replicas. Suboptimal, not incorrect.
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.models import ExperimentStatus, Worker, WorkUnit
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    WorkUnitRepository,
)


@dataclass(frozen=True)
class SchedulerPick:
    """Result of `Scheduler.pick_for_worker`. The route layer turns this
    into an Assignment + the wire-format work-unit envelope."""

    experiment_id: str
    tenant_id: str
    tenant_experiment_label: str
    manifest_hash: str
    work_unit: WorkUnit


class Scheduler:
    def __init__(
        self,
        experiment_repository: ExperimentRepository,
        per_job_factory: PerJobDatabaseFactory,
    ):
        self._experiments = experiment_repository
        self._per_job_factory = per_job_factory

    def pick_for_worker(self, worker: Worker) -> SchedulerPick | None:
        """Return the first eligible (experiment_id, work_unit) pair, or
        None if no work is available for this worker."""
        # Approved experiments only — paused/aborted/completed/archived
        # are not assignable. Paused stops new assignments but accepts
        # in-flight results (M6e); the gating happens here at scheduler
        # entry, not at result-submission.
        for experiment in self._experiments.list_all(status=ExperimentStatus.APPROVED):
            per_job_db = self._per_job_factory.get(experiment.experiment_id)
            if per_job_db is None:
                continue
            work_units = WorkUnitRepository(per_job_db)
            assignments = AssignmentRepository(per_job_db)

            # Pending units first, then in_progress (units that still need more
            # replicas). list_all returns in created-at order.
            candidates: list[WorkUnit] = []
            from auspexai_platform.db.models import WorkUnitStatus

            candidates.extend(work_units.list_all(status=WorkUnitStatus.PENDING))
            candidates.extend(work_units.list_all(status=WorkUnitStatus.IN_PROGRESS))

            for unit in candidates:
                if assignments.already_assigned(unit.unit_id, worker.worker_id):
                    continue
                # Refused assignments don't consume a replication slot — the
                # offer was burned but no progress was made. Use the active
                # count so refused-then-reschedule actually frees the unit
                # for another worker. Per M3 Q-W4 resolution.
                if assignments.count_active_for_unit(unit.unit_id) >= unit.replication_target:
                    continue
                return SchedulerPick(
                    experiment_id=experiment.experiment_id,
                    tenant_id=experiment.tenant_id,
                    tenant_experiment_label=experiment.tenant_experiment_label,
                    manifest_hash=experiment.manifest_hash,
                    work_unit=unit,
                )
        return None
