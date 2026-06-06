"""Scheduler — picks the next work unit for a worker on demand (M6d).

Pull model: workers call `GET /workers/{id}/assignments` after each
heartbeat; the scheduler returns at most one assignment per call (one
unit at a time per worker for v0). No background loops, no push, no
SSE — those are M8 concerns.

Algorithm: **first-fit-with-capability filtering**. Walk approved
experiments in registration order; for each, walk pending + in_progress
work units in creation order; pick the first one this worker is
eligible for and not already assigned to.

Eligibility:
  - Worker not retired (filtered upstream by CredentialResolver)
  - Worker hasn't already been assigned this unit
  - Unit's total assignment count < unit.replication_target
    (no over-assignment beyond the quorum target)
  - **Per-tier replication floor (ratified 2026-05-24)**: workers are
    only eligible for units whose replication_target meets or exceeds
    their tier floor. T0 requires N≥3, T1 N≥2, T2+ N≥1. A T0 worker
    is skipped for units with replication_target < 3.

**Capability matching (#30, M1):** per §5.8 the scheduler matches a worker's
locally-held models against the experiment's `required_capabilities` (derived at
submit from the manifest's `local_weights_required` models, keyed by store
model_id). A worker is skipped for an experiment whose required models it
doesn't hold (`worker_satisfies`). An experiment with no requirement is open to
every worker (the pre-M1 behavior). Broader capability dimensions (OS/GPU) and
the full heterogeneous-pool routing remain Phase-2; M1 ships the model-inventory
thin slice that makes BYOM routing real.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from auspexai_platform.db.models import ExperimentStatus, TrustTier, Worker, WorkUnit
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    WorkUnitRepository,
)

_TIER_REPLICATION_FLOOR = {
    TrustTier.T0_ANONYMOUS: 3,
    TrustTier.T1_AUTHENTICATED: 2,
    TrustTier.T2_TRUSTED: 1,
    TrustTier.T3_VETTED: 1,
}


def replication_floor_for_tier(tier: TrustTier) -> int:
    return _TIER_REPLICATION_FLOOR.get(tier, 3)


class SkipReason(StrEnum):
    """Why the scheduler passed over a unit/experiment for a given worker. The
    shared vocabulary the M4 scheduler-ops console surfaces as 'why a unit isn't
    being assigned'. (M1 introduces it + uses MISSING_CAPABILITY; M4 wires the
    per-unit reasons into the observability endpoint.)"""

    BELOW_TIER_FLOOR = "below_tier_floor"
    ALREADY_ASSIGNED = "already_assigned"
    AT_REPLICATION = "at_replication"
    MISSING_CAPABILITY = "missing_capability"


def worker_satisfies(worker: Worker, required_capabilities: dict[str, list[str]]) -> bool:
    """True if the worker locally holds every model the experiment requires
    (#30, M1). `required_capabilities` is keyed by dimension; Phase-1 matches the
    "models" key against the worker's declared `capabilities["models"]` inventory
    by EXACT store model_id (hash-agreement consensus needs identical quants).
    Empty requirement ⇒ always satisfied (the pre-M1 behavior — every worker
    eligible). Unknown capability dimensions are ignored in Phase-1."""
    required_models = set(required_capabilities.get("models", []))
    if not required_models:
        return True
    have = worker.capabilities.get("models", [])
    have_models = set(have) if isinstance(have, list) else set()
    return required_models <= have_models


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
        tier_floor = replication_floor_for_tier(worker.trust_tier)

        for experiment in self._experiments.list_all(status=ExperimentStatus.APPROVED):
            # #30 (M1): skip the whole experiment when this worker lacks a model
            # it requires (the requirement is experiment-level, derived from the
            # manifest at submit). Empty requirement ⇒ satisfied (pre-M1 behavior).
            if not worker_satisfies(worker, experiment.required_capabilities):
                continue
            per_job_db = self._per_job_factory.get(experiment.experiment_id)
            if per_job_db is None:
                continue
            work_units = WorkUnitRepository(per_job_db)
            assignments = AssignmentRepository(per_job_db)

            if experiment.max_concurrent_assignments is not None:
                total_active = assignments.count_active_for_experiment()
                if total_active >= experiment.max_concurrent_assignments:
                    continue

            from auspexai_platform.db.models import WorkUnitStatus

            candidates: list[WorkUnit] = []
            candidates.extend(work_units.list_all(status=WorkUnitStatus.PENDING))
            candidates.extend(work_units.list_all(status=WorkUnitStatus.IN_PROGRESS))

            for unit in candidates:
                if unit.replication_target < tier_floor:
                    continue
                if assignments.already_assigned(unit.unit_id, worker.worker_id):
                    continue
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
