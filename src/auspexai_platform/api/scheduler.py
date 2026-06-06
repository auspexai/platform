"""Scheduler view — the cross-cutting matching layer (M4, §3c).

`GET /api/v0/scheduler/state` (maintainer) is the read side of the operator
`/scheduler` page: the supply/demand/*why* matching rollup that no per-experiment or
per-worker page shows. Pure read over existing data (no schema):

- `experiments`: per approved experiment with outstanding work — pending/in-progress
  counts, its model requirement, and whether it's **blocked** (units that can't
  land on any worker) with the M1 `SkipReason` (`empty_pool` / `missing_capability`
  / `below_tier_floor`).
- `workers`: per on-network worker — tier, model count, paused flag, and how many
  experiments it's eligible for (`eligible_experiment_count == 0` is the cheap
  "why idle" signal — can't help anything currently queued).

The catalog section reuses `GET /models/catalog`; the new-requirement queue is the
already-built demand-board. Paused workers are shown (flagged) but excluded from
the eligible workforce.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential
from auspexai_platform.db.models import INTEGRITY_POLICY_REPLICATION, ExperimentStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    ExperimentRepository,
    WorkerRepository,
    WorkUnitRepository,
)
from auspexai_platform.scheduler import (
    replication_floor_for_tier,
    worker_is_degraded,
    worker_satisfies,
)
from auspexai_platform.worker_status import heartbeat_cutoff


class SchedulerExperiment(BaseModel):
    experiment_id: str
    tenant_id: str
    tenant_experiment_label: str
    pending: int
    in_progress: int
    completed: int
    required_capabilities: dict[str, list[str]]
    capable_worker_count: int  # active workers that hold the required model(s)
    eligible_worker_count: int  # capable AND tier-eligible for the unit replication target
    blocked: bool
    block_reason: str | None = None  # empty_pool | missing_capability | below_tier_floor


class SchedulerWorker(BaseModel):
    worker_id: str
    trust_tier: int
    model_count: int
    paused: bool
    degraded: bool = False  # M5: heartbeat thermal state == critical (routed around)
    eligible_experiment_count: int  # approved experiments w/ outstanding work this worker can take


class SchedulerStateResponse(BaseModel):
    experiments: list[SchedulerExperiment]
    workers: list[SchedulerWorker]
    active_worker_count: int  # on-network, available for work (excludes paused + degraded)


def _model_count(worker) -> int:
    m = worker.capabilities.get("models")
    return len(m) if isinstance(m, list) else 0


def build_router(
    credential_dep,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    worker_repository: WorkerRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get(
        "/scheduler/state",
        response_model=SchedulerStateResponse,
        status_code=status.HTTP_200_OK,
    )
    async def scheduler_state(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SchedulerStateResponse:
        if not credential.is_maintainer():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")
        cutoff = heartbeat_cutoff(datetime.now(UTC))

        all_workers = worker_repository.list_all()
        # On the network = heartbeating + not retired/quarantined (those live on the
        # Workers page). Paused workers are shown here (flagged) but excluded from
        # the workforce the scheduler can actually use.
        on_network = [
            w
            for w in all_workers
            if w.retired_at is None
            and w.quarantined_at is None
            and w.last_heartbeat_at is not None
            and w.last_heartbeat_at >= cutoff
        ]
        # M5: a degraded (thermal-critical) worker is routed around, like paused —
        # exclude it from the available workforce so eligibility counts are honest.
        workforce = [w for w in on_network if w.paused_at is None and not worker_is_degraded(w)]

        elig_count: dict[str, int] = {w.worker_id: 0 for w in workforce}
        experiments_out: list[SchedulerExperiment] = []
        for exp in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
            pj = per_job_factory.get(exp.experiment_id)
            counts = WorkUnitRepository(pj).count_by_status() if pj is not None else {}
            pending = counts.get("pending", 0)
            in_progress = counts.get("in_progress", 0)
            completed = counts.get("completed", 0)
            needs_work = pending + in_progress  # in-progress units may still need replicas
            repl = INTEGRITY_POLICY_REPLICATION.get(exp.integrity_policy, 3)
            required = exp.required_capabilities or {}
            capable = [w for w in workforce if worker_satisfies(w, required)]
            eligible = [w for w in capable if replication_floor_for_tier(w.trust_tier) <= repl]
            if needs_work > 0:
                for w in eligible:
                    elig_count[w.worker_id] += 1
            blocked = needs_work > 0 and not eligible
            reason = None
            if blocked:
                if not workforce:
                    reason = "empty_pool"
                elif not capable:
                    reason = "missing_capability"
                else:
                    reason = "below_tier_floor"
            experiments_out.append(
                SchedulerExperiment(
                    experiment_id=exp.experiment_id,
                    tenant_id=exp.tenant_id,
                    tenant_experiment_label=exp.tenant_experiment_label,
                    pending=pending,
                    in_progress=in_progress,
                    completed=completed,
                    required_capabilities=required,
                    capable_worker_count=len(capable),
                    eligible_worker_count=len(eligible),
                    blocked=blocked,
                    block_reason=reason,
                )
            )

        workers_out = [
            SchedulerWorker(
                worker_id=w.worker_id,
                trust_tier=int(w.trust_tier),
                model_count=_model_count(w),
                paused=w.paused_at is not None,
                degraded=worker_is_degraded(w),
                eligible_experiment_count=elig_count.get(w.worker_id, 0),
            )
            for w in on_network
        ]

        return SchedulerStateResponse(
            experiments=experiments_out,
            workers=workers_out,
            active_worker_count=len(workforce),
        )

    return router
