"""Capacity-collapse detection (M9 leg 1).

A no-fault hold (operator pause, worker self-pause, thermal-degraded) removes a
worker from the schedulable pool. Individually that's correct; in aggregate it can
drop an *active* experiment below the point where any eligible worker remains, and
the experiment silently stops progressing (M4 `blocked`/`empty_pool`; §2.1 #8-tail
`stalled_units`). M9's policy is **warn-but-allow**: the pause still happens (the
volunteer/operator's call is final), but if it would collapse an experiment's
eligible pool to zero we surface that to the operator + record it in the audit so
the stall isn't a silent surprise.

This module is the read-only substrate: given the worker about to leave the pool,
which APPROVED, needs-work experiments would lose their *last* eligible worker. It
reuses the exact eligibility logic the M4 `/scheduler/state` view uses
(`worker_satisfies` + `replication_floor_for_tier` + `INTEGRITY_POLICY_REPLICATION`)
so the warning and the observability view can never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.models import ExperimentStatus, Worker
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import ExperimentRepository, WorkUnitRepository
from auspexai_platform.db.repositories.workers import WorkerRepository
from auspexai_platform.scheduler import (
    replication_floor_for_tier,
    worker_is_degraded,
    worker_is_self_paused,
    worker_satisfies,
)
from auspexai_platform.worker_status import heartbeat_cutoff


@dataclass(frozen=True)
class BlockedExperiment:
    """An experiment whose eligible-worker pool collapses to zero if a given
    worker leaves the schedulable set."""

    experiment_id: str
    tenant_id: str
    tenant_experiment_label: str | None
    needs_work: int  # pending + in_progress units still wanting replicas


def _schedulable_workforce(
    workers: list[Worker], *, now: datetime, excluding: str | None = None
) -> list[Worker]:
    """The workers the scheduler can actually hand work to: heartbeating, not
    retired/quarantined, and not under any no-fault hold (operator pause /
    thermal-degraded / volunteer self-pause). `excluding` drops one worker_id
    (the one about to be paused) so the caller can compare before/after."""
    cutoff = heartbeat_cutoff(now)
    out: list[Worker] = []
    for w in workers:
        if excluding is not None and w.worker_id == excluding:
            continue
        if w.retired_at is not None or w.quarantined_at is not None:
            continue
        if w.last_heartbeat_at is None or w.last_heartbeat_at < cutoff:
            continue
        if w.paused_at is not None or worker_is_degraded(w) or worker_is_self_paused(w):
            continue
        out.append(w)
    return out


def _eligible(
    workforce: list[Worker],
    required: dict[str, list[str]],
    repl: int,
    *,
    requires_real_execution: bool = False,
    required_containment: str = "permissive",
) -> list[Worker]:
    return [
        w
        for w in workforce
        if worker_satisfies(
            w,
            required,
            requires_real_execution=requires_real_execution,
            required_containment=required_containment,
        )
        and replication_floor_for_tier(w.trust_tier) <= repl
    ]


def experiments_collapsed_by_removing(
    worker_id: str,
    *,
    worker_repository: WorkerRepository,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    now: datetime,
) -> list[BlockedExperiment]:
    """Active (APPROVED, needs-work) experiments whose eligible-worker pool is
    non-empty now but becomes **empty** once `worker_id` leaves the schedulable
    set — i.e. this pause is the cause of the collapse. Experiments already
    blocked (eligible pool already empty) are *not* reported: this pause didn't
    break them. Warn-but-allow substrate; never mutates state.
    """
    all_workers = worker_repository.list_all()
    before = _schedulable_workforce(all_workers, now=now)
    after = _schedulable_workforce(all_workers, now=now, excluding=worker_id)
    # If removing the worker changes nothing (it wasn't schedulable anyway), no
    # collapse is possible — short-circuit.
    if len(after) == len(before):
        return []

    collapsed: list[BlockedExperiment] = []
    for exp in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
        pj = per_job_factory.get(exp.experiment_id)
        counts = WorkUnitRepository(pj).count_by_status() if pj is not None else {}
        needs_work = counts.get("pending", 0) + counts.get("in_progress", 0)
        if needs_work <= 0:
            continue
        repl = exp.replication_target  # C14: source of truth (decoupled from the policy map)
        required = exp.required_capabilities or {}
        rre = exp.requires_real_execution
        rc = exp.required_containment
        if _eligible(
            before, required, repl, requires_real_execution=rre, required_containment=rc
        ) and not _eligible(
            after, required, repl, requires_real_execution=rre, required_containment=rc
        ):
            collapsed.append(
                BlockedExperiment(
                    experiment_id=exp.experiment_id,
                    tenant_id=exp.tenant_id,
                    tenant_experiment_label=exp.tenant_experiment_label,
                    needs_work=needs_work,
                )
            )
    return collapsed
