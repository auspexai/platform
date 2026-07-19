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
(`worker_satisfies` over the schedulable workforce — D9 Phase 4 removed the
worker tier-floor eligibility filter) so the warning and the observability view
can never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.models import ExperimentStatus, Worker
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import ExperimentRepository, WorkUnitRepository
from auspexai_platform.db.repositories.model_serve_failures import ModelServeFailureRepository
from auspexai_platform.db.repositories.workers import WorkerRepository
from auspexai_platform.scheduler import (
    serve_fits,
    worker_is_degraded,
    worker_is_self_paused,
)
from auspexai_platform.serve_memory import fleet_reported_footprints
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


def _serve_context(
    schedulable: list[Worker], worker_repository: WorkerRepository
) -> tuple[dict[str, float], dict[str, float], set[tuple[str, str]]]:
    """(footprints, oom, recovered) — the fleet-authoritative on-disk sizes + observed-OOM
    ground truth + per-worker serve-recovery shadows that the ROUTER applies. Passing them into
    `_eligible` makes the regime capacity model use the SAME `serve_fits` verdict as routing, so
    regime-3 pause/resume can't disagree with what the scheduler will actually offer (a model
    that OOMs a worker isn't counted toward structural capacity — UNLESS that worker remediated
    and is re-eligible via `recovered`)."""
    repo = ModelServeFailureRepository(worker_repository.db)
    footprints = fleet_reported_footprints(w.capabilities for w in schedulable)
    return footprints, repo.oom_thresholds(), repo.recovery_shadows()


def _eligible(
    workforce: list[Worker],
    required: dict[str, list[str]],
    repl: int,
    *,
    requires_real_execution: bool = False,
    required_containment: str = "permissive",
    footprints: dict[str, float] | None = None,
    oom: dict[str, float] | None = None,
    recovered: set[tuple[str, str]] | None = None,
) -> list[Worker]:
    # D9 Phase 4: worker trust-tier no longer gates eligibility — a capable,
    # schedulable worker is eligible regardless of tier. `repl` is retained in
    # the signature for callers but no longer filters the worker pool. Fit is the
    # SHARED `serve_fits` verdict (footprint-backfill + worker_satisfies + observed-OOM
    # + per-worker recovery), the same one routing uses — so structural capacity ==
    # routable capacity.
    return [
        w
        for w in workforce
        if serve_fits(
            w,
            required,
            requires_real_execution=requires_real_execution,
            required_containment=required_containment,
            footprints=footprints,
            oom=oom,
            recovered=recovered,
        )
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

    fp, oom, recovered = _serve_context(before, worker_repository)
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
            before,
            required,
            repl,
            requires_real_execution=rre,
            required_containment=rc,
            footprints=fp,
            oom=oom,
            recovered=recovered,
        ) and not _eligible(
            after,
            required,
            repl,
            requires_real_execution=rre,
            required_containment=rc,
            footprints=fp,
            oom=oom,
            recovered=recovered,
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


def unit_fleet_exhausted(
    unit,
    experiment,
    *,
    worker_repository: WorkerRepository,
    assignments_repo,
    now: datetime,
) -> bool:
    """C14 regime-2: True when no further replica can arrive for this unit from the current
    fleet — every SCHEDULABLE worker eligible for it has already delivered a result or
    terminally refused, so none is still available to take it and none is mid-execution with a
    pending result. Reuses the M9 capacity eligibility (`worker_satisfies`; D9 Phase 4 dropped the worker tier-floor) so
    the two never disagree. An OFFLINE worker's stale in-flight assignment does NOT block (it
    isn't schedulable); a transiently-offline worker is covered by the sweep's quiescence window.
    Vacuously True when no eligible worker exists at all (nothing can contribute)."""
    schedulable = _schedulable_workforce(worker_repository.list_all(), now=now)
    fp, oom, recovered = _serve_context(schedulable, worker_repository)
    eligible = _eligible(
        schedulable,
        experiment.required_capabilities or {},
        unit.replication_target,
        requires_real_execution=experiment.requires_real_execution,
        required_containment=experiment.required_containment,
        footprints=fp,
        oom=oom,
        recovered=recovered,
    )
    done = {
        a.worker_id
        for a in assignments_repo.list_for_unit(unit.unit_id)
        if a.result_id is not None or a.refused_at is not None
    }
    return all(w.worker_id in done for w in eligible)


def unit_max_achievable_replication(
    unit,
    experiment,
    *,
    worker_repository: WorkerRepository,
    assignments_repo,
    now: datetime,
) -> int:
    """C14 regime-3: the most replicas this unit could still reach from the CURRENT schedulable
    fleet — its delivered results plus every schedulable eligible worker that hasn't yet
    delivered or terminally refused. Below the floor it can never be corroborated with today's
    fleet (→ pause); when it recovers to >= floor the experiment can resume. Same eligibility
    basis as `unit_fleet_exhausted` so the pause and resume sides never disagree."""
    schedulable = _schedulable_workforce(worker_repository.list_all(), now=now)
    fp, oom, recovered = _serve_context(schedulable, worker_repository)
    eligible = _eligible(
        schedulable,
        experiment.required_capabilities or {},
        unit.replication_target,
        requires_real_execution=experiment.requires_real_execution,
        required_containment=experiment.required_containment,
        footprints=fp,
        oom=oom,
        recovered=recovered,
    )
    done = {
        a.worker_id
        for a in assignments_repo.list_for_unit(unit.unit_id)
        if a.result_id is not None or a.refused_at is not None
    }
    uncontributed = sum(1 for w in eligible if w.worker_id not in done)
    return unit.completions_so_far + uncontributed


def eligible_capable_count(
    experiment,
    *,
    worker_repository: WorkerRepository,
    now: datetime,
) -> int:
    """The number of SCHEDULABLE workers eligible to serve this experiment AT ALL — the
    fleet's structural ceiling on any unit's replication. When it is below the
    experiment's replication_floor, a below-floor regime-3 pause is STRUCTURAL: no worker
    returning can lift it (there simply aren't enough workers that can serve the model),
    so the pause will never auto-resume — as opposed to a transient dip a logged-out
    worker returning would fix. Same eligibility basis as `unit_fleet_exhausted`."""
    schedulable = _schedulable_workforce(worker_repository.list_all(), now=now)
    fp, oom, recovered = _serve_context(schedulable, worker_repository)
    eligible = _eligible(
        schedulable,
        experiment.required_capabilities or {},
        # A not-yet-approved experiment may have no replication_target yet; the
        # eligibility count is about model/containment capability, so 1 is a safe
        # stand-in for "how many workers could serve this at all".
        getattr(experiment, "replication_target", None) or 1,
        requires_real_execution=experiment.requires_real_execution,
        required_containment=experiment.required_containment,
        footprints=fp,
        oom=oom,
        recovered=recovered,
    )
    return len(eligible)
