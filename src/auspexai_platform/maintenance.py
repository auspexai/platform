"""Age-off sweep — the platform's first retention mechanism (M-Results).

Result payloads accumulate permanently in per-job DBs; this sweep blanks the
heavy `payload_json` once a result is past its retention horizon, while keeping
the row + signature + semantic_hash + receipt linkage intact (provability is
decoupled from the bytes). It is **dry-run by default** — `apply=False` reports
what *would* age off without mutating; the operator reviews, can place a
retention hold, then re-runs with `apply=True`. Run via the `auspexai-coordinator
age-off` CLI (e.g. a systemd timer).

Retention precedence per result (see `results_delivery_design.md`):
  - experiment under **retention_hold** → keep everything (audit/legal).
  - **T-C consensus**: kept (experiment-lifetime) unless a `consensus_ttl_days`
    override is set AND the results have been collected → `collected_at + ttl`.
  - **T-X replica**: collected/delivered → `+ raw_ttl` (default 30d); never
    delivered → `completed_at + grace` (default 14d).
  - receipts (T-R) are never touched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from auspexai_platform.config import Config
from auspexai_platform.db.database import Database
from auspexai_platform.db.models import (
    CredentialClass,
    Experiment,
    ExperimentStatus,
    Result,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AuditRepository,
    ExperimentRepository,
    ResultRepository,
)
from auspexai_platform.worker_status import STALE_HEARTBEAT_MINUTES

DEFAULT_RAW_TTL_DAYS = 30
DEFAULT_GRACE_DAYS = 14


def projected_raw_age_off(experiment: Experiment) -> datetime | None:
    """When the sweep will start aging off this experiment's raw (T-X) payloads,
    or `None` if there is no experiment-level projection yet.

    Collection is the anchor: until the researcher collects the export bundle
    (`results_collected_at` is set) each result ages on its own per-result clock
    (`delivered_at + raw_ttl`, or `completed_at + grace` if never delivered), so
    there is no single experiment-wide date to project. Once collected, every
    raw payload ages at `results_collected_at + raw_ttl` — matching the collected
    branch of `_horizon_for` exactly (no extra grace; grace is only the
    never-collected fallback). Single source of truth for the O-M8 operator
    projection so the console never re-derives retention math.
    """
    if experiment.results_collected_at is None:
        return None
    raw_ttl = experiment.raw_payload_ttl_days or DEFAULT_RAW_TTL_DAYS
    return experiment.results_collected_at + timedelta(days=raw_ttl)


@dataclass
class ExperimentSweep:
    experiment_id: str
    held: bool
    ageable_result_ids: list[str] = field(default_factory=list)
    bytes_freed: int = 0


@dataclass
class SweepReport:
    applied: bool
    now: str
    experiments: list[ExperimentSweep] = field(default_factory=list)

    @property
    def total_aged(self) -> int:
        return sum(len(e.ageable_result_ids) for e in self.experiments)

    @property
    def total_bytes(self) -> int:
        return sum(e.bytes_freed for e in self.experiments)

    @property
    def held_count(self) -> int:
        return sum(1 for e in self.experiments if e.held)

    def summary(self) -> str:
        verb = "aged off" if self.applied else "would age off"
        lines = [
            f"age-off sweep @ {self.now} ({'APPLIED' if self.applied else 'DRY-RUN'})",
            f"  {verb} {self.total_aged} result payload(s), ~{self.total_bytes} bytes, "
            f"across {len(self.experiments)} experiment(s); {self.held_count} on hold (skipped)",
        ]
        for e in self.experiments:
            if e.held:
                lines.append(f"  - {e.experiment_id}: HELD (retention hold) — skipped")
            elif e.ageable_result_ids:
                lines.append(
                    f"  - {e.experiment_id}: {len(e.ageable_result_ids)} payload(s), "
                    f"~{e.bytes_freed} bytes"
                )
        return "\n".join(lines)


def _horizon_for(
    result: Result, experiment: Experiment, *, raw_ttl_days: int, grace_days: int
) -> datetime | None:
    """The age-off deadline for a result's payload, or None if it should be KEPT."""
    if result.is_consensus:
        # T-C: kept (experiment-lifetime) unless an override TTL is set and the
        # results have been collected (offload → the researcher owns the copy).
        cons_ttl = experiment.consensus_ttl_days
        if cons_ttl is None or experiment.results_collected_at is None:
            return None
        return experiment.results_collected_at + timedelta(days=cons_ttl)
    # T-X replica: clock starts on delivery/collection; never-delivered gets grace.
    anchor = experiment.results_collected_at or result.delivered_at
    if anchor is not None:
        return anchor + timedelta(days=raw_ttl_days)
    return result.completed_at + timedelta(days=grace_days)


def age_off_sweep(
    jobs_dir: Path,
    control_db: Database,
    *,
    apply: bool,
    now: datetime,
) -> SweepReport:
    """Walk every per-job DB on disk (incl. cold ones) and age off expired T-X /
    overridden T-C payloads. Skips experiments under retention hold. Dry-run
    unless `apply=True`. Returns a report."""
    factory = PerJobDatabaseFactory(jobs_dir)
    exp_repo = ExperimentRepository(control_db)
    audit_repo = AuditRepository(control_db)
    report = SweepReport(applied=apply, now=now.isoformat())
    try:
        for db_path in sorted(jobs_dir.glob("*.db")):
            experiment_id = db_path.stem
            experiment = exp_repo.get_by_id(experiment_id)
            if experiment is None:
                continue  # orphan per-job DB with no control row — leave it
            if experiment.retention_hold:
                report.experiments.append(ExperimentSweep(experiment_id, held=True))
                continue
            per_job = factory.get(experiment_id)
            if per_job is None:
                continue
            repo = ResultRepository(per_job)
            raw_ttl = experiment.raw_payload_ttl_days or DEFAULT_RAW_TTL_DAYS
            ageable: list[str] = []
            bytes_freed = 0
            for r in repo.list_active_payloads():
                horizon = _horizon_for(
                    r, experiment, raw_ttl_days=raw_ttl, grace_days=DEFAULT_GRACE_DAYS
                )
                if horizon is not None and horizon < now:
                    ageable.append(r.result_id)
                    bytes_freed += len(json.dumps(r.payload))
            if apply and ageable:
                repo.age_off(ageable, expires_at=now)
                audit_repo.append(
                    actor_class=CredentialClass.SYSTEM,
                    action="results.payload_aged_off",
                    resource_type="experiment",
                    resource_id=experiment_id,
                    payload={"count": len(ageable), "bytes_freed": bytes_freed},
                )
            report.experiments.append(
                ExperimentSweep(
                    experiment_id,
                    held=False,
                    ageable_result_ids=ageable,
                    bytes_freed=bytes_freed,
                )
            )
    finally:
        factory.close_all()
    return report


# ---- C14 regime-2: capacity-aware settle-sweep ----

# Quiescence window before a capacity-stuck unit settles at its floor, in heartbeat
# intervals so it rides the existing liveness framework (no new wall-clock constant). 2x the
# stale-heartbeat window lets a transiently-offline worker recover before its unit settles
# below target.
SETTLE_QUIESCENCE_INTERVALS = 2


@dataclass
class SettledUnit:
    experiment_id: str
    unit_id: str
    achieved: int
    target: int
    floor: int


@dataclass
class SettleReport:
    applied: bool
    now: str
    settled: list[SettledUnit] = field(default_factory=list)

    def summary(self) -> str:
        verb = "settled" if self.applied else "would settle"
        head = f"regime-2 settle-sweep @ {self.now} ({'APPLIED' if self.applied else 'DRY-RUN'})"
        if not self.settled:
            return f"{head}\n  no capacity-stuck units ready to settle"
        lines = [head]
        lines += [
            f"  {verb} {s.experiment_id}/{s.unit_id} at {s.achieved}/{s.target} (floor {s.floor})"
            for s in self.settled
        ]
        return "\n".join(lines)


def settle_sweep(
    config: Config,
    *,
    apply: bool,
    now: datetime,
    quiescence_intervals: int = SETTLE_QUIESCENCE_INTERVALS,
) -> SettleReport:
    """C14 regime-2 (capacity-aware completion). Complete an IN_PROGRESS unit at its ACHIEVED
    replication when it has met its floor, the eligible fleet is exhausted, AND it has been
    quiescent (no new result) for >= `quiescence_intervals` heartbeat windows — so a unit aiming
    for more replicas than the fleet can supply settles at the best achievable instead of
    stalling forever. Dry-run unless `apply=True`.

    A settled unit runs the SAME post-completion path as a normal completion
    (`finalize_completed_unit`) so receipts / consensus-promotion / attestation are
    byte-identical; the agreeing contributors get their promotion check (their receipts are
    minted here for the first time)."""
    from auspexai_platform.api.assignments import finalize_completed_unit
    from auspexai_platform.db.repositories.assignments import AssignmentRepository
    from auspexai_platform.db.repositories.work_units import WorkUnitRepository
    from auspexai_platform.scheduler.capacity import unit_fleet_exhausted
    from auspexai_platform.services import build_coordinator_services

    svc = build_coordinator_services(config)
    quiescence = timedelta(minutes=quiescence_intervals * STALE_HEARTBEAT_MINUTES)
    report = SettleReport(applied=apply, now=now.isoformat())
    factory = svc.per_job_factory
    try:
        for exp in svc.experiment_repository.list_all(status=ExperimentStatus.APPROVED):
            per_job = factory.get(exp.experiment_id)
            if per_job is None:
                continue
            wu_repo = WorkUnitRepository(per_job)
            assignments_repo = AssignmentRepository(per_job)  # assignments are a per-job table
            for unit in wu_repo.list_all(status=WorkUnitStatus.IN_PROGRESS):
                if unit.completions_so_far < exp.replication_floor:
                    continue  # below the floor → regime 3 (pause/resume), not a settle
                results = ResultRepository(per_job).list_for_unit(unit.unit_id)
                if not results:
                    continue  # defensive — completions>=floor implies results exist
                if now - max(r.received_at for r in results) < quiescence:
                    continue  # not quiescent yet — a late result / enroller may still arrive
                if not unit_fleet_exhausted(
                    unit,
                    exp,
                    worker_repository=svc.worker_repository,
                    assignments_repo=assignments_repo,
                    now=now,
                ):
                    continue  # a schedulable eligible worker can still contribute
                report.settled.append(
                    SettledUnit(
                        experiment_id=exp.experiment_id,
                        unit_id=unit.unit_id,
                        achieved=unit.completions_so_far,
                        target=unit.replication_target,
                        floor=exp.replication_floor,
                    )
                )
                if not apply:
                    continue
                updated, just_completed = wu_repo.complete_at_floor(unit.unit_id)
                if not just_completed:
                    continue  # a racing path already completed it
                svc.audit_repository.append(
                    actor_class=CredentialClass.SYSTEM,
                    actor_identifier="settle-sweep",
                    action="unit.completed_at_floor",
                    resource_type="work_unit",
                    resource_id=unit.unit_id,
                    payload={
                        "experiment_id": exp.experiment_id,
                        "achieved": updated.completions_so_far,
                        "target": updated.replication_target,
                        "floor": exp.replication_floor,
                    },
                )
                finalize_completed_unit(
                    unit_id=unit.unit_id,
                    experiment_id=exp.experiment_id,
                    updated_unit=updated,
                    per_job_db=per_job,
                    promote_worker_ids=sorted({r.worker_id for r in results}),
                    experiment_repository=svc.experiment_repository,
                    receipt_signing_key=svc.receipt_signing_key,
                    receipt_index_repository=svc.receipt_index_repository,
                    worker_repository=svc.worker_repository,
                    account_repository=svc.account_repository,
                    audit_repository=svc.audit_repository,
                    eligibility_thresholds=svc.eligibility_thresholds,
                    vouch_repository=svc.vouch_repository,
                    promotion_auto_t1_t2=svc.promotion_auto_t1_t2,
                    trust_model_policy_repository=svc.trust_model_policy_repository,
                    attestation_repository=svc.attestation_repository,
                    event_bus=None,
                    governance_footprint_builder=svc.governance_footprint_for,
                )
    finally:
        factory.close_all()
    return report
