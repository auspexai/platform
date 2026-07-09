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
from datetime import UTC, datetime, timedelta
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
from auspexai_platform.db.repositories.experiments import InvalidStatusTransitionError
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
    result: Result,
    experiment: Experiment,
    *,
    raw_ttl_days: int,
    grace_days: int,
    observation_units: frozenset[str] = frozenset(),
) -> datetime | None:
    """The age-off deadline for a result's payload, or None if it should be KEPT.

    D19 (ratified 2026-07-03): the tier follows what the run DECLARED as its
    science. Under `builtin_process_only` every replica is an independent
    observation — the declared scientific content — so ALL of a process-only
    unit's rows take the T-C horizon (download-then-purge on the consensus
    clock), not the T-X byproduct clock they landed on by promotion accident.
    Diverged replicas and tolerance outliers stay T-X: corroboration byproducts,
    interesting briefly, hashes verify forever."""
    if result.is_consensus or result.unit_id in observation_units:
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
            observation_units = frozenset(
                row["unit_id"]
                for row in per_job.execute(
                    "SELECT unit_id FROM unit_consensus WHERE method = 'builtin_process_only'"
                )
            )
            ageable: list[str] = []
            bytes_freed = 0
            for r in repo.list_active_payloads():
                horizon = _horizon_for(
                    r,
                    experiment,
                    raw_ttl_days=raw_ttl,
                    grace_days=DEFAULT_GRACE_DAYS,
                    observation_units=observation_units,
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
    paused: list[SettledUnit] = field(default_factory=list)  # regime 3: starved below the floor
    resumed: list[str] = field(default_factory=list)  # experiment_ids auto-resumed (capacity back)

    def summary(self) -> str:
        head = (
            f"regime-2/3 capacity sweep @ {self.now} ({'APPLIED' if self.applied else 'DRY-RUN'})"
        )
        if not (self.settled or self.paused or self.resumed):
            return f"{head}\n  nothing to settle, pause, or resume"
        sv = "settled" if self.applied else "would settle"
        pv = "paused" if self.applied else "would pause"
        rv = "resumed" if self.applied else "would resume"
        lines = [head]
        lines += [
            f"  {sv} {s.experiment_id}/{s.unit_id} at {s.achieved}/{s.target} (floor {s.floor})"
            for s in self.settled
        ]
        lines += [
            f"  {pv} {p.experiment_id}: {p.unit_id} starved at {p.achieved}/floor {p.floor}"
            for p in self.paused
        ]
        lines += [f"  {rv} {e} (corroborating capacity recovered)" for e in self.resumed]
        return "\n".join(lines)


def settle_sweep(
    config: Config,
    *,
    apply: bool,
    now: datetime,
    quiescence_intervals: int = SETTLE_QUIESCENCE_INTERVALS,
) -> SettleReport:
    """C14 regimes 2 + 3 (capacity-aware completion + pause/resume below the floor). Settle an IN_PROGRESS unit at its ACHIEVED
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
    from auspexai_platform.scheduler.capacity import (
        unit_fleet_exhausted,
        unit_max_achievable_replication,
    )
    from auspexai_platform.services import build_coordinator_services

    svc = build_coordinator_services(config)
    quiescence = timedelta(minutes=quiescence_intervals * STALE_HEARTBEAT_MINUTES)
    report = SettleReport(applied=apply, now=now.isoformat())
    factory = svc.per_job_factory
    try:
        # APPROVED experiments: settle a unit at the floor (regime 2), or pause the experiment
        # when a unit's fleet is exhausted BELOW the floor (regime 3).
        for exp in svc.experiment_repository.list_all(status=ExperimentStatus.APPROVED):
            per_job = factory.get(exp.experiment_id)
            if per_job is None:
                continue
            wu_repo = WorkUnitRepository(per_job)
            assignments_repo = AssignmentRepository(per_job)  # assignments are a per-job table
            starved: SettledUnit | None = None  # first below-floor, fleet-exhausted unit
            for unit in wu_repo.list_all(status=WorkUnitStatus.IN_PROGRESS):
                results = ResultRepository(per_job).list_for_unit(unit.unit_id)
                assigns = assignments_repo.list_for_unit(unit.unit_id)
                if not assigns:
                    continue  # defensive: an IN_PROGRESS unit has been assigned at least once
                # Quiescence is keyed on the last RESULT (a worker delivering); an in-flight
                # fetch is handled by unit_fleet_exhausted, not here. The assignment time is the
                # fallback only for a 0-result unit (an abandoned fetch with nothing delivered).
                last_activity = (
                    max(r.received_at for r in results)
                    if results
                    else max(a.assigned_at for a in assigns)
                )
                if now - last_activity < quiescence:
                    continue  # not quiescent: a late result / enroller may still arrive
                if not unit_fleet_exhausted(
                    unit,
                    exp,
                    worker_repository=svc.worker_repository,
                    assignments_repo=assignments_repo,
                    now=now,
                ):
                    continue  # a schedulable eligible worker can still contribute
                if unit.completions_so_far < exp.replication_floor:
                    # regime 3: exhausted BELOW the floor, so this unit can never be corroborated
                    # with today's fleet. Remember it; pause the experiment after this pass.
                    starved = starved or SettledUnit(
                        experiment_id=exp.experiment_id,
                        unit_id=unit.unit_id,
                        achieved=unit.completions_so_far,
                        target=unit.replication_target,
                        floor=exp.replication_floor,
                    )
                    continue
                # regime 2: exhausted AT/ABOVE the floor, settle at the achieved replication.
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
                    manifest_repository=svc.manifest_repository,
                    pre_registration_repository=svc.pre_registration_repository,
                )
            if starved is not None:
                report.paused.append(starved)
                if apply:
                    _regime3_pause(svc, exp, starved, now=now)

        # PAUSED-by-the-sweep experiments: resume once corroborating capacity recovers (regime 3).
        for exp in svc.experiment_repository.list_all(status=ExperimentStatus.PAUSED):
            if exp.last_action_by_class is not CredentialClass.SYSTEM:
                continue  # only auto-resume what the sweep paused, never an operator pause
            per_job = factory.get(exp.experiment_id)
            if per_job is None:
                continue
            wu_repo = WorkUnitRepository(per_job)
            assignments_repo = AssignmentRepository(per_job)
            recovered = True
            for unit in wu_repo.list_all(status=WorkUnitStatus.IN_PROGRESS):
                if unit.completions_so_far >= exp.replication_floor:
                    continue  # already corroborated to the floor
                if (
                    unit_max_achievable_replication(
                        unit,
                        exp,
                        worker_repository=svc.worker_repository,
                        assignments_repo=assignments_repo,
                        now=now,
                    )
                    < exp.replication_floor
                ):
                    recovered = False  # at least one unit still can't reach the floor
                    break
            if recovered:
                report.resumed.append(exp.experiment_id)
                if apply:
                    _regime3_resume(svc, exp)
    finally:
        factory.close_all()
    return report


def _regime3_pause(svc, exp, starved: SettledUnit, *, now: datetime) -> None:
    """C14 regime 3: SYSTEM-pause an experiment whose unit cannot reach the floor with the
    current fleet. Mirrors `_maybe_auto_complete` (SYSTEM-actor status transition + audit);
    `last_action_by_class=SYSTEM` marks it for the sweep's auto-resume. Idempotent: a racing
    operator transition (e.g. abort) just no-ops.

    Records whether the starvation is STRUCTURAL — the eligible fleet holds fewer capable
    workers than the floor, so no returning worker can ever lift the hold (it will never
    auto-resume) — vs a transient dip, so the audit log / operator can tell them apart."""
    from auspexai_platform.scheduler.capacity import eligible_capable_count

    try:
        svc.experiment_repository.update_status(
            exp.experiment_id,
            ExperimentStatus.PAUSED,
            actor_class=CredentialClass.SYSTEM,
        )
    except InvalidStatusTransitionError:
        return
    capable = eligible_capable_count(exp, worker_repository=svc.worker_repository, now=now)
    structural = capable < starved.floor
    svc.audit_repository.append(
        actor_class=CredentialClass.SYSTEM,
        actor_identifier="settle-sweep",
        action="experiment.regime3_pause",
        resource_type="experiment",
        resource_id=exp.experiment_id,
        payload={
            "trigger": (
                "structural_under_replication"
                if structural
                else "insufficient_corroborating_capacity"
            ),
            "unit_id": starved.unit_id,
            "need": starved.floor,
            "have": starved.achieved,
            "eligible_capable_workers": capable,
            "structural": structural,
        },
    )


def _regime3_resume(svc, exp) -> None:
    """C14 regime 3: SYSTEM-resume an experiment the sweep paused, once corroborating capacity
    recovered (every below-floor unit can again reach the floor). Only ever called for
    experiments the sweep itself paused; never un-pauses an operator pause."""
    try:
        svc.experiment_repository.update_status(
            exp.experiment_id,
            ExperimentStatus.APPROVED,
            actor_class=CredentialClass.SYSTEM,
        )
    except InvalidStatusTransitionError:
        return
    svc.audit_repository.append(
        actor_class=CredentialClass.SYSTEM,
        actor_identifier="settle-sweep",
        action="experiment.regime3_resume",
        resource_type="experiment",
        resource_id=exp.experiment_id,
        payload={"trigger": "corroborating_capacity_recovered"},
    )


# ---------------------------------------------------------------------------
# A11 — orphan per-job DB file reaper
# ---------------------------------------------------------------------------


@dataclass
class OrphanJobsReport:
    apply: bool
    removed: list[str] = field(default_factory=list)  # experiment_ids whose files were reaped
    skipped_recent: int = 0  # orphans inside the grace window (left for now)

    def summary(self) -> str:
        verb = "removed" if self.apply else "would remove"
        s = f"orphan per-job DB(s): {verb} {len(self.removed)}"
        if self.skipped_recent:
            s += f"; {self.skipped_recent} recent orphan(s) within grace, left"
        for eid in self.removed:
            s += f"\n  - {eid}.db (+ -wal/-shm)"
        return s


def reap_orphan_jobs(
    jobs_dir: Path,
    control_db: Database,
    *,
    now: datetime,
    grace: timedelta,
    apply: bool,
) -> OrphanJobsReport:
    """Remove per-job DB files (+ their -wal/-shm sidecars) whose experiment_id
    has NO row in the experiments table AND whose file is older than `grace`.

    Per-job DB files are the permanent research record for an experiment that
    EXISTS (grows-by-design); this only touches ORPHANS — files for an
    experiment_id with no row, which is genuinely dead (experiments are never
    deleted in-code, so a fileless id has no live reference). The grace window
    guards a create-order race (file written, experiment INSERT still in flight).
    DRY-RUN by default. See `persistent_artifact_reaper_audit.md`."""
    report = OrphanJobsReport(apply=apply)
    if not jobs_dir.exists():
        return report
    live = {r["experiment_id"] for r in control_db.execute("SELECT experiment_id FROM experiments")}
    cutoff = now - grace
    for db_path in sorted(jobs_dir.glob("*.db")):
        if db_path.stem in live:
            continue  # the experiment exists → its per-job DB is the permanent record
        mtime = datetime.fromtimestamp(db_path.stat().st_mtime, tz=UTC)
        if mtime > cutoff:
            report.skipped_recent += 1  # too fresh — could be an in-flight create
            continue
        if apply:
            db_path.unlink(missing_ok=True)
            db_path.with_name(db_path.name + "-wal").unlink(missing_ok=True)
            db_path.with_name(db_path.name + "-shm").unlink(missing_ok=True)
        report.removed.append(db_path.stem)
    return report
