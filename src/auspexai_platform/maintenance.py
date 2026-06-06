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

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import CredentialClass, Experiment, Result
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AuditRepository,
    ExperimentRepository,
    ResultRepository,
)

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
