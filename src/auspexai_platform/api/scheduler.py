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

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    ExperimentStatus,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
    ModelPrestageRepository,
    WorkerRepository,
    WorkUnitRepository,
)
from auspexai_platform.db.repositories.model_prestage import DuplicatePrestageError
from auspexai_platform.scheduler import (
    reoffer_eligible,
    replication_floor_for_tier,
    worker_is_degraded,
    worker_is_self_paused,
    worker_satisfies,
)
from auspexai_platform.scheduler.conductor import _coords_for_models
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
    # §2.1 #8-tail: in-progress units that every worker has refused non-reofferably
    # (terminal kind, or retryable but at the attempt cap) — stranded, won't
    # complete without intervention. Distinct from `blocked` (a pending-side signal).
    stalled_units: int = 0


class SchedulerWorker(BaseModel):
    worker_id: str
    trust_tier: int
    model_count: int
    paused: bool
    degraded: bool = False  # M5: heartbeat thermal state == critical (routed around)
    self_paused: bool = False  # §2.1 #11: volunteer self-pause (owner hold)
    # M9 leg 4: the worker's declared code-execution mode (synthetic/provisioned/off).
    # Explains real-execution eligibility — a synthetic worker is excluded from
    # model-gated experiments (it would echo). Absent declaration ⇒ "synthetic".
    execute_tenant_code: str = "synthetic"
    eligible_experiment_count: int  # approved experiments w/ outstanding work this worker can take


class SchedulerStateResponse(BaseModel):
    experiments: list[SchedulerExperiment]
    workers: list[SchedulerWorker]
    active_worker_count: int  # on-network, available for work (excludes paused + degraded)


def _model_count(worker) -> int:
    m = worker.capabilities.get("models")
    return len(m) if isinstance(m, list) else 0


def _count_stalled(pj) -> int:
    """§2.1 #8-tail: in-progress units stranded because every assignment is a
    non-reofferable refusal (terminal kind, or retryable but at the attempt cap)
    and none is active — the unit can't complete without intervention."""
    if pj is None:
        return 0
    work_units = WorkUnitRepository(pj)
    assignments_repo = AssignmentRepository(pj)
    stalled = 0
    for unit in work_units.list_all(status=WorkUnitStatus.IN_PROGRESS):
        assignments = assignments_repo.list_for_unit(unit.unit_id)
        if not assignments:
            continue  # in-progress but unassigned (a transient state) — not stalled
        if any(a.refused_at is None and a.result_id is None for a in assignments):
            continue  # an active assignment exists — someone's working it
        if any(reoffer_eligible(a) for a in assignments):
            continue  # a refused assignment is still re-offerable — not stalled
        stalled += 1
    return stalled


class TriggerPrestageRequest(BaseModel):
    reason: str  # mandatory, audited


class PinUnitRequest(BaseModel):
    worker_id: str
    reason: str  # mandatory, audited


def build_router(
    credential_dep,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    worker_repository: WorkerRepository,
    *,
    manifest_repository: ManifestRepository | None = None,
    prestage_repository: ModelPrestageRepository | None = None,
    audit_repository: AuditRepository | None = None,
) -> APIRouter:
    router = APIRouter()

    def _require_maintainer(credential: Credential) -> None:
        if not credential.is_maintainer():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")

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
        # M5/§2.1 #11: a degraded (thermal-critical) or volunteer-self-paused worker
        # is routed around, like operator-paused — exclude all from the available
        # workforce so eligibility counts are honest.
        workforce = [
            w
            for w in on_network
            if w.paused_at is None and not worker_is_degraded(w) and not worker_is_self_paused(w)
        ]

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
            capable = [
                w
                for w in workforce
                if worker_satisfies(
                    w,
                    required,
                    requires_real_execution=exp.requires_real_execution,
                    required_containment=exp.required_containment,
                )
            ]
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
                    stalled_units=_count_stalled(pj),
                )
            )

        workers_out = [
            SchedulerWorker(
                worker_id=w.worker_id,
                trust_tier=int(w.trust_tier),
                model_count=_model_count(w),
                paused=w.paused_at is not None,
                degraded=worker_is_degraded(w),
                self_paused=worker_is_self_paused(w),
                execute_tenant_code=(w.capabilities.get("execute_tenant_code") or "synthetic"),
                eligible_experiment_count=elig_count.get(w.worker_id, 0),
            )
            for w in on_network
        ]

        return SchedulerStateResponse(
            experiments=experiments_out,
            workers=workers_out,
            active_worker_count=len(workforce),
        )

    # ---- M4-tail overrides (maintainer, mandatory reason, audited) --------

    @router.post("/experiments/{experiment_id}/actions/trigger-prestage")
    async def trigger_prestage(
        experiment_id: str,
        body: TriggerPrestageRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """Proactively pre-stage this experiment's required models onto eligible
        workers now (the manual conductor fill, M3b/M4-tail). Creates prestage
        rows up to the replication need across auto-acquire workers that lack the
        model; idempotent (skips workers already holding/queued)."""
        _require_maintainer(credential)
        if prestage_repository is None or manifest_repository is None:
            raise HTTPException(status_code=503, detail="prestage not configured")
        if not body.reason.strip():
            raise HTTPException(status_code=422, detail="reason is required")
        exp = experiment_repository.get_by_id(experiment_id)
        if exp is None:
            raise HTTPException(status_code=404, detail="experiment not found")
        required = (exp.required_capabilities or {}).get("models", [])
        manifest = manifest_repository.get(exp.manifest_hash)
        coords = _coords_for_models(manifest.manifest_json) if manifest is not None else {}
        repl = INTEGRITY_POLICY_REPLICATION.get(exp.integrity_policy, 3)
        need = repl + 1  # + churn margin (matches the conductor)
        cutoff = heartbeat_cutoff(datetime.now(UTC))
        on_network = [
            w
            for w in worker_repository.list_all()
            if w.retired_at is None
            and w.quarantined_at is None
            and w.paused_at is None
            and not worker_is_degraded(w)
            and w.last_heartbeat_at is not None
            and w.last_heartbeat_at >= cutoff
            and w.capabilities.get("auto_acquire") is True
        ]
        created = 0
        for model_id in required:
            if model_id not in coords:
                continue
            hf_repo, hf_filename = coords[model_id]
            for w in on_network:
                if replication_floor_for_tier(w.trust_tier) > repl:
                    continue
                if model_id in (w.capabilities.get("models") or []):
                    continue
                if prestage_repository.has_open(model_id=model_id, worker_id=w.worker_id):
                    continue
                holders = worker_repository.count_capable(
                    required_models=[model_id], heartbeat_cutoff=cutoff
                )
                if holders + prestage_repository.count_open_for_model(model_id) >= need:
                    break  # enough supply for this model
                try:
                    prestage_repository.create(
                        model_id=model_id,
                        hf_repo=hf_repo,
                        hf_filename=hf_filename,
                        worker_id=w.worker_id,
                        requested_by=credential.maintainer_login or "maintainer",
                        experiment_id=experiment_id,
                    )
                    created += 1
                except DuplicatePrestageError:
                    continue
        if audit_repository is not None:
            audit_repository.append(
                actor_class=CredentialClass.MAINTAINER,
                actor_identifier=credential.maintainer_login,
                action="prestage.trigger",
                resource_type="experiment",
                resource_id=experiment_id,
                payload={"models": required, "rows_created": created, "reason": body.reason},
            )
        return {"experiment_id": experiment_id, "rows_created": created}

    @router.post("/experiments/{experiment_id}/units/{unit_id}/actions/pin")
    async def pin_unit(
        experiment_id: str,
        unit_id: str,
        body: PinUnitRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """Force-assign a work unit to a specific worker: the scheduler will then
        offer this unit ONLY to that worker (which claims it on its next poll).
        Pull-compatible — a pin is a per-unit worker preference, not a push."""
        _require_maintainer(credential)
        if not body.reason.strip():
            raise HTTPException(status_code=422, detail="reason is required")
        if worker_repository.get_by_id(body.worker_id) is None:
            raise HTTPException(status_code=404, detail="worker not found")
        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            raise HTTPException(status_code=404, detail="experiment has no work units")
        unit = WorkUnitRepository(per_job_db).pin(unit_id, body.worker_id)
        if unit is None:
            raise HTTPException(status_code=404, detail="unit not found")
        if audit_repository is not None:
            audit_repository.append(
                actor_class=CredentialClass.MAINTAINER,
                actor_identifier=credential.maintainer_login,
                action="unit.pin",
                resource_type="work_unit",
                resource_id=unit_id,
                payload={
                    "experiment_id": experiment_id,
                    "worker_id": body.worker_id,
                    "reason": body.reason,
                },
            )
        return {
            "experiment_id": experiment_id,
            "unit_id": unit_id,
            "pinned_worker_id": body.worker_id,
        }

    return router
