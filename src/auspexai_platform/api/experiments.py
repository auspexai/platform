"""Experiment routes — /api/v0/experiments.

  POST   /api/v0/experiments                      — researcher submits manifest
  GET    /api/v0/experiments                      — list (filtered)
  GET    /api/v0/experiments/{experiment_id}      — detail
  POST   /api/v0/experiments/{id}/actions/approve — operator only
  POST   /api/v0/experiments/{id}/actions/abort   — operator OR own-tenant researcher
  POST   /api/v0/experiments/{id}/actions/archive — operator only

`pause` + `resume` are deferred to M6 (no scheduler yet means there's nothing
to pause). The lifecycle graph is enforced in `ExperimentRepository.update_status`;
the routes layer adds credential-based authorization on top.

Manifest submission flow:

  1. Researcher signs the HTTP request via RFC 9421 (auth layer resolves
     credential.tenant_id from the keyid).
  2. Body is `{"manifest": {...}, "signature": {...}}` — the manifest body
     plus the SDK's ManifestSignature object as JSON. Both opaque to v0.
  3. We enforce `body.manifest.tenant_id == credential.tenant_id` so a
     researcher can't submit a manifest under another tenant.
  4. `body.manifest.experiment_id` becomes the experiment's
     `tenant_experiment_label`. Coordinator generates its own `experiment_id`.
  5. Insert manifest (raises 409 on hash collision) + experiment (raises 409
     on (tenant, label) collision).
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auspexai_platform.assessment import assess_envelope, decide
from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.certification import certified_match
from auspexai_platform.completion import reached_unit_cap
from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    ExperimentStatus,
    IntegrityPolicy,
    ResearchStanding,
    TrustTier,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    AttestationRepository,
    AuditRepository,
    CertifiedProfileRepository,
    DriverStatusRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
)
from auspexai_platform.db.repositories.assignments import AssignmentRepository
from auspexai_platform.db.repositories.experiments import (
    DuplicateExperimentLabelError,
    InvalidStatusTransitionError,
)
from auspexai_platform.db.repositories.manifests import DuplicateManifestError
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.events import EventBus
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.feature_schema import validate_feature_schema
from auspexai_platform.maintenance import projected_raw_age_off
from auspexai_platform.model_sizes import ModelSizer
from auspexai_platform.pre_registration import (
    build_deviation_predicate,
    build_pre_registration_predicate,
    canonical_deviation_bytes,
    validate_pre_registration,
)
from auspexai_platform.receipts.intoto import (
    build_deviation_statement,
    build_pre_registration_statement,
)
from auspexai_platform.receipts.signing import SigningKey, cose_sign1_encode
from auspexai_platform.receipts.tolerance import validate_tolerance_reducer
from auspexai_platform.scheduler import (
    is_sub_floor_policy,
    policy_floor_for_tier,
    required_containment_for_tier,
    resolve_replication,
    worker_is_provisioning,
)

logger = logging.getLogger(__name__)

# ---- response models -------------------------------------------------------


class DriverStatusView(BaseModel):
    """The off-coordinator tenant driver's last-known liveness (0059), so a
    stalled / stranded run self-explains: which driver, when it was last seen,
    how long it has been silent, and why it stopped when it managed a final
    report. The driver runs on the tenant's machine over the tunnel, so this is
    the coordinator's ONLY window into driver liveness."""

    status: str | None = None  # driving | finalizing | exiting | gone
    run_id: str | None = None
    reason: str | None = None
    round: int | None = None
    last_seen_at: str | None = None
    silent_for_seconds: int | None = None


class DriverHeartbeatBody(BaseModel):
    """A driver liveness ping. Sent each round and on the driver's exit paths."""

    status: Literal["driving", "finalizing", "exiting", "gone"]
    run_id: str | None = None
    reason: str | None = None
    round: int | None = None


class ExperimentResponse(BaseModel):
    """Wire shape for an experiment. Fields are Optional so the exposure
    filter can mask non-visible ones.

    Tenant-private posture (researcher_dashboard_design.md §3): an experiment's
    operational metadata is visible to its owning tenant and the maintainer
    only — never anonymously. The maintainer sees everything via the
    `is_visible` short-circuit; the owning researcher matches TENANT_SCOPED.
    No field is PUBLIC: experiment rows carry no open-transparency role — that
    is the receipt/verifier surface's job (the DOI-analogue, §6.8.1). The
    earlier PUBLIC tags predated the researcher credential class hitting a
    *list* endpoint, which would have leaked every tenant's experiment
    existence, ids, status and timeline to anonymous callers.
    """

    experiment_id: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    tenant_id: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    status: Annotated[ExperimentStatus | None, ExposureTag.TENANT_SCOPED] = None
    # E15: a coarse, presentation-only phase so a bare status (esp. the overloaded
    # APPROVED) doesn't conflate awaiting-assessment / queued / running / inert.
    # NOT a new ExperimentStatus — a view-layer refinement; None where the status
    # already says it.
    run_phase: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    # Campaign UI fix B: the manifest's declared duration, surfaced so the
    # dashboard can render elapsed/ETA progress for duration-mode runs
    # (detail route only — one manifest parse; None elsewhere).
    expected_duration_hours: Annotated[float | None, ExposureTag.TENANT_SCOPED] = None
    # How many workers in the fleet can serve this experiment's model at all — the
    # structural ceiling on replication (detail route only). Lets the approve pane
    # warn when the replication floor exceeds the capable fleet (a structural stall).
    capable_worker_count: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    # The replication the MANIFEST declared (detail route only) — so the researcher
    # can see whether approval changed it vs the approved replication_target/floor.
    declared_replication_factor: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    # The off-coordinator tenant driver's liveness (0059, detail route only) —
    # the `DriverStatusView` shape, dumped to a plain dict so the TENANT_SCOPED
    # exposure filter (which flattens nested models) round-trips it cleanly. None
    # when no driver has ever reported; a large `silent_for_seconds` = the driver
    # died/dropped without finalizing → the run reads `stalled`, not `running`.
    driver: Annotated[dict[str, Any] | None, ExposureTag.TENANT_SCOPED] = None
    submitted_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    started_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    completed_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    submissions_finalized: Annotated[bool | None, ExposureTag.TENANT_SCOPED] = None
    last_action_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    last_action_by_class: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    tenant_experiment_label: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    manifest_hash: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    revision: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    error_summary: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    integrity_policy: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    replication_target: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    replication_floor: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    max_unit_duration_seconds: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    # The approved resource bounds are the researcher's OWN run's envelope — the
    # tenant sees them (from approval onward) so a cap or replication change made at
    # approval is visible on their experiment page, not a silent surprise.
    max_units: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    max_concurrent_assignments: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    max_payload_bytes: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    # M1 (#30): models a worker must locally hold to be eligible (empty = none).
    required_capabilities: Annotated[dict[str, Any] | None, ExposureTag.TENANT_SCOPED] = None
    # M-Results retention state.
    retention_hold: Annotated[bool | None, ExposureTag.TENANT_SCOPED] = None
    retention_hold_reason: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    results_collected_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    # Retention policy + projected age-off (O-M8): operators set/own the policy;
    # researchers see only its effects (hold + collected_at + aged-off badges).
    raw_payload_ttl_days: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    consensus_ttl_days: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    raw_payload_age_off_at: Annotated[datetime | None, ExposureTag.OPERATOR_ONLY] = None
    # §9 #48 admission-assessment provenance — the lifecycle-timeline (R-D) +
    # review/auto-queue (console) inputs. TENANT_SCOPED: the owning tenant sees
    # its OWN verdicts (ratified transparency = outcome + envelope always,
    # rationale own-only) and the maintainer sees all. `assessed_by` (which
    # maintainer/agent decided) is operator audit detail, not the tenant's.
    research_class: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_decision: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_tier: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    assessment_rationale: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_envelope: Annotated[list[dict[str, Any]] | None, ExposureTag.TENANT_SCOPED] = None
    assessed_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    assessed_by: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None


class ExperimentListResponse(BaseModel):
    experiments: Annotated[list[ExperimentResponse] | None, ExposureTag.PUBLIC] = None


# E14 — operator "needs attention" surfacing. An approved experiment that has
# submitted ZERO work units for more than this many minutes = the driver never
# delivered (crash / abandon / Ctrl-C). Surfaced to the maintainer (nav badge)
# so abandoned runs don't sit invisibly behind the collapsed Accounts tree.
ATTENTION_STUCK_MINUTES = 10
# C16: must exceed the scheduler's ASSIGNMENT_REDELIVERY_LEASE_SECONDS (600 s) —
# soft-lease re-delivery gets first shot at self-healing a lost offer; anything
# still stale past THIS threshold means re-delivery didn't fire (attempt cap /
# worker gone) and a human should look. See _stalled_unit_experiments.
STALLED_UNIT_MINUTES = 15


class AttentionExperiment(BaseModel):
    experiment_id: str
    tenant_id: str
    label: str | None = None
    age_minutes: int
    reason: str


class AttentionResponse(BaseModel):
    count: int
    experiments: list[AttentionExperiment]


def _stuck_experiments(
    experiment_repository, per_job_factory, now: datetime
) -> list[tuple[Any, int]]:
    """E14: approved experiments with zero work units submitted for more than
    `ATTENTION_STUCK_MINUTES` — the driver never delivered. Returns (experiment,
    age_minutes). Per-job iteration over approved experiments only (few); the nav
    badge polls this, so it stays cheap at current scale."""
    out: list[tuple[Any, int]] = []
    if per_job_factory is None:
        return out
    cutoff = now - timedelta(minutes=ATTENTION_STUCK_MINUTES)
    for e in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
        submitted = e.submitted_at
        if isinstance(submitted, str):
            submitted = datetime.fromisoformat(submitted)
        if submitted.tzinfo is None:
            submitted = submitted.replace(tzinfo=UTC)
        if submitted > cutoff:
            continue  # too fresh — the driver may still be starting up
        pj = per_job_factory.get(e.experiment_id)
        units = sum(WorkUnitRepository(pj).count_by_status().values()) if pj is not None else 0
        if units == 0:
            out.append((e, int((now - submitted).total_seconds() // 60)))
    return out


def _stalled_unit_experiments(
    experiment_repository, per_job_factory, now: datetime, worker_repository=None
) -> list[tuple[Any, int, int]]:
    """C16: approved experiments holding an in_progress unit whose missing
    replicas sit on ACTIVE assignments (no result, no refusal) older than
    `STALLED_UNIT_MINUTES` — the lost-delivery wedge signature. E14's original
    detector only sees approved-with-ZERO-units; a mid-run stall with a dead
    driver returned count:0 live on 2026-07-01 (exp-9WLGijaO). Returns
    (experiment, stalled_unit_count, oldest_age_minutes).

    Threshold ordering is load-bearing: STALLED_UNIT_MINUTES must exceed the
    scheduler's ASSIGNMENT_REDELIVERY_LEASE_SECONDS — re-delivery is the
    self-heal (a re-armed row gets a fresh assigned_at and drops back below
    the threshold); this surface is the backstop for when re-delivery can't
    fire (attempt cap exhausted, worker stopped polling) or hasn't worked.

    A worker still DOWNLOADING a required model is PROVISIONING, not stalled — a
    multi-GB first-serve legitimately outlasts the threshold with no result yet.
    Such an assignment is excluded from the stall count via the shared
    `worker_is_provisioning` guard (the same fact the re-delivery lease consults),
    so a large-model pull never raises a false "needs attention"."""
    out: list[tuple[Any, int, int]] = []
    if per_job_factory is None:
        return out
    workers_by_id = (
        {w.worker_id: w for w in worker_repository.list_all()}
        if worker_repository is not None
        else {}
    )
    cutoff = now - timedelta(minutes=STALLED_UNIT_MINUTES)
    for e in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
        pj = per_job_factory.get(e.experiment_id)
        if pj is None:
            continue
        required_models = (e.required_capabilities or {}).get("models") or []
        wu_repo = WorkUnitRepository(pj)
        asg_repo = AssignmentRepository(pj)
        stalled = 0
        oldest_minutes = 0
        for unit in wu_repo.list_all(status=WorkUnitStatus.IN_PROGRESS):
            for a in asg_repo.list_for_unit(unit.unit_id):
                if a.result_id is not None or a.refused_at is not None:
                    continue
                worker = workers_by_id.get(a.worker_id)
                if worker is not None and worker_is_provisioning(worker, required_models):
                    continue  # provisioning the model — making progress, not stalled
                assigned_at = a.assigned_at
                if assigned_at.tzinfo is None:
                    assigned_at = assigned_at.replace(tzinfo=UTC)
                if assigned_at <= cutoff:
                    stalled += 1
                    oldest_minutes = max(
                        oldest_minutes, int((now - assigned_at).total_seconds() // 60)
                    )
                    break  # one stale active assignment marks the unit stalled
        if stalled:
            out.append((e, stalled, oldest_minutes))
    return out


def _capability_unsatisfiable_experiments(
    experiment_repository, per_job_factory, worker_repository, now: datetime
) -> list[tuple[Any, str]]:
    """C6a: approved experiments with pending work whose `required_capabilities`
    NO active worker satisfies — a routing dead-end that would otherwise sit
    pending until age-off. Distinct from C16 (a lost delivery to an ELIGIBLE
    worker) — here the fleet simply can't run it (a model nobody serves +
    no auto-acquire, a feature no build has, a containment floor no worker
    meets). Returns (experiment, missing-capability summary).

    Cheap by construction: only approved experiments with pending-and-never-
    assigned units are checked, and only against the current active fleet."""
    from auspexai_platform.db.models import WorkerStatus
    from auspexai_platform.scheduler import CONTAINMENT_PERMISSIVE, worker_satisfies

    out: list[tuple[Any, str]] = []
    if per_job_factory is None or worker_repository is None:
        return out
    hb_cutoff = now - timedelta(minutes=ATTENTION_STUCK_MINUTES)

    def _active(w) -> bool:
        hb = getattr(w, "last_heartbeat_at", None)
        if hb is None:
            return False
        if hb.tzinfo is None:
            hb = hb.replace(tzinfo=UTC)
        status = getattr(w, "status", None)
        retired = status in (WorkerStatus.RETIRED, WorkerStatus.QUARANTINED) if status else False
        return hb >= hb_cutoff and not retired

    active = [w for w in worker_repository.list_all() if _active(w)]
    for e in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
        req = getattr(e, "required_capabilities", None) or {}
        if not req:
            continue  # no requirements ⇒ any worker eligible; never unsatisfiable
        pj = per_job_factory.get(e.experiment_id)
        if pj is None:
            continue
        wu_repo = WorkUnitRepository(pj)
        pending = wu_repo.list_all(status=WorkUnitStatus.PENDING)
        if not pending:
            continue  # nothing waiting → not a live routing dead-end
        rre = bool(getattr(e, "requires_real_execution", False))
        floor = getattr(e, "required_containment", None) or CONTAINMENT_PERMISSIVE
        if any(
            worker_satisfies(w, req, requires_real_execution=rre, required_containment=floor)
            for w in active
        ):
            continue  # at least one active worker can run it
        # Name what's unmet (display-only; the first non-satisfiable dimension).
        parts = []
        for dim, vals in req.items():
            if vals:
                parts.append(f"{dim}={','.join(vals)}")
        summary = "; ".join(parts) or "declared requirements"
        out.append((e, summary))
    return out


# A driver silent (no heartbeat) this long past its round cadence has died/
# dropped, not paused between rounds. 4x the stuck threshold matches the longest
# cadence we run (a half-hourly loop idles ~28 min between rounds).
DRIVER_STALL_MINUTES = 4 * ATTENTION_STUCK_MINUTES


def _driver_is_stalled(driver_status_repository, experiment_id: str, now: datetime) -> bool:
    """True when the off-coordinator driver has reported it is leaving
    (exiting/gone) OR its last heartbeat is older than the stall grace — the
    telemetry signal (0059) that a run is stalled, not merely between rounds.
    False when there's no driver-status store or no driver has ever reported."""
    if driver_status_repository is None:
        return False
    ds = driver_status_repository.get(experiment_id)
    if ds is None:
        return False
    if ds.status in ("exiting", "gone"):
        return True
    try:
        last = datetime.fromisoformat(str(ds.last_seen_at).replace("Z", "+00:00"))
    except (ValueError, TypeError):  # pragma: no cover — defensive against a bad stamp
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) > timedelta(minutes=DRIVER_STALL_MINUTES)


def _experiment_phase(
    experiment,
    per_job_factory,
    now: datetime,
    driver_status_repository=None,
    worker_repository=None,
) -> str | None:
    """THE canonical run-phase for an experiment: derives the live signals
    (work-unit counts, latest completion, driver liveness) and delegates to the
    pure `compute_run_phase`. ONE function so every surface — the experiment
    detail, the list, and the activity rollup — agrees (the R-D "stalled here /
    running there" bug was two divergent phase functions)."""
    pj = per_job_factory.get(experiment.experiment_id) if per_job_factory is not None else None
    counts = WorkUnitRepository(pj).count_by_status() if pj is not None else {}
    last_dt: datetime | None = None
    last = WorkUnitRepository(pj).latest_completion_at() if pj is not None else None
    if last is not None:
        last_dt = datetime.fromisoformat(last)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=UTC)
    # Is a capable worker still pulling a required model? Then the run is
    # provisioning, not running (compute_run_phase folds this in when no result
    # has landed yet). Cheap: reads each worker's already-loaded capabilities.
    provisioning = False
    required_models = (getattr(experiment, "required_capabilities", None) or {}).get("models") or []
    if worker_repository is not None and required_models:
        provisioning = any(
            worker_is_provisioning(w, required_models) for w in worker_repository.list_all()
        )
    return compute_run_phase(
        experiment,
        in_flight=counts.get("in_progress", 0),
        pending=counts.get("pending", 0),
        completed=counts.get("completed", 0),
        total=sum(counts.values()),
        last_completion_at=last_dt,
        driver_stalled=_driver_is_stalled(driver_status_repository, experiment.experiment_id, now),
        now=now,
        provisioning=provisioning,
    )


def compute_run_phase(
    experiment,
    *,
    in_flight: int,
    pending: int,
    completed: int,
    total: int,
    last_completion_at: datetime | None,
    driver_stalled: bool,
    now: datetime,
    provisioning: bool = False,
) -> str | None:
    """Pure, presentation-only run-phase from already-derived signals — one
    vocabulary, unit-testable, identical across every surface. NOT a new
    ExperimentStatus. None for terminal states, where the status already says it.

      submitted → awaiting_assessment (async auto-assessment hasn't run) | assessed
      paused    → paused
      approved  → provisioning (fresh, 0 units) · inert (old, 0 units = E14 stuck)
                  · queued (work pending, nothing started) · running
                  · capped (reached its max_units cap — a clean quota end)
                  · completing (finalized — no more submissions can come)
                  · stalled (driver silent/exited without a clean end — 0059 telemetry,
                             falling back to completion-staleness when no driver signal)
    """
    status_val = getattr(experiment.status, "value", experiment.status)
    if status_val == ExperimentStatus.SUBMITTED.value:
        decided = getattr(experiment, "assessment_decision", None)
        return "assessed" if decided else "awaiting_assessment"
    if status_val == ExperimentStatus.PAUSED.value:
        return "paused"
    if status_val != ExperimentStatus.APPROVED.value:
        return None
    if total == 0:
        submitted = experiment.submitted_at
        if isinstance(submitted, str):
            submitted = datetime.fromisoformat(submitted)
        if submitted.tzinfo is None:
            submitted = submitted.replace(tzinfo=UTC)
        return (
            "inert"
            if (now - submitted) > timedelta(minutes=ATTENTION_STUCK_MINUTES)
            else "provisioning"
        )
    # A capable worker is still pulling a required model and no result has landed
    # yet: the units sit in_progress on the downloading worker, but the run is
    # PROVISIONING, not "running" — say so, so every surface agrees the worker is
    # fetching the model rather than mislabeling a multi-GB first-serve as running.
    if provisioning and completed == 0:
        return "provisioning"
    all_settled = in_flight == 0 and pending == 0
    # Reached the max_units cap with everything settled: a clean quota end, NOT a
    # stall (the coordinator won't accept more units — see completion.reached_unit_cap).
    if (
        all_settled
        and completed > 0
        and reached_unit_cap(getattr(experiment, "max_units", None), total)
    ):
        return "capped"
    if all_settled:
        # "completing" was the 2026-07-04 campaign's most-reported legibility bug:
        # round-based drivers sit all-settled ~93% of wall time. Honest split:
        #   finalized                → completing (no more submissions can come)
        #   driver silent/exited     → stalled    (0059 telemetry — the driver died)
        #   settled + recent         → running    (between rounds)
        #   settled + stale (no sig) → stalled    (the completion-staleness fallback)
        if getattr(experiment, "submissions_finalized", False):
            return "completing"
        if driver_stalled:
            return "stalled"
        # 4x the stuck threshold: a half-hourly cadence (the longest we run) idles
        # ~28 min between rounds — comfortably "running".
        if last_completion_at is not None and (now - last_completion_at) <= timedelta(
            minutes=4 * ATTENTION_STUCK_MINUTES
        ):
            return "running"
        return "stalled"
    if in_flight > 0 or completed > 0:
        return "running"
    return "queued"  # pending work, nothing started


class DeviationDeclarationRequest(BaseModel):
    """D16.2-D (§5): a researcher's declaration that the analysis changed after
    the pre-registered design — what changed and why, signed by the DECLARER
    over the canonical bytes (manifest_hash + what_changed + why; the SDK's
    `experiment deviate` convention). Append-only; never an edit."""

    what_changed: str = Field(min_length=10, max_length=2000)
    why: str = Field(min_length=10, max_length=2000)
    tenant_signature_b64: str = Field(min_length=1)


class ExperimentSubmissionRequest(BaseModel):
    """POST /api/v0/experiments body. Manifest + ManifestSignature."""

    manifest: dict[str, Any] = Field(description="Manifest body (opaque to v0)")
    signature: dict[str, Any] = Field(description="SDK ManifestSignature object")


class SetIntegrityPolicyRequest(BaseModel):
    """M4 scheduler override: change an experiment's integrity policy (the
    replication target). `reason` is mandatory + audited. `force` is required to
    set a policy BELOW the tenant's tier floor (A' approve-time clamp)."""

    integrity_policy: str = Field(description="standard | high | trusted")
    reason: str = Field(min_length=1, max_length=2000)
    force: bool = Field(
        default=False,
        description="override the tenant tier floor (set a sub-floor / repl-1 policy "
        "the account hasn't earned); requires reason; loudly audited",
    )


class SetReplicationRequest(BaseModel):
    """C14 override: set an experiment's (replication_target, replication_floor) directly — the
    post-ladder mechanic that supersedes the {1,3,5} integrity_policy ladder. `reason` is
    mandatory + audited. resolve_replication tier-floors both, so a maintainer RAISES
    corroboration freely; lowering BELOW the tier floor stays on the legacy
    set-integrity-policy + force path."""

    replication_target: int | None = Field(default=None, ge=1, le=15)
    replication_floor: int | None = Field(default=None, ge=1, le=15)
    reason: str = Field(min_length=1, max_length=2000)


# ---- helpers ---------------------------------------------------------------


def _assessment_payload(experiment) -> dict[str, Any]:
    """The §9 #48 assessment view: the decision + its provenance (class, tier,
    envelope, rationale) and the resulting status (`approved` after an auto)."""
    return {
        "experiment_id": experiment.experiment_id,
        "status": experiment.status.value,
        "research_class": experiment.research_class,
        "decision": experiment.assessment_decision,
        "tier": experiment.assessment_tier,
        "rationale": experiment.assessment_rationale,
        "envelope": experiment.assessment_envelope,
        "assessed_at": experiment.assessed_at.isoformat() if experiment.assessed_at else None,
        "assessed_by": experiment.assessed_by,
    }


def _to_response(experiment) -> ExperimentResponse:
    return ExperimentResponse(
        experiment_id=experiment.experiment_id,
        tenant_id=experiment.tenant_id,
        tenant_experiment_label=experiment.tenant_experiment_label,
        manifest_hash=experiment.manifest_hash,
        status=experiment.status,
        submitted_at=experiment.submitted_at,
        started_at=experiment.started_at,
        completed_at=experiment.completed_at,
        revision=experiment.revision,
        error_summary=experiment.error_summary,
        submissions_finalized=experiment.submissions_finalized,
        last_action_at=experiment.last_action_at,
        last_action_by_class=(
            experiment.last_action_by_class.value
            if experiment.last_action_by_class is not None
            else None
        ),
        integrity_policy=experiment.integrity_policy.value
        if hasattr(experiment, "integrity_policy") and experiment.integrity_policy
        else "standard",
        replication_target=getattr(experiment, "replication_target", None),
        replication_floor=getattr(experiment, "replication_floor", None),
        max_unit_duration_seconds=experiment.max_unit_duration_seconds,
        max_units=experiment.max_units,
        max_concurrent_assignments=experiment.max_concurrent_assignments,
        max_payload_bytes=experiment.max_payload_bytes,
        required_capabilities=getattr(experiment, "required_capabilities", None) or None,
        retention_hold=getattr(experiment, "retention_hold", False) or None,
        retention_hold_reason=getattr(experiment, "retention_hold_reason", None),
        results_collected_at=getattr(experiment, "results_collected_at", None),
        raw_payload_ttl_days=getattr(experiment, "raw_payload_ttl_days", None),
        consensus_ttl_days=getattr(experiment, "consensus_ttl_days", None),
        raw_payload_age_off_at=projected_raw_age_off(experiment),
        research_class=getattr(experiment, "research_class", None),
        assessment_decision=getattr(experiment, "assessment_decision", None),
        assessment_tier=getattr(experiment, "assessment_tier", None),
        assessment_rationale=getattr(experiment, "assessment_rationale", None),
        assessment_envelope=getattr(experiment, "assessment_envelope", None),
        assessed_at=getattr(experiment, "assessed_at", None),
        assessed_by=getattr(experiment, "assessed_by", None),
    )


def _extract_manifest_identity(manifest: dict[str, Any]) -> tuple[str, str]:
    """Return `(tenant_id, experiment_id)` from a manifest dict. Raises
    ValueError if either is missing or malformed."""
    tenant_id = manifest.get("tenant_id")
    experiment_id = manifest.get("experiment_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("manifest must include `tenant_id` (non-empty string)")
    if not isinstance(experiment_id, str) or not experiment_id:
        raise ValueError("manifest must include `experiment_id` (non-empty string)")
    return tenant_id, experiment_id


# Shared, cache-backed model sizer (top-down fleet-fit): sizes each experiment's
# required models from HF at submit so the scheduler can RAM-gate routing.
_MODEL_SIZER = ModelSizer()


def _derive_required_capabilities(manifest: dict[str, Any], sizer=None) -> dict[str, Any]:
    """M1 (#30): a worker must locally hold every model the manifest marks
    `local_weights_required` (BYOM, §5.8). Keyed by the worker store model_id
    (`<repo-slug>-<quant>`, exact match for hash-agreement consensus). Empty ⇒ no
    requirement (every worker eligible). The manifest stays opaque otherwise.

    Top-down fleet-fit: when a `sizer` (ModelSizer) is given, size each required
    model from HF (coords in the manifest) and record `model_ram_gb` — the
    scheduler then RAM-gates routing so a model is never offered to a worker too
    small to serve it. Sized models only; one with no HF coords is left unsized
    (the worker-side acquire guard is the backstop).

    v0.2 M1 `features`: a seeded-sampling experiment additionally requires
    workers whose build declares the `generation_policy` feature — a volunteer
    fleet never rolls atomically, and a pre-M1 broker would burn every unit
    with params_rejected at request time instead of refusing cleanly."""
    required: dict[str, Any] = {}
    models = manifest.get("models")
    if isinstance(models, list):
        model_ids = [
            m["id"]
            for m in models
            if isinstance(m, dict) and m.get("local_weights_required") and m.get("id")
        ]
        if model_ids:
            required["models"] = model_ids
            if sizer is not None:
                by_id = {m["id"]: m for m in models if isinstance(m, dict) and m.get("id")}
                ram = {}
                for mid in model_ids:
                    m = by_id.get(mid) or {}
                    fp = sizer.footprint_gb(m.get("hf_repo"), m.get("hf_filename"))
                    if fp is not None:
                        ram[mid] = fp
                if ram:
                    required["model_ram_gb"] = ram
    determinism = manifest.get("inference_determinism")
    declared_temp = determinism.get("temperature", 0) if isinstance(determinism, dict) else 0
    try:
        if float(declared_temp) > 0:
            required["features"] = ["generation_policy"]
    except (TypeError, ValueError):
        pass
    return required


def _reject_sampling_agreement_raise(manifest_repository, experiment, new_target: int) -> None:
    """v0.2 M1 §3c, consulted at the maintainer replication-raising overrides
    (the A'-clamp precedent: what submit gates, an override must not silently
    re-open). Raising the target above 1 on a seeded-sampling experiment that
    declares an agreement reducer would wake the dormant agreement machinery on
    legitimately-differing replicas — reject. There is no force path: this is
    structural incoherence, not a trust judgment."""
    if new_target <= 1:
        return
    stored = manifest_repository.get(experiment.manifest_hash)
    manifest = stored.manifest_json if stored is not None else None
    if not isinstance(manifest, dict):
        return
    det = manifest.get("inference_determinism")
    temp = det.get("temperature", 0) if isinstance(det, dict) else 0
    try:
        if float(temp) <= 0:
            return
    except (TypeError, ValueError):
        return
    reducer = manifest.get("reducer")
    kind = reducer.get("kind") if isinstance(reducer, dict) else None
    if kind is None:
        # No declared reducer falls back to hash-agreement at issuance.
        kind = "builtin_hash_agreement"
    if kind in ("builtin_hash_agreement", "builtin_within_cell_tolerance"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "sampling_incoherent_with_agreement_consensus",
                    "message": (
                        f"cannot raise replication to {new_target} on a seeded-sampling "
                        f"experiment declaring the agreement reducer {kind!r}: sampled "
                        "replicas legitimately differ, so cross-worker agreement would be "
                        "meaningless or falsely claimed (inference_determinism memo §3c). "
                        "This experiment runs process-only at target 1."
                    ),
                }
            },
        )


def _check_action_authz(credential: Credential, experiment, *, allow_researcher: bool) -> None:
    """403 if credential can't act on the experiment. Maintainer can always
    act; researcher can act only on their own tenant's experiments and only
    when the route allows it."""
    if credential.is_maintainer():
        return
    if (
        allow_researcher
        and credential.is_researcher()
        and credential.tenant_id == experiment.tenant_id
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "experiment_action_forbidden",
                "message": "this credential is not authorized to perform this action",
                "details": {"experiment_id": experiment.experiment_id},
            }
        },
    )


def _can_view(credential: Credential, experiment) -> bool:
    """True if this credential may view the experiment: maintainer (all) or the
    owning-tenant researcher. Tenant-private — no anonymous/cross-tenant view."""
    if credential.is_maintainer():
        return True
    if credential.is_researcher() and credential.tenant_id == experiment.tenant_id:
        return True
    # Tier-1: the account that RAN this experiment may view it (it ran under a
    # public tenant it does not own, so tenant-match would not apply).
    return (
        credential.is_account()
        and credential.account_id is not None
        and experiment.submitted_by_account_id == credential.account_id
    )


def _experiment_not_found(experiment_id: str) -> HTTPException:
    """The 404 used for both genuinely-absent and not-visible-to-you
    experiments, so a non-owner cannot distinguish existence (§3)."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": {
                "code": "experiment_not_found",
                "message": f"no experiment with id {experiment_id!r}",
                "details": {"experiment_id": experiment_id},
            }
        },
    )


def _enforce_policy_floor(
    *,
    experiment,
    policy: IntegrityPolicy,
    tenant_tier: Callable[[str], int] | None,
    force: bool,
    reason: str | None,
) -> dict[str, Any]:
    """A' approve-time clamp (§9 trust-economics). The submit path already seeds
    an experiment's integrity policy floored by the tenant's tier; this guards
    the two MANUAL maintainer overrides (approve `?integrity_policy=` and
    set-integrity-policy) so they can't silently re-open the hole.

    A maintainer may RAISE integrity above the floor freely. Lowering it BELOW
    the floor (fewer replicas / less consensus than the account has earned) is a
    deliberate, audited exception, not a silent default:

      - no override          → 409 sub_floor_integrity_policy
      - force=true, no reason → 422 force_requires_reason
      - force=true + reason   → allowed; returns the audit-extra dict
        (forced_below_floor / floor_policy / tenant_tier / force_reason) for the
        caller to fold into the action's audit payload.

    No-op (returns {}) when `tenant_tier` is unwired (tests) or the requested
    policy already sits at/above the floor — the common case."""
    if tenant_tier is None:
        return {}
    tier = tenant_tier(experiment.tenant_id)
    if tier is None or not is_sub_floor_policy(policy, tier):
        return {}
    floor = policy_floor_for_tier(tier)
    if not force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "sub_floor_integrity_policy",
                    "message": (
                        f"{policy.value} (repl-{INTEGRITY_POLICY_REPLICATION[policy]}) is below "
                        f"the tier floor {floor.value!r} "
                        f"(repl-{INTEGRITY_POLICY_REPLICATION[floor]}) for tenant tier "
                        f"T{int(tier)}; pass force=true with a reason to override for this "
                        f"experiment, or promote the account to lower replication"
                    ),
                    "details": {
                        "requested_policy": policy.value,
                        "floor_policy": floor.value,
                        "tenant_tier": int(tier),
                    },
                }
            },
        )
    if not (reason and reason.strip()):
        raise HTTPException(
            status_code=422,
            detail={
                "error": {
                    "code": "force_requires_reason",
                    "message": "force=true requires a non-empty reason for a sub-floor "
                    "integrity-policy override",
                }
            },
        )
    return {
        "forced_below_floor": True,
        "floor_policy": floor.value,
        "tenant_tier": int(tier),
        "force_reason": reason,
    }


# ---- router ----------------------------------------------------------------


def _driver_status_view(
    driver_status_repository: DriverStatusRepository, experiment_id: str, now: datetime
) -> DriverStatusView | None:
    """Build the DriverStatusView from the stored row, computing how long the
    driver has been silent (now - last_seen_at) — the signal a stalled run reads.
    None when no driver has ever reported for this experiment."""
    ds = driver_status_repository.get(experiment_id)
    if ds is None:
        return None
    silent: int | None = None
    try:
        last = datetime.fromisoformat(str(ds.last_seen_at).replace("Z", "+00:00"))
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        silent = max(0, int((now - last).total_seconds()))
    except (ValueError, TypeError):  # pragma: no cover — defensive against a bad stamp
        pass
    return DriverStatusView(
        status=ds.status,
        run_id=ds.run_id,
        reason=ds.reason,
        round=ds.round,
        last_seen_at=ds.last_seen_at,
        silent_for_seconds=silent,
    )


def build_router(
    credential_dep,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    *,
    event_bus: EventBus | None = None,
    per_job_factory: PerJobDatabaseFactory | None = None,
    receipt_index_repository: ReceiptIndexRepository | None = None,
    signing_key: SigningKey | None = None,
    attestation_repository: AttestationRepository | None = None,
    pre_registration_repository=None,  # D16.2: the submit-time anchor store
    pre_registration_deviation_repository=None,  # D16.2-D: append-only deviations
    # Promotion-gate certifications (RFC 0001 / Ethics §6.7). Optional so the
    # router builds in tests without it; absent → no run is ever certified-cleared.
    certified_profile_repository: CertifiedProfileRepository | None = None,
    # Tier-1: a connected ACCOUNT (no tenant) may run a public tenant's certified
    # starter. Used to gate the account path on suspension + research standing
    # (the other lookups here are tenant-scoped and don't apply to an account).
    account_repository: AccountRepository | None = None,
    # 0059: the off-coordinator driver's liveness store. Optional so the router
    # builds in tests without it; absent → the heartbeat route is a no-op and the
    # detail response carries no driver field.
    driver_status_repository: DriverStatusRepository | None = None,
    # §9 #48: injected lookups (wired in main.py from the account/application
    # repos, à la the scheduler's account_suspended_for_tenant). All optional so
    # the router builds in tests without them — defaults make every experiment
    # route to human review (tier T1, no scope, no catalog).
    tenant_tier: Callable[[str], int] | None = None,
    # D9 Phase 4 (§2): tenant → research_standing (R0-R3), the BYOT gate input. None
    # in tests / unwired → the gate is a no-op (no frontier submission is rejected).
    tenant_research_standing: Callable[[str], int] | None = None,
    tenant_byot_revoked: Callable[[str], bool] | None = None,
    approved_classes: Callable[[str], list[str] | None] | None = None,
    served_model_ids: Callable[[], set[str] | None] | None = None,
    # §9 #48 inc-4: the runtime auto-approval gate, read server-authoritatively
    # at decision time. Returns (enabled, min_tier). Unwired (tests that don't
    # exercise the gate) ⇒ the endpoint falls back to DISABLED — the safe default.
    auto_approval_gate: Callable[[], tuple[bool, int]] | None = None,
    # §41 containment floor: tenants below this tier require strict sandboxing.
    # 0 = disabled (Phase-1 default). Wired from config.containment_strict_below_tier.
    containment_strict_below_tier: int = 0,
    # firewall #2: (experiment, entries, diverged, db) -> dict | None. The finalize
    # path also persists the canonical attestation, so it needs the footprint builder.
    governance_footprint_builder=None,
    # C6a: enumerated to detect units no active worker can satisfy (capability gap).
    worker_repository=None,
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/experiments",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_experiment(
        body: ExperimentSubmissionRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        # Extract the manifest identity first — the account path's public-starter
        # check below needs it.
        try:
            manifest_tenant, manifest_label = _extract_manifest_identity(body.manifest)
        except ValueError as e:
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT — Starlette renamed in 1.0
                detail={
                    "error": {
                        "code": "manifest_malformed",
                        "message": str(e),
                        "details": {},
                    }
                },
            ) from e

        # The certified profile (if any) is the PUBLIC-ACCESS GRANT: a connected
        # account may run a public tenant's certified starter. Computed once and
        # reused for the replication-floor seed below.
        cert = (
            certified_match(body.manifest, certified_profile_repository)
            if certified_profile_repository is not None
            else None
        )

        # Authorize. A tenant owner (Tier-2) submits under their OWN tenant. A
        # connected ACCOUNT (Tier-1, no tenant) may run a public tenant's
        # certified starter — the certification record IS the public grant; the
        # account must be unsuspended + R1+ (a connected account is R1 by default).
        if credential.is_researcher():
            if manifest_tenant != credential.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": {
                            "code": "manifest_tenant_mismatch",
                            "message": (
                                f"manifest tenant_id {manifest_tenant!r} does not match "
                                f"the signing credential's tenant {credential.tenant_id!r}"
                            ),
                            "details": {
                                "manifest_tenant": manifest_tenant,
                                "credential_tenant": credential.tenant_id,
                            },
                        }
                    },
                )
        elif credential.is_account():
            if cert is None or cert.tenant_id != manifest_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": {
                            "code": "not_a_public_certified_starter",
                            "message": (
                                "a connected account may only run a public tenant's "
                                "certified starter; this manifest is not certified for "
                                f"tenant {manifest_tenant!r}"
                            ),
                            "details": {"manifest_tenant": manifest_tenant},
                        }
                    },
                )
            # Fail-safe: without the account lookup we cannot verify suspension /
            # standing, so the account path is rejected (acct stays None → 403).
            acct = (
                account_repository.get_by_id(credential.account_id)
                if account_repository is not None and credential.account_id is not None
                else None
            )
            if acct is None or acct.suspended_at is not None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": {
                            "code": "account_not_runnable",
                            "message": "this account is not authorized to run experiments",
                            "details": {},
                        }
                    },
                )
            standing = account_repository.research_standing_summary(credential.account_id)
            if int(standing.current) < int(ResearchStanding.R1_VERIFIED):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": {
                            "code": "research_standing_too_low",
                            "message": "running a certified starter requires research standing R1+",
                            "details": {"research_standing": int(standing.current)},
                        }
                    },
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_or_account_required",
                        "message": (
                            "experiment submission requires a researcher or "
                            "connected-account credential"
                        ),
                        "details": {"credential_class": credential.kind.value},
                    }
                },
            )

        # Custom reducers are advertised in the SDK manifest contract but the
        # coordinator only runs builtin_hash_agreement (issuance.py defers custom
        # reducers). Reject `kind:"custom"` at ingest so a tenant can't submit a
        # reducer that would silently never run (its consensus would fall back to
        # hash-agreement without the tenant knowing). Drop this guard when custom
        # reducer subprocess dispatch lands.
        reducer = body.manifest.get("reducer")
        if isinstance(reducer, dict) and reducer.get("kind") == "custom":
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT (starlette 1.x deprecates the _ENTITY alias)
                detail={
                    "error": {
                        "code": "custom_reducer_unsupported",
                        "message": (
                            "custom reducers are not yet supported; the coordinator "
                            "runs builtin_hash_agreement only. Use "
                            'reducer.kind="builtin_hash_agreement".'
                        ),
                    }
                },
            )

        # D16.1 (Inc 2): validate the self-describing feature schema BEFORE the
        # manifest is stored, so a malformed / non-§7-safe declaration never
        # reaches storage or the ingest enforcer. The manifest stays opaque to v0
        # otherwise — this validates ONLY the feature_schema member, via a mirror
        # validator (the coordinator does not import the SDK). The declared schema
        # IS the entire interpretability surface under §7 (raw outputs are never
        # retained), so it must be well-formed and contained at submit.
        feature_schema = body.manifest.get("feature_schema")
        if feature_schema is not None:
            # Blacklist form (mirrors the SDK validators): feature_schema entered
            # the contract at 0.3; every later superset version carries it.
            if str(body.manifest.get("schema_version")) in ("0.1", "0.2"):
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "feature_schema_requires_v0_3",
                            "message": (
                                "a manifest declaring feature_schema must set "
                                'schema_version "0.3" or later (D16.1)'
                            ),
                        }
                    },
                )
            fs_errors = validate_feature_schema(feature_schema)
            if fs_errors:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "feature_schema_invalid",
                            "message": "the declared feature_schema is malformed or not §7-safe",
                            "details": {"errors": fs_errors[:20]},
                        }
                    },
                )
        # §10 Q6: a CERTIFIED / citable experiment MUST declare a feature_schema
        # (certification vouches for the code; the feature schema vouches for the
        # interpretability of the claim). BYOT may omit it during onboarding.
        if cert is not None and not feature_schema:
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT
                detail={
                    "error": {
                        "code": "certified_requires_feature_schema",
                        "message": (
                            "a certified/citable experiment must declare a feature_schema "
                            "(D16.1 §10 Q6)"
                        ),
                    }
                },
            )

        # C7 (Inc 1): a within_cell_tolerance reducer reads its envelope from the
        # feature_schema, so validate the relationship at submit — there must be a
        # predicate feature, and any explicit tolerance_features must reference a
        # declared feature that carries a `comparison`. Rejects a tolerance reducer
        # that would silently have nothing to compare.
        if isinstance(reducer, dict) and reducer.get("kind") == "builtin_within_cell_tolerance":
            tol_errors = validate_tolerance_reducer(reducer, feature_schema)
            if tol_errors:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "tolerance_reducer_invalid",
                            "message": (
                                "the within_cell_tolerance reducer and feature_schema "
                                "are inconsistent (no agreement predicate)"
                            ),
                            "details": {"errors": tol_errors[:20]},
                        }
                    },
                )

        # D16.2: a declared pre_registration must be well-formed, §7-safe, and
        # CHECKABLE against this same manifest (features exist in the
        # feature_schema and carry the comparison envelope the design
        # pre-registers) BEFORE storage — a malformed design never gets an
        # anchor. Mirror validation; the coordinator does not import the SDK.
        if body.manifest.get("pre_registration") is not None:
            pr_errors = validate_pre_registration(body.manifest)
            if pr_errors:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "pre_registration_invalid",
                            "message": (
                                "the declared pre_registration is malformed or not "
                                "checkable against this manifest (D16.2)"
                            ),
                            "details": {"errors": pr_errors[:20]},
                        }
                    },
                )

        # C7 / inference_determinism — the SAMPLING COHERENCE GATE (Inc 1, made
        # durable by Inc 2). Seeded sampling (inference_determinism.temperature > 0)
        # makes replica outputs legitimately DIFFER, so engaging cross-replica
        # AGREEMENT machinery would either spuriously fail (hash-agreement) or —
        # with a loose envelope — FALSELY claim corroboration (tolerance). The
        # agreement machinery is dormant exactly when the EFFECTIVE replication
        # target is 1 (no peer; every unit settles process_only — "each replica an
        # independent sample, no cross-worker agreement claimed", memo §3c). So:
        # sampling + an agreement reducer is accepted ONLY at an effective target
        # of 1, computed post-A'-floor with the same resolve_replication the
        # seeding below uses (a sub-tier tenant's repl-1 request floors UP — that
        # floored target is the honest one to gate on). Inc 2 also removed the
        # Inc-1 "not yet enforced" blanket reject (the fleet now honors the
        # declared policy) and added the pinned-seed floor, mirroring the SDK
        # build-time validators (the coordinator does not import the SDK).
        # Ref: inference_determinism_scoping_memo.md §3c/§6. Greedy (temperature 0
        # or an omitted inference_determinism block) is unaffected — the common case.
        determinism = body.manifest.get("inference_determinism")
        declared_temp = determinism.get("temperature", 0) if isinstance(determinism, dict) else 0
        try:
            is_sampling = float(declared_temp) > 0
        except (TypeError, ValueError):
            is_sampling = False
        if is_sampling:
            declared_seed = determinism.get("seed") if isinstance(determinism, dict) else None
            if not isinstance(declared_seed, int) or isinstance(declared_seed, bool):
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "sampling_requires_pinned_seed",
                            "message": (
                                "seeded sampling (inference_determinism.temperature > 0) requires "
                                "a pinned integer 'seed' — unseeded sampling is not accepted "
                                "(the reproducibility floor; a sampling run's attestation attests "
                                "the declared (model, params, seed-stream))."
                            ),
                        }
                    },
                )
            sampling_reducer_kind = reducer.get("kind") if isinstance(reducer, dict) else None
            if sampling_reducer_kind is None:
                # A manifest with no declared reducer falls back to hash-agreement
                # at issuance — gate it as what it will actually run.
                sampling_reducer_kind = "builtin_hash_agreement"
            if sampling_reducer_kind in ("builtin_hash_agreement", "builtin_within_cell_tolerance"):
                _requested_target = int(body.manifest.get("replication_factor", 1) or 1)
                _effective_target = _requested_target
                if tenant_tier is not None:
                    _effective_target, _, _ = resolve_replication(
                        requested_target=_requested_target,
                        requested_floor=body.manifest.get("replication_floor"),
                        tenant_tier=tenant_tier(manifest_tenant),
                        tier_floor_override=cert.replication_floor if cert else None,
                    )
                if _effective_target > 1:
                    raise HTTPException(
                        status_code=422,  # UNPROCESSABLE_CONTENT
                        detail={
                            "error": {
                                "code": "sampling_incoherent_with_agreement_consensus",
                                "message": (
                                    "seeded sampling (inference_determinism.temperature > 0) at an "
                                    f"effective replication target of {_effective_target} is "
                                    f"incoherent with the agreement reducer "
                                    f"{sampling_reducer_kind!r}: sampled replicas legitimately "
                                    "differ, so cross-worker agreement would be meaningless or "
                                    "falsely claimed. Declare replication_factor 1 (process-only: "
                                    "each replica an independent sample) or a non-agreement "
                                    "collection mode."
                                ),
                            }
                        },
                    )

        # Insert manifest. Duplicate (same canonical hash) means re-submission;
        # treat as 409 — researchers shouldn't blindly re-upload identical
        # manifests; the receipt audit chain wants distinct submission events.
        try:
            manifest = manifest_repository.insert(
                tenant_id=manifest_tenant,
                manifest_json=body.manifest,
                signature_json=body.signature,
            )
        except DuplicateManifestError as e:
            logger.warning("duplicate manifest for tenant %s: %s", manifest_tenant, e)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_manifest",
                        "message": "an identical manifest is already stored",
                    }
                },
            ) from e

        try:
            experiment = experiment_repository.create(
                tenant_id=manifest_tenant,
                tenant_experiment_label=manifest_label,
                manifest_hash=manifest.manifest_hash,
                required_capabilities=_derive_required_capabilities(
                    body.manifest, sizer=_MODEL_SIZER
                ),
                requires_real_execution=bool(body.manifest.get("requires_real_execution")),
                # The runner — for an account-run public starter this is the only
                # link back to the researcher; for a tenant owner it's their account.
                submitted_by_account_id=credential.account_id,
            )
        except DuplicateExperimentLabelError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_experiment_label",
                        "message": (
                            f"tenant {manifest_tenant!r} already has an experiment "
                            f"with label {manifest_label!r}"
                        ),
                        "details": {
                            "tenant_id": manifest_tenant,
                            "tenant_experiment_label": manifest_label,
                        },
                    }
                },
            ) from e

        # D16.1: record whether this ran a CERTIFIED starter at submit (cert
        # resolved in the authorization gate above). Drives the §7 reject-vs-flag
        # decision at result ingest. Captured at submit because certification
        # vouches for the CODE — a submit-time property that a later cert
        # revocation must not retroactively change for a running experiment.
        experiment = experiment_repository.set_certified(experiment.experiment_id, cert is not None)

        # A' (§9): seed the integrity policy from the researcher's requested
        # replication (manifest.replication_factor), FLOORED by the tenant's trust
        # tier — reciprocity: a tenant earns lower replication (less consensus
        # cross-check) only as its account earns trust. The maintainer can still
        # RAISE it at approve; the floor caps how LOW it can go, and auto-approval
        # (§9 #48) inherits this floored seed so it can never clear a sub-tier
        # experiment at trusted/repl-1.
        if tenant_tier is not None:
            tier = tenant_tier(manifest_tenant)
            # C14: decouple replication from the {1,3,5} ladder so repl-2 is expressible.
            # The manifest's replication_factor is the TARGET; replication_floor defaults
            # to 2 (a real cross-check), both floored by the tenant's trust tier.
            # §6.7: a gate-certified starter runs at its CERTIFIED floor. DEFENSIVE only —
            # registered tenants floor at T1 (already 2), so this bites only a hypothetical
            # T0 (anonymous) submitter; not load-bearing for real newcomer-tenants.
            # `cert` was computed once in the authorization gate above (reused).
            _target, _floor, _policy = resolve_replication(
                requested_target=int(body.manifest.get("replication_factor", 1) or 1),
                requested_floor=body.manifest.get("replication_floor"),
                tenant_tier=tier,
                tier_floor_override=cert.replication_floor if cert else None,
            )
            experiment_repository.set_replication(
                experiment.experiment_id,
                replication_target=_target,
                replication_floor=_floor,
                integrity_policy=_policy,
            )
            # §41 containment floor: seed the minimum sandbox isolation from the
            # tenant tier (the host-isolation analogue of the A' replication floor).
            # The scheduler then routes units only to workers that meet it.
            experiment_repository.set_required_containment(
                experiment.experiment_id,
                required_containment_for_tier(tier, containment_strict_below_tier),
            )
            experiment = experiment_repository.get_by_id(experiment.experiment_id)

        audit_repository.append(
            # AUD-10 (A9 audit): attribute by the credential's actual class — an
            # account-run public starter is ACCOUNT, not RESEARCHER (tenant_id None) —
            # and record the runner account so the submit is attributable.
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.submit",
            resource_type="experiment",
            resource_id=experiment.experiment_id,
            payload={
                "tenant_experiment_label": experiment.tenant_experiment_label,
                "manifest_hash": experiment.manifest_hash,
                "submitted_by_account_id": experiment.submitted_by_account_id,
                "integrity_policy": experiment.integrity_policy.value
                if experiment.integrity_policy
                else None,
            },
        )

        # D16.2 (§4 strong tier): COSE-sign + persist the SUBMIT-TIME
        # pre-registration anchor. Placeholder Rekor sentinels; the hourly A2
        # backfill anchors it publicly — its timestamp then provably precedes
        # the result attestation's completion-time anchor (`design ≺ data`).
        # Best-effort: a failure never blocks the submit (the minimum tier —
        # tenant-signed manifest + the audit timestamp above — already holds,
        # and the citable/DOI gate fails CLOSED on a missing row), but it is
        # audited loudly because the row is load-bearing for citation.
        if (
            body.manifest.get("pre_registration") is not None
            and pre_registration_repository is not None
            and signing_key is not None
        ):
            try:
                predicate_cbor = build_pre_registration_predicate(
                    manifest_hash=experiment.manifest_hash,
                    tenant_id=experiment.tenant_id,
                    tenant_experiment_label=experiment.tenant_experiment_label,
                    pre_registration=body.manifest["pre_registration"],
                    submitted_at=experiment.submitted_at.isoformat(),
                )
                statement_cbor = build_pre_registration_statement(
                    predicate_cbor=predicate_cbor,
                    experiment_id=experiment.experiment_id,
                )
                blob = cose_sign1_encode(payload=statement_cbor, signing_key=signing_key)
                pre_registration_repository.insert(
                    experiment_id=experiment.experiment_id,
                    tenant_id=experiment.tenant_id,
                    tenant_experiment_label=experiment.tenant_experiment_label,
                    manifest_hash=experiment.manifest_hash,
                    cose_signed_blob=blob,
                    signing_key_pubkey_hex=signing_key.pubkey_hex,
                    submitted_at=experiment.submitted_at.isoformat(),
                )
                audit_repository.append(
                    actor_class=CredentialClass.SYSTEM,
                    actor_identifier="coordinator",
                    action="pre_registration.recorded",
                    resource_type="experiment",
                    resource_id=experiment.experiment_id,
                    payload={"manifest_hash": experiment.manifest_hash},
                )
            except Exception:
                logger.exception(
                    "pre_registration anchor write failed for %s — the minimum tier "
                    "(signed manifest + audit timestamp) holds; the citable gate "
                    "will fail closed without this row",
                    experiment.experiment_id,
                )
                audit_repository.append(
                    actor_class=CredentialClass.SYSTEM,
                    actor_identifier="coordinator",
                    action="pre_registration.record_failed",
                    resource_type="experiment",
                    resource_id=experiment.experiment_id,
                    payload={"manifest_hash": experiment.manifest_hash},
                )

        # C7 Inc 3: the exact-without-pin footgun. Byte-exact hash agreement on a
        # BYO / heterogeneous fleet predictably diverges unless the serving stack is
        # pinned — the C15 incident (Ollama 0.17.7 vs 0.18.2, same weights). If an
        # inference run (one that declares an inference_determinism profile) selects
        # the exact reducer WITHOUT a serving_version_pin, record an advisory:
        # within_cell_tolerance is the default for such runs. Non-fatal — the run is
        # allowed (the maintainer/researcher decides), the advisory is the nudge.
        determinism = body.manifest.get("inference_determinism")
        reducer_kind = reducer.get("kind") if isinstance(reducer, dict) else None
        if (
            reducer_kind == "builtin_hash_agreement"
            and isinstance(determinism, dict)
            and determinism
            and not determinism.get("serving_version_pin")
        ):
            logger.warning(
                "experiment %s: exact (builtin_hash_agreement) inference run without a "
                "serving_version_pin — predictably diverges on a heterogeneous fleet (C15); "
                "prefer builtin_within_cell_tolerance, or pin the serving version",
                experiment.experiment_id,
            )
            audit_repository.append(
                actor_class=CredentialClass.SYSTEM,
                actor_identifier="coordinator",
                action="experiment.exact_without_pin",
                resource_type="experiment",
                resource_id=experiment.experiment_id,
                payload={
                    "advisory": (
                        "exact hash-agreement inference run without a serving_version_pin; "
                        "version skew predictably diverges (C15) — prefer "
                        "within_cell_tolerance, or pin the serving version"
                    ),
                    "reducer_kind": reducer_kind,
                },
            )

        # M6: a newly-submitted experiment enters the approval queue. The bus
        # otherwise emits `experiment.status` only on *transitions* — never on
        # creation — so without this the operator console can't surface a pending
        # approval live (it had to be refreshed). Full payload: the maintainer
        # firehose renders it as-is; a tenant-scoped stream applies the §6.1
        # per-subscriber exposure filter (the event is not pre-redacted by audience).
        if event_bus is not None:
            event_bus.publish(
                "experiment.submitted",
                experiment_id=experiment.experiment_id,
                data={
                    "status": experiment.status.value,
                    "tenant_id": experiment.tenant_id,
                    "tenant_experiment_label": experiment.tenant_experiment_label,
                    "manifest_hash": experiment.manifest_hash,
                    "submitted_at": (
                        experiment.submitted_at.isoformat()
                        if experiment.submitted_at is not None
                        else None
                    ),
                    "required_capabilities": getattr(experiment, "required_capabilities", None)
                    or None,
                },
            )

        return filter_for_credential(
            _to_response(experiment),
            credential,
            resource_tenant_id=experiment.tenant_id,
            resource_account_id=experiment.submitted_by_account_id,
        )

    @router.get(
        "/experiments",
        response_model=ExperimentListResponse,
        response_model_exclude_none=True,
    )
    async def list_experiments(
        assessment: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentListResponse:
        # Tenant-private row scoping (§3): maintainer sees the whole fleet; a
        # researcher sees only their own tenant's rows; anyone else (anonymous,
        # worker) sees none. Field-level filtering still applies on top, but the
        # row scope is what stops cross-tenant existence/count leaking through a
        # list endpoint.
        # §9 #48: `?assessment=review|auto` is the maintainer's review / auto
        # queue (maintainer-only — a researcher's list stays their full set).
        if credential.is_maintainer():
            experiments = experiment_repository.list_all(assessment_decision=assessment)
        elif credential.is_researcher() and credential.tenant_id is not None:
            experiments = experiment_repository.list_all(tenant_id=credential.tenant_id)
        elif credential.is_account() and credential.account_id is not None:
            # Tier-1: a connected account's OWN runs (under public tenants).
            experiments = experiment_repository.list_all(
                submitted_by_account_id=credential.account_id
            )
        else:
            experiments = []
        now = datetime.now(UTC)
        filtered = []
        for e in experiments:
            resp = _to_response(e)
            # E15: only APPROVED experiments touch the per-job DB (the helper
            # early-returns for submitted/terminal), so the list stays cheap.
            resp.run_phase = _experiment_phase(
                e, per_job_factory, now, driver_status_repository, worker_repository
            )
            filtered.append(
                filter_for_credential(
                    resp,
                    credential,
                    resource_tenant_id=e.tenant_id,
                    resource_account_id=e.submitted_by_account_id,
                )
            )
        return ExperimentListResponse(experiments=filtered)

    @router.get(
        "/maintainer/experiments/attention",
        response_model=AttentionResponse,
    )
    async def experiments_attention(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AttentionResponse:
        """E14: experiments needing the maintainer's attention — approved-but-inert
        (zero work units past the stuck threshold) and (D16.1 §7) experiments with
        CERTIFIED results rejected for feature_schema violations. Surfaced on the
        nav badge. Maintainer-only — a fleet-wide health view, never tenant-exposed."""
        require_maintainer(credential)
        now = datetime.now(UTC)
        items = [
            AttentionExperiment(
                experiment_id=e.experiment_id,
                tenant_id=e.tenant_id,
                label=getattr(e, "tenant_experiment_label", None),
                age_minutes=age,
                reason="approved with no work units submitted",
            )
            for e, age in _stuck_experiments(experiment_repository, per_job_factory, now)
        ]
        # C16: mid-run stalls — an in_progress unit wedged on a stale ACTIVE
        # assignment (lost offer delivery; re-delivery didn't self-heal). The
        # 2026-07-01 incident class the zero-units detector above cannot see.
        items.extend(
            AttentionExperiment(
                experiment_id=e.experiment_id,
                tenant_id=e.tenant_id,
                label=getattr(e, "tenant_experiment_label", None),
                age_minutes=oldest_minutes,
                reason=(
                    f"{n} unit(s) stalled in_progress on a stale assignment "
                    "(no result, no refusal — possible lost offer delivery)"
                ),
            )
            for e, n, oldest_minutes in _stalled_unit_experiments(
                experiment_repository, per_job_factory, now, worker_repository
            )
        )
        # D16.1 §7: a CERTIFIED result rejected for a feature_schema violation is a
        # §7 leak or executor/schema mismatch — the unit goes terminal, so the
        # experiment stalls until a human acts (abort / re-certify). BYOT flags
        # (certified=0) are the researcher's own onboarding feedback, not a fleet
        # alert, so they are excluded here.
        if receipt_index_repository is not None:
            for exp_id, n in receipt_index_repository.certified_schema_rejection_counts().items():
                e = experiment_repository.get_by_id(exp_id)
                if e is None:
                    continue
                submitted = e.submitted_at
                if isinstance(submitted, str):
                    submitted = datetime.fromisoformat(submitted)
                if submitted.tzinfo is None:
                    submitted = submitted.replace(tzinfo=UTC)
                items.append(
                    AttentionExperiment(
                        experiment_id=exp_id,
                        tenant_id=e.tenant_id,
                        label=getattr(e, "tenant_experiment_label", None),
                        age_minutes=int((now - submitted).total_seconds() // 60),
                        reason=f"{n} certified result(s) rejected for feature_schema violations (§7)",
                    )
                )
        items.extend(
            AttentionExperiment(
                experiment_id=e.experiment_id,
                tenant_id=e.tenant_id,
                label=getattr(e, "tenant_experiment_label", None),
                age_minutes=0,
                reason=f"no active worker satisfies its requirements ({summary}) — capability gap",
            )
            for e, summary in _capability_unsatisfiable_experiments(
                experiment_repository, per_job_factory, worker_repository, now
            )
        )
        return AttentionResponse(count=len(items), experiments=items)

    @router.get(
        "/experiments/{experiment_id}",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def get_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        # Tenant-private (§3): a non-owning researcher / anonymous caller gets
        # the same 404 as a genuinely-absent experiment, so detail never
        # confirms an experiment id exists.
        if experiment is None or not _can_view(credential, experiment):
            raise _experiment_not_found(experiment_id)
        resp = _to_response(experiment)
        resp.run_phase = _experiment_phase(
            experiment,
            per_job_factory,
            datetime.now(UTC),
            driver_status_repository,
            worker_repository,
        )
        if worker_repository is not None:
            from auspexai_platform.scheduler.capacity import eligible_capable_count

            resp.capable_worker_count = eligible_capable_count(
                experiment, worker_repository=worker_repository, now=datetime.now(UTC)
            )
        m = manifest_repository.get(experiment.manifest_hash)
        if m is not None:
            try:
                mj = m.manifest_json or {}
                resp.expected_duration_hours = mj.get("expected_duration_hours")
                declared_repl = mj.get("replication_factor")
                if isinstance(declared_repl, int):
                    resp.declared_replication_factor = declared_repl
            except AttributeError:
                pass
        if driver_status_repository is not None:
            dv = _driver_status_view(driver_status_repository, experiment_id, datetime.now(UTC))
            resp.driver = dv.model_dump() if dv is not None else None
        return filter_for_credential(
            resp,
            credential,
            resource_tenant_id=experiment.tenant_id,
            resource_account_id=experiment.submitted_by_account_id,
        )

    @router.post(
        "/experiments/{experiment_id}/driver-heartbeat",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    async def driver_heartbeat(
        experiment_id: str,
        body: DriverHeartbeatBody,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> Response:
        """The off-coordinator tenant driver reports its liveness — each round
        (status=driving) and on its exit paths (finalizing / exiting, with a
        reason). Best-effort from the driver's side; here it upserts the driver's
        last-seen/status/reason so a stalled or stranded run is a timestamped,
        queryable fact instead of a silent mystery. An `exiting`/`gone` report is
        also audited (the diagnostic record of WHY a driver stopped)."""
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        _check_action_authz(credential, experiment, allow_researcher=True)
        if driver_status_repository is not None:
            now = datetime.now(UTC).isoformat()
            driver_status_repository.record(
                experiment_id,
                status=body.status,
                now=now,
                run_id=body.run_id,
                reason=body.reason,
                round=body.round,
            )
            if body.status in ("exiting", "gone"):
                audit_repository.append(
                    actor_class=credential.kind,
                    actor_identifier=credential.pubkey_hex,
                    actor_tenant_id=credential.tenant_id,
                    action="driver.exit",
                    resource_type="experiment",
                    resource_id=experiment_id,
                    payload={
                        "status": body.status,
                        "reason": body.reason,
                        "run_id": body.run_id,
                        "round": body.round,
                    },
                )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/experiments/{experiment_id}/actions/approve",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def approve_experiment(
        experiment_id: str,
        integrity_policy: str | None = None,
        replication_target: int | None = None,
        replication_floor: int | None = None,
        max_unit_duration_seconds: int | None = None,
        max_units: int | None = None,
        max_concurrent_assignments: int | None = None,
        max_payload_bytes: int | None = None,
        force: bool = False,
        reason: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        require_maintainer(credential)
        override_audit: dict[str, Any] = {}
        if replication_target is not None or replication_floor is not None:
            # C14 (target, floor) override — the post-ladder mechanic. resolve_replication
            # tier-floors both: the maintainer RAISES corroboration freely; lowering below the
            # tier floor stays on the legacy integrity_policy + force path (the elif).
            experiment = experiment_repository.get_by_id(experiment_id)
            if experiment is None:
                raise _experiment_not_found(experiment_id)
            tier = tenant_tier(experiment.tenant_id) if tenant_tier is not None else None
            cur_target = getattr(experiment, "replication_target", None) or 3
            _rt, _rf, _rp = resolve_replication(
                requested_target=int(replication_target)
                if replication_target is not None
                else int(cur_target),
                requested_floor=replication_floor,
                tenant_tier=tier if tier is not None else int(TrustTier.T2_TRUSTED),
            )
            # v0.2 M1 §3c: the submit-time sampling coherence gate, consulted here too.
            _reject_sampling_agreement_raise(manifest_repository, experiment, _rt)
            experiment_repository.set_replication(
                experiment_id, replication_target=_rt, replication_floor=_rf, integrity_policy=_rp
            )
            override_audit = {
                "replication_target": _rt,
                "replication_floor": _rf,
                "integrity_policy": _rp.value,
            }
        elif integrity_policy is not None:
            try:
                policy = IntegrityPolicy(integrity_policy)
            except ValueError:
                raise HTTPException(
                    status_code=422,
                    detail=f"invalid integrity_policy: {integrity_policy!r}; "
                    f"must be one of: standard, high, trusted",
                ) from None
            experiment = experiment_repository.get_by_id(experiment_id)
            if experiment is None:
                raise _experiment_not_found(experiment_id)
            # A' approve-time clamp: a sub-floor policy needs force=true + reason.
            override_audit = _enforce_policy_floor(
                experiment=experiment,
                policy=policy,
                tenant_tier=tenant_tier,
                force=force,
                reason=reason,
            )
            # v0.2 M1 §3c: the submit-time sampling coherence gate, consulted here too.
            _reject_sampling_agreement_raise(
                manifest_repository, experiment, INTEGRITY_POLICY_REPLICATION[policy]
            )
            experiment_repository.set_integrity_policy(experiment_id, policy)
        if any(
            v is not None
            for v in [
                max_unit_duration_seconds,
                max_units,
                max_concurrent_assignments,
                max_payload_bytes,
            ]
        ):
            experiment_repository.set_resource_bounds(
                experiment_id,
                max_unit_duration_seconds=max_unit_duration_seconds,
                max_units=max_units,
                max_concurrent_assignments=max_concurrent_assignments,
                max_payload_bytes=max_payload_bytes,
            )
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.APPROVED,
            credential=credential,
            allow_researcher=False,
            action="experiment.approve",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
            extra_payload=override_audit or None,
        )

    @router.post(
        "/experiments/{experiment_id}/pre-registration/deviations",
        status_code=status.HTTP_201_CREATED,
    )
    async def declare_deviation(
        experiment_id: str,
        body: DeviationDeclarationRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """D16.2-D (§5): record an append-only, tenant-signed deviation from the
        pre-registered design. The DECLARER signs (accountability); the
        coordinator COSE-signs an anchor statement binding the declaration
        digest + the coordinator-observed declared_at, Rekor-anchored by the
        hourly sweep — WHEN the analysis changed is publicly provable. The
        original pre-registration is never edited. Exploratory analysis is
        allowed and valuable; these records keep it from masquerading as
        confirmatory. NOT a maintainer action — a deviation is the researcher's
        own declaration."""
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        declarer_ok = (
            credential.is_researcher() and credential.tenant_id == experiment.tenant_id
        ) or (
            credential.is_account()
            and credential.account_id is not None
            and experiment.submitted_by_account_id == credential.account_id
        )
        if not declarer_ok:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "deviation_declarer_forbidden",
                        "message": (
                            "a deviation is declared by the experiment's own researcher "
                            "(or the account that ran it) — not by other parties"
                        ),
                    }
                },
            )
        if pre_registration_repository is None or pre_registration_deviation_repository is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": {"code": "deviations_unavailable", "message": "not wired"}},
            )
        prereg = pre_registration_repository.get(experiment_id)
        if prereg is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT
                if hasattr(status, "HTTP_422_UNPROCESSABLE_CONTENT")
                else 422,
                detail={
                    "error": {
                        "code": "not_pre_registered",
                        "message": (
                            "this experiment has no pre-registration — there is no "
                            "declared design to deviate from (exploratory runs need "
                            "no deviation records)"
                        ),
                    }
                },
            )
        # The DECLARER's signature over the canonical declaration, verified
        # against the AUTHENTICATED caller's key — nobody can plant a deviation
        # under someone else's name.
        from base64 import b64decode as _b64d

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        declaration = canonical_deviation_bytes(prereg.manifest_hash, body.what_changed, body.why)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(credential.pubkey_hex)).verify(
                _b64d(body.tenant_signature_b64), declaration
            )
        except (InvalidSignature, ValueError, TypeError):
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "deviation_signature_invalid",
                        "message": (
                            "tenant_signature_b64 does not verify over the canonical "
                            "declaration (manifest_hash + what_changed + why) with the "
                            "authenticated credential's key"
                        ),
                    }
                },
            ) from None
        declared_at = datetime.now(UTC).isoformat()
        deviation_id = f"dev-{secrets.token_urlsafe(9)}"
        predicate_cbor = build_deviation_predicate(
            tenant_experiment_label=experiment.tenant_experiment_label,
            tenant_id=experiment.tenant_id,
            manifest_hash=prereg.manifest_hash,
            what_changed=body.what_changed,
            why=body.why,
            tenant_pubkey_hex=credential.pubkey_hex,
            tenant_signature_b64=body.tenant_signature_b64,
            declared_at=declared_at,
        )
        statement_cbor = build_deviation_statement(
            predicate_cbor=predicate_cbor, deviation_id=deviation_id
        )
        blob = cose_sign1_encode(payload=statement_cbor, signing_key=signing_key)
        record = pre_registration_deviation_repository.insert(
            deviation_id=deviation_id,
            experiment_id=experiment_id,
            tenant_id=experiment.tenant_id,
            manifest_hash=prereg.manifest_hash,
            what_changed=body.what_changed,
            why=body.why,
            tenant_pubkey_hex=credential.pubkey_hex,
            tenant_signature_b64=body.tenant_signature_b64,
            cose_signed_blob=blob,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
            declared_at=declared_at,
        )
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="pre_registration.deviation_recorded",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "deviation_id": deviation_id,
                "manifest_hash": prereg.manifest_hash,
                "what_changed": body.what_changed[:200],
            },
        )
        return record.bundle_dict()

    @router.get("/experiments/{experiment_id}/pre-registration/deviations")
    async def list_deviations(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """D16.2-D: the experiment's append-only deviation history (owner or
        maintainer). Empty list = the pre-registered analysis stands unchanged."""
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None or not _can_view(credential, experiment):
            raise _experiment_not_found(experiment_id)
        if pre_registration_deviation_repository is None:
            return {"deviations": []}
        return {
            "deviations": [
                r.bundle_dict()
                for r in pre_registration_deviation_repository.list_for_experiment(experiment_id)
            ]
        }

    @router.post("/experiments/{experiment_id}/assessment")
    async def assess_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> JSONResponse:
        """§9 #48 — assess a submitted experiment (class-by-tier auto-approval).

        Maintainer-credentialed (the future agent uses a scoped maintainer
        token). The decision is computed SERVER-AUTHORITATIVELY here — the
        caller cannot propose one — so a compromised agent cannot widen the
        gate. `auto` reuses the maintainer approve transition; `review` records
        the assessment and leaves the experiment in `submitted` for the human
        queue. Idempotent: re-calling an already-assessed experiment returns the
        prior assessment unchanged.
        """
        require_maintainer(credential)
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "experiment_not_found",
                        "message": f"no experiment with id {experiment_id!r}",
                    }
                },
            )
        if experiment.assessment_decision is not None:
            return JSONResponse(_assessment_payload(experiment))  # idempotent
        if experiment.status != ExperimentStatus.SUBMITTED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "not_assessable",
                        "message": (
                            "only a submitted experiment can be assessed "
                            f"(status: {experiment.status.value})"
                        ),
                    }
                },
            )

        manifest = manifest_repository.get(experiment.manifest_hash)
        manifest_json = manifest.manifest_json if manifest else {}
        research_class = manifest_json.get("research_class")
        tier = (
            tenant_tier(experiment.tenant_id)
            if tenant_tier is not None
            else int(TrustTier.T1_AUTHENTICATED)
        )
        r_standing = (
            tenant_research_standing(experiment.tenant_id)
            if tenant_research_standing is not None
            else int(ResearchStanding.R2_ESTABLISHED)
        )
        byot_revoked = (
            tenant_byot_revoked(experiment.tenant_id) if tenant_byot_revoked is not None else False
        )
        approved = approved_classes(experiment.tenant_id) if approved_classes is not None else None
        served = served_model_ids() if served_model_ids is not None else None

        envelope = assess_envelope(
            manifest_json=manifest_json,
            research_class=research_class,
            tenant_approved_classes=approved,
            served_model_ids=served,
        )
        if auto_approval_gate is not None:
            gate_enabled, gate_min_tier = auto_approval_gate()
        else:
            # Unwired (a test that doesn't exercise the gate): DISABLED is the
            # safe default — production always wires the reader in main.py.
            gate_enabled, gate_min_tier = False, int(TrustTier.T2_TRUSTED)
        # §6.7.5: a certified-profile run auto-clears regardless of accrued tier
        # (certification substitutes for standing). Both submit and assess resolve
        # the cert independently from the manifest's package digest — no marker column.
        cert = (
            certified_match(manifest_json, certified_profile_repository)
            if certified_profile_repository is not None
            else None
        )
        verdict = decide(
            research_class=research_class,
            tenant_tier=tier,
            envelope=envelope,
            auto_tier=gate_min_tier,
            auto_approval_enabled=gate_enabled,
            certified=cert is not None,
            research_standing=r_standing,
            byot_revoked=byot_revoked,
        )
        assessed_by = credential.maintainer_login or "maintainer"
        # Denormalize the certification provenance onto the experiment's rationale so
        # it surfaces wherever the rationale renders (researcher dashboard, console,
        # API) — including the Rekor logIndex, the public proof handle. (Cheaper than
        # a marker column; the cert stays resolvable from the package digest.)
        rationale = verdict.rationale
        if cert is not None:
            anchor = (
                f"Rekor logIndex {cert.rekor_log_index}"
                if cert.rekor_log_index is not None
                else "Rekor anchor pending"
            )
            rationale = (
                f"{rationale} · certified {cert.tenant_id}/{cert.profile_name} "
                f"(pkg {cert.package_sha256[:12]}…, {anchor})"
            )
        experiment = experiment_repository.set_assessment(
            experiment_id,
            research_class=research_class,
            decision=verdict.decision,
            tier=tier,
            envelope=envelope.as_json(),
            rationale=rationale,
            assessed_by=assessed_by,
        )
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=assessed_by,
            actor_tenant_id=None,
            action="experiment.assess",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "research_class": research_class,
                "decision": verdict.decision,
                "track": verdict.track,
                "tier": tier,
                "envelope_failures": envelope.failures,
                "rationale": verdict.rationale,
            },
        )
        if verdict.decision == "auto":
            # Reuse the maintainer approve transition; the assessment row records
            # WHY. The distinct action keeps an auto-approval auditable as such.
            _transition(
                experiment_id=experiment_id,
                new_status=ExperimentStatus.APPROVED,
                credential=credential,
                allow_researcher=False,
                action="experiment.assess.auto",
                experiment_repository=experiment_repository,
                audit_repository=audit_repository,
                event_bus=event_bus,
            )
            experiment = experiment_repository.get_by_id(experiment_id)
        return JSONResponse(_assessment_payload(experiment))

    @router.post(
        "/experiments/{experiment_id}/actions/abort",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def abort_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        response = _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.ABORTED,
            credential=credential,
            allow_researcher=True,
            action="experiment.abort",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )
        # D22-B teardown cascade: the status flip alone leaves open units
        # in_progress forever and every collected result without a terminal
        # signal, so workers poll canonical-receipt 404s that never resolve.
        # Cancel the open units and mark receiptless results terminal so the
        # worker's M7-tail loop stops. Best-effort — never undo a successful
        # abort if the cascade hits a snag (the settle sweep is the backstop).
        if per_job_factory is not None and receipt_index_repository is not None:
            try:
                from auspexai_platform.scheduler.teardown import (
                    settle_terminal_experiment,
                )

                settle_terminal_experiment(
                    experiment_id=experiment_id,
                    experiment_status=ExperimentStatus.ABORTED,
                    per_job_factory=per_job_factory,
                    receipt_index_repository=receipt_index_repository,
                )
            except Exception:
                logger.exception(
                    "D22-B abort cascade failed for %s; run the settle sweep",
                    experiment_id,
                )
        return response

    @router.post(
        "/experiments/{experiment_id}/actions/archive",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def archive_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        require_maintainer(credential)
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.ARCHIVED,
            credential=credential,
            allow_researcher=False,
            action="experiment.archive",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/pause",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def pause_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.PAUSED,
            credential=credential,
            allow_researcher=True,
            action="experiment.pause",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/resume",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def resume_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.APPROVED,
            credential=credential,
            allow_researcher=True,
            action="experiment.resume",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/finalize-submissions",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def finalize_submissions(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "experiment_not_found",
                        "message": f"no experiment with id {experiment_id!r}",
                        "details": {"experiment_id": experiment_id},
                    }
                },
            )
        _check_action_authz(credential, experiment, allow_researcher=True)
        # Only sensible when there's something to receive — block on terminal
        # states. The transition graph already encodes which statuses are
        # terminal; finalize is meaningful only for approved/paused.
        if experiment.status not in {ExperimentStatus.APPROVED, ExperimentStatus.PAUSED}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "finalize_not_applicable",
                        "message": (
                            f"submissions can only be finalized while the experiment "
                            f"is approved or paused (current status: "
                            f"{experiment.status.value})"
                        ),
                        "details": {"current_status": experiment.status.value},
                    }
                },
            )
        updated = experiment_repository.finalize_submissions(
            experiment_id, actor_class=credential.kind
        )
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.finalize_submissions",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "was_already_finalized": experiment.submissions_finalized,
            },
        )
        # If every unit already completed *before* this finalize (the autonomic
        # loop's finalize-on-convergence case — it finalizes once the last round's
        # units are all done), the unit-completion auto-complete trigger
        # (assignments._maybe_auto_complete, fired on result submit) never re-fires.
        # So run the same check here; otherwise the experiment is stuck APPROVED +
        # finalized and never reaches COMPLETED (no result-set attestation).
        if per_job_factory is not None:
            per_job_db = per_job_factory.get(experiment_id)
            if per_job_db is not None:
                from auspexai_platform.api.assignments import (
                    _maybe_auto_complete,
                    _maybe_emit_completion_attestation,
                )

                _maybe_auto_complete(
                    experiment_id=experiment_id,
                    per_job_db=per_job_db,
                    experiment_repository=experiment_repository,
                    audit_repository=audit_repository,
                    event_bus=event_bus,
                )
                # A1: the finalize-on-convergence completion path (M8 autonomic
                # driver finalizes after the last round's units are all done)
                # reaches COMPLETED here, NOT via a result submit — so persist the
                # canonical attestation on this path too. Idempotent + best-effort;
                # the on-demand GET canonicalizes lazily if these deps are absent.
                if receipt_index_repository is not None and signing_key is not None:
                    _maybe_emit_completion_attestation(
                        experiment_id=experiment_id,
                        per_job_db=per_job_db,
                        experiment_repository=experiment_repository,
                        receipt_index_repository=receipt_index_repository,
                        signing_key=signing_key,
                        audit_repository=audit_repository,
                        attestation_repository=attestation_repository,
                        event_bus=event_bus,
                        # firewall #2: the finalize path persists the canonical
                        # attestation too — it MUST carry the footprint (the
                        # bug a live D6 run surfaced: emit here lacked it).
                        governance_footprint_builder=governance_footprint_builder,
                        pre_registration_repository=pre_registration_repository,
                    )
                updated = experiment_repository.get_by_id(experiment_id) or updated
        return filter_for_credential(
            _to_response(updated),
            credential,
            resource_tenant_id=updated.tenant_id,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/retention-hold",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def place_retention_hold(
        experiment_id: str,
        reason: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only: place an audit/legal retention hold so the age-off
        sweep keeps this experiment's data regardless of collection. Mandatory
        reason (mirrors the account-suspension pattern)."""
        require_maintainer(credential)
        if not reason.strip():
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "reason_required",
                        "message": "a reason is required to place a retention hold",
                    }
                },
            )
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        updated = experiment_repository.set_retention_hold(experiment_id, held=True, reason=reason)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.retention_hold",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"reason": reason},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    @router.post(
        "/experiments/{experiment_id}/actions/set-integrity-policy",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def set_integrity_policy(
        experiment_id: str,
        body: SetIntegrityPolicyRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only M4 scheduler override: change the experiment's
        integrity policy (replication target). NOTE: units bake `replication_target`
        at submit, so this changes FUTURE units' target, not units already
        submitted. Mandatory reason; audited."""
        require_maintainer(credential)

        try:
            policy = IntegrityPolicy(body.integrity_policy)
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "invalid_integrity_policy",
                        "message": f"invalid integrity_policy: {body.integrity_policy!r}; "
                        "expected standard | high | trusted",
                    }
                },
            ) from e
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        # A' approve-time clamp: a sub-floor policy needs force=true + reason.
        override_audit = _enforce_policy_floor(
            experiment=experiment,
            policy=policy,
            tenant_tier=tenant_tier,
            force=body.force,
            reason=body.reason,
        )
        # v0.2 M1 §3c: the submit-time sampling coherence gate, consulted here too.
        _reject_sampling_agreement_raise(
            manifest_repository, experiment, INTEGRITY_POLICY_REPLICATION[policy]
        )
        experiment_repository.set_integrity_policy(experiment_id, policy)
        updated = experiment_repository.get_by_id(experiment_id)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.set_integrity_policy",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"integrity_policy": policy.value, "reason": body.reason, **override_audit},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    @router.post(
        "/experiments/{experiment_id}/actions/set-replication",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def set_replication(
        experiment_id: str,
        body: SetReplicationRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only M4 override (C14): set the experiment's (replication_target,
        replication_floor) directly — the post-ladder mechanic superseding set-integrity-policy.
        resolve_replication tier-floors both: a maintainer RAISES corroboration freely; lowering
        BELOW the tier's earned floor stays on the legacy set-integrity-policy + force path.
        Changes FUTURE units (units bake the target at submit). Mandatory reason; audited."""
        require_maintainer(credential)
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        tier = tenant_tier(experiment.tenant_id) if tenant_tier is not None else None
        cur_target = getattr(experiment, "replication_target", None) or 3
        target, floor, policy = resolve_replication(
            requested_target=body.replication_target
            if body.replication_target is not None
            else int(cur_target),
            requested_floor=body.replication_floor,
            tenant_tier=tier if tier is not None else int(TrustTier.T2_TRUSTED),
        )
        # v0.2 M1 §3c: the submit-time sampling coherence gate, consulted here too.
        _reject_sampling_agreement_raise(manifest_repository, experiment, target)
        experiment_repository.set_replication(
            experiment_id,
            replication_target=target,
            replication_floor=floor,
            integrity_policy=policy,
        )
        updated = experiment_repository.get_by_id(experiment_id)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.set_replication",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "replication_target": target,
                "replication_floor": floor,
                "integrity_policy": policy.value,
                "reason": body.reason,
            },
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    @router.post(
        "/experiments/{experiment_id}/actions/release-hold",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def release_retention_hold(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only: release a retention hold (the experiment's data
        resumes normal age-off)."""
        require_maintainer(credential)
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        updated = experiment_repository.set_retention_hold(experiment_id, held=False, reason=None)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.retention_hold_released",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    return router


def _transition(
    *,
    experiment_id: str,
    new_status: ExperimentStatus,
    credential: Credential,
    allow_researcher: bool,
    action: str,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    event_bus: EventBus | None = None,
    extra_payload: dict[str, Any] | None = None,
) -> ExperimentResponse:
    """Common path for the action endpoints. Authorization + transition +
    audit + response filter. `extra_payload` merges into the audit payload —
    used by approve to record an A' sub-floor integrity-policy override."""
    experiment = experiment_repository.get_by_id(experiment_id)
    if experiment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "code": "experiment_not_found",
                    "message": f"no experiment with id {experiment_id!r}",
                    "details": {"experiment_id": experiment_id},
                }
            },
        )
    _check_action_authz(credential, experiment, allow_researcher=allow_researcher)
    try:
        updated = experiment_repository.update_status(
            experiment_id, new_status, actor_class=credential.kind
        )
    except InvalidStatusTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "invalid_status_transition",
                    "message": str(e),
                    "details": {
                        "current_status": experiment.status.value,
                        "requested_status": new_status.value,
                    },
                }
            },
        ) from e

    audit_repository.append(
        actor_class=credential.kind,
        actor_identifier=credential.pubkey_hex,
        actor_tenant_id=credential.tenant_id,
        action=action,
        resource_type="experiment",
        resource_id=experiment_id,
        payload={
            "from_status": experiment.status.value,
            "to_status": new_status.value,
            **(extra_payload or {}),
        },
    )
    if event_bus is not None:
        event_bus.publish(
            "experiment.status",
            experiment_id=experiment_id,
            data={
                "status": new_status.value,
                "from_status": experiment.status.value,
                "revision": updated.revision,
                "actor_class": credential.kind.value,
            },
        )
    return filter_for_credential(
        _to_response(updated),
        credential,
        resource_tenant_id=updated.tenant_id,
    )
