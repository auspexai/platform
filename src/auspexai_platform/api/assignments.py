"""Assignment routes — /api/v0/workers/{worker_id}/assignments[/...]

  GET   .../assignments                       — worker; pull next assignment
  POST  .../assignments/{unit_id}/result      — worker; submit Result envelope

This is M6d's load-bearing piece: the loop where work actually moves
between researcher → worker → coordinator.

**GET /workers/{id}/assignments** asks the scheduler for the next work
unit this worker should run. The scheduler walks approved experiments
in registration order, picks the first pending/in-progress unit this
worker isn't already assigned to and that hasn't hit its replication
target. If found, an `assignments` row is created in the per-job DB,
the work-unit status transitions pending → in_progress, and the SDK
work-unit envelope is returned. If no work is available, the response
is `{"work_unit": null}` so the worker can poll without surprises.

**POST .../result** consumes the SDK Result envelope (per
schemas/result_v0_1.json):
  {schema_version, unit_id, worker_pubkey, completed_at, exit_code,
   payload, worker_signature}

Coordinator validates:
  - credential.worker_id == URL worker_id (worker submitting for self)
  - body.unit_id == URL unit_id
  - body.worker_pubkey == credential.pubkey_hex (defense against signed
    request claiming a different worker pubkey in the body)
  - An assignment for this (unit, worker) exists AND has no result yet

Then it inserts the result row, attaches result_id to the assignment,
increments work_unit.completions_so_far, and (if completions >=
replication_target) transitions the unit to 'completed'. Audit-log
entries are written for both assign and result.

**The body-level worker_signature is VERIFIED at submit (§9 #13a).** The
canonical body is reconstructed (v0 or v1 per `schema_version`) and the
Ed25519 signature checked before the result is accepted into the consensus
set — an unauthentic / tampered result is refused (422
`worker_signature_invalid`). This keeps fabricated results out entirely and,
for a v1 result, cryptographically binds the served-weights digest that #13b
enforces. The HTTP-level RFC 9421 signature remains the transport acceptance
proof; receipt issuance re-anchors the same body hash for external verifiers.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import enforce_worker_active, require_worker
from auspexai_platform.completion import reached_unit_cap
from auspexai_platform.db.models import ExperimentStatus, TrustTier
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    AttestationRepository,
    AuditRepository,
    ExperimentRepository,
    ReceiptIndexRepository,
    ResultRepository,
    UnitConsensusRepository,
    WorkerRepository,
    WorkUnitRepository,
)
from auspexai_platform.db.repositories.assignments import (
    AssignmentAlreadyResolvedError,
    DuplicateAssignmentError,
)
from auspexai_platform.db.repositories.attestations import DuplicateAttestationError
from auspexai_platform.db.repositories.experiments import (
    InvalidStatusTransitionError,
)
from auspexai_platform.exposure import ExposureTag
from auspexai_platform.feature_schema import check_payload_conformance
from auspexai_platform.receipts import (
    ReceiptRepository,
    SigningKey,
    issue_receipts_for_completed_unit,
)
from auspexai_platform.receipts.attestation import (
    IncompleteAttestationSetError,
    assert_entries_cover_consensus,
    build_result_set_attestation,
    collect_diverged_units,
    collect_result_set_entries,
    receipt_map_from_per_job,
    unit_quorum_by_unit,
)
from auspexai_platform.result_signature import verify_raw_signature, verify_result_signature
from auspexai_platform.scheduler import (
    CONTAINMENT_STRICT,
    Scheduler,
    containment_rank,
    reoffer_eligible,
)
from auspexai_platform.scheduler.conductor import plan_prestage_for_worker
from auspexai_platform.scheduler.teardown import _mark_terminal_unit_receiptless_results
from auspexai_platform.weights import served_weights_verdict
from auspexai_platform.worker_status import heartbeat_cutoff

logger = logging.getLogger(__name__)

# ---- response models ------------------------------------------------------


class WorkUnitEnvelopeOut(BaseModel):
    """SDK work-unit envelope shape (workunit_v0_1.json). Coordinator
    fills in fields from per-job DB + parent experiment so the worker
    can hand the body to the tenant executor as-is."""

    schema_version: Annotated[str | None, ExposureTag.PUBLIC] = "0.1"
    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    tenant_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None  # tenant label
    manifest_sha256: Annotated[str | None, ExposureTag.PUBLIC] = None
    created_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    payload: Annotated[dict[str, Any] | None, ExposureTag.PUBLIC] = None


class AssignmentResponse(BaseModel):
    assignment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    assigned_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None  # coordinator id
    work_unit: Annotated[WorkUnitEnvelopeOut | None, ExposureTag.PUBLIC] = None
    # WHY the worker got no work (only when work_unit is None) — so a healthy-but-idle
    # node's operator sees "understood" not "stuck". {code, message, model_id?}.
    idle_reason: Annotated[dict | None, ExposureTag.PUBLIC] = None


class ResultSubmissionRequest(BaseModel):
    """Body shape — subset of SDK result_v0_1.json. schema_version is
    accepted but not validated (we already know it's v0.1 in M6d)."""

    unit_id: str = Field(min_length=1, max_length=128)
    worker_pubkey: str = Field(pattern=r"^[a-f0-9]{64}$")
    completed_at: datetime
    exit_code: int = Field(ge=-255, le=255)
    payload: dict[str, Any]
    worker_signature: str = Field(min_length=1)
    # §9 #46 D6 finding: unit_ids are tenant-chosen and can collide across
    # experiments — the bare (unit_id, worker_id) scan once matched a stale
    # ABORTED experiment's assignment. Workers ≥ v0.2.2 send the exact
    # assignment_id; older workers omit it (the scan then skips terminal
    # experiments, which already fixes the observed incident).
    assignment_id: str | None = Field(default=None, max_length=128)
    # §9 #13a: a v1 result additionally signs the served-weights digest. Absent
    # ⇒ legacy v0 (un-rolled worker) and the coordinator reconstructs the
    # five-field canonical body. served_weights is {model_id: gguf_sha256}.
    schema_version: int | None = Field(default=None)
    served_weights: dict[str, str] | None = Field(default=None)
    # §9 / A2 #32: a v2 result additionally signs `ran_under` — the sandbox policy
    # the worker actually ran under. Absent ⇒ pre-v2 (un-rolled worker); the
    # containment guard then falls back to the worker's reported capability.
    ran_under: str | None = Field(default=None, max_length=64)
    # AUD-26: D20 raw model text travels OUTSIDE the signed `payload` — new workers
    # send it here with its own detached `raw_signature` (over sha256(raw) bound to
    # unit+worker). The coordinator verifies the detached sig, then parks raw in the
    # ephemeral transit buffer; it never enters the signed/stored payload, so the
    # result signature verifies on export. Absent ⇒ non-capture or pre-fix worker.
    raw_response: str | None = Field(default=None)
    raw_signature: str | None = Field(default=None, min_length=1)


class RefuseRequest(BaseModel):
    """POST /workers/{id}/assignments/{unit_id}/refuse body — worker tells the
    coordinator it's declining a previously-assigned unit (per M3 Q-W4)."""

    kind: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Refusal reason code. Worker M3 uses: manifest_swap, sensitive, "
            "tenant_deny, tenant_allow_list_miss, manual."
        ),
    )
    # Same disambiguator as ResultSubmissionRequest (workers ≥ v0.2.2).
    assignment_id: str | None = Field(default=None, max_length=128)
    reason: str = Field(
        max_length=2048,
        description="Free-form human-readable detail (operator-visible).",
    )


class RefuseResponse(BaseModel):
    assignment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    refused_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    refused_kind: Annotated[str | None, ExposureTag.PUBLIC] = None


class ServeRecoveredRequest(BaseModel):
    """POST /workers/{id}/serve-recovered body — the worker reports its operator REMEDIATED a
    serve condition (freed memory / restarted the backend) after `model_id` OOM'd on it, so
    this one worker may retry the model despite the model-level exclusion (surgical recovery,
    diversity_seed_stream / volunteer-legibility work)."""

    model_id: str


class ServeRecoveredResponse(BaseModel):
    worker_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    model_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    recorded: Annotated[bool | None, ExposureTag.PUBLIC] = None


class PrestageItem(BaseModel):
    """One model the worker is asked to pre-stage (pull ahead of assignment)."""

    model_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    hf_repo: Annotated[str | None, ExposureTag.PUBLIC] = None
    hf_filename: Annotated[str | None, ExposureTag.PUBLIC] = None


class PrestageResponse(BaseModel):
    prestage: Annotated[list[PrestageItem] | None, ExposureTag.PUBLIC] = None


class ResultSubmissionResponse(BaseModel):
    result_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_status_after: Annotated[str | None, ExposureTag.PUBLIC] = None
    completions_so_far: Annotated[int | None, ExposureTag.PUBLIC] = None
    replication_target: Annotated[int | None, ExposureTag.PUBLIC] = None


# ---- helpers --------------------------------------------------------------


def _generate_assignment_id() -> str:
    return f"asg-{secrets.token_urlsafe(9)}"


def _generate_result_id() -> str:
    return f"res-{secrets.token_urlsafe(9)}"


def _require_self_worker(credential: Credential, url_worker_id: str) -> None:
    require_worker(credential)
    if credential.worker_id != url_worker_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "worker_id_mismatch",
                    "message": "credential worker_id does not match URL worker_id",
                    "details": {
                        "credential_worker_id": credential.worker_id,
                        "url_worker_id": url_worker_id,
                    },
                }
            },
        )


# ---- router ---------------------------------------------------------------


def _result_account_opted_in(worker_repository, account_repository, result) -> bool:
    """System B (non-retroactive citation): was the contributing worker's account opted
    into public attribution AT THE MOMENT this result became a receipt? Snapshotted onto
    the receipt (`public_attribution_at_issue`) so opting in later can't retroactively
    credit past runs. `account_repository` may be None (older wiring) → not opted-in."""
    if account_repository is None:
        return False
    w = worker_repository.get_by_id(result.worker_id)
    if w is None or w.account_id is None:
        return False
    acct = account_repository.get_by_id(w.account_id)
    return bool(acct is not None and acct.public_attribution)


def _result_ran_strict(worker_repository, result) -> bool:
    """Firewall #1 (A2): did this RESULT run under STRICT containment? Counts ONLY
    the worker-SIGNED `ran_under` (a v2 result, #32 — accountable, covered by the
    signature verified at submit).

    AUD-3 (A9 audit): the pre-v2 fallback to the worker's self-reported
    `sandbox_policy` capability was REMOVED — it was spoofable (a v1 worker could
    heartbeat `sandbox_policy='strict'`, actually run permissive, and still earn
    STRICT-contained trust). A missing/legacy signed claim now earns NO STRICT
    trust (fail-closed); the fleet is v2 (worker 0.2.38), so no live impact.
    `worker_repository` is retained in the signature for call-site compatibility."""
    policy = getattr(result, "ran_under", None)
    if policy is None:
        return False
    return containment_rank(policy) >= containment_rank(CONTAINMENT_STRICT)


def build_router(
    credential_dep,
    worker_repository: WorkerRepository,
    scheduler: Scheduler,
    per_job_factory: PerJobDatabaseFactory,
    audit_repository: AuditRepository,
    experiment_repository: ExperimentRepository,
    receipt_signing_key: SigningKey,
    receipt_index_repository: ReceiptIndexRepository,
    account_repository=None,
    eligibility_thresholds=None,
    vouch_repository=None,
    event_bus=None,
    raw_transit=None,  # D20: ephemeral raw-content transit buffer (live collection)
    manifest_repository=None,  # M3b conductor: read acquisition coords from the manifest
    prestage_repository=None,  # M3b conductor: the model_prestage table
    attestation_repository: AttestationRepository | None = None,  # A1: persist on complete
    pre_registration_repository=None,  # D16.2: bind the attestation to the design
    # §6.2 promotion mode: () -> bool, True when T1->T2 auto-promotion is enabled
    # (auto_with_override). Unwired (tests) defaults to True = behavior-preserving.
    promotion_auto_t1_t2=None,
    # firewall #2: (experiment, entries, diverged, db) -> dict | None
    governance_footprint_builder=None,
    # firewall #1 (A2): the equal-trust flip toggle. Unwired (tests) → OFF = the
    # current convergence-gradient trust model (behavior-preserving).
    trust_model_policy_repository=None,
) -> APIRouter:
    router = APIRouter()

    # ---- GET next assignment ------------------------------------------

    @router.get(
        "/workers/{worker_id}/assignments",
        response_model=AssignmentResponse,
        response_model_exclude_none=False,  # we explicitly want work_unit=null
    )
    async def get_assignment(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AssignmentResponse:
        _require_self_worker(credential, worker_id)
        worker = worker_repository.get_by_id(worker_id)
        if worker is None or worker.retired_at is not None:
            # Retired workers fall out of CredentialResolver, so this is
            # technically unreachable from a signed request — guard anyway.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no active worker with id {worker_id!r}",
                    }
                },
            )
        if worker.quarantined_at is not None:
            # Maintainer-applied pause. The worker is still alive (and can
            # still heartbeat); we just don't dispatch work to it. Return
            # 423 Locked so the worker's `auspexai-worker status` can
            # surface the state honestly instead of looking like an idle
            # network with no assignments. The quarantine *reason* IS included
            # now: a worker (the volunteer running it) is entitled to know why
            # its own machine was paused — the same reason the maintainer
            # entered. (Reason is no longer operator-only; it travels with the
            # status to the worker itself and to the worker's own-account
            # researcher.)
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={
                    "error": {
                        "code": "worker_quarantined",
                        "message": (
                            "this worker is quarantined; contact the operator "
                            "or wait for unquarantine"
                        ),
                        "details": {
                            "quarantined_at": worker.quarantined_at.isoformat(),
                            "quarantine_reason": worker.quarantine_reason,
                        },
                    }
                },
            )

        # §2.1 #11: an operator-PAUSED worker is now told it's paused + why — the
        # same transparency as quarantine, but a distinct `worker_paused` code and
        # `no_fault: true` so the volunteer's dashboard frames it as an operational
        # hold, not a trust/fault signal. (Volunteer self-pause is the worker's own
        # state — it doesn't 423 itself; the scheduler just offers it nothing.)
        if worker.paused_at is not None:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={
                    "error": {
                        "code": "worker_paused",
                        "message": (
                            "this worker was paused by the operator (no-fault); "
                            "wait for unpause or contact the operator"
                        ),
                        "details": {
                            "paused_at": worker.paused_at.isoformat(),
                            "pause_reason": worker.pause_reason,
                            "no_fault": True,
                        },
                    }
                },
            )

        pick = scheduler.pick_for_worker(worker)
        if pick is None:
            _idle = getattr(scheduler, "idle_reason_for_worker", None)
            return AssignmentResponse(
                work_unit=None, idle_reason=_idle(worker) if _idle is not None else None
            )

        per_job_db = per_job_factory.get_or_create(pick.experiment_id)
        assignments_repo = AssignmentRepository(per_job_db)
        work_units_repo = WorkUnitRepository(per_job_db)

        # §2.1 #8 (dispatch-retry): the scheduler may pick a unit this worker
        # previously refused for a *retryable* reason (env/transient failure
        # under the attempt cap). In that case an assignment row already exists
        # (refused) — re-arm it rather than INSERT into the UNIQUE (unit,worker)
        # slot. A fresh pairing has no row and takes the create path.
        # C16 (at-least-once delivery): the same re-arm path also serves a
        # stale-ACTIVE row whose offer response was lost in flight (the worker
        # never learned of its assignment) — after the re-delivery lease,
        # reoffer_eligible admits it and reactivate() hands the SAME row back
        # to the same worker with a fresh assigned_at + attempt bump.
        existing = assignments_repo.get_for_unit_and_worker(
            pick.work_unit.unit_id, worker.worker_id
        )
        reoffer = False
        if existing is None:
            try:
                assignment = assignments_repo.create(
                    assignment_id=_generate_assignment_id(),
                    unit_id=pick.work_unit.unit_id,
                    worker_id=worker.worker_id,
                    worker_pubkey_hex=worker.pubkey_hex,
                )
            except DuplicateAssignmentError:
                # Race: another scheduler call already assigned this unit to
                # this worker between the eligibility check and the insert.
                # Return no-work; the next poll will pick a different unit.
                return AssignmentResponse(work_unit=None)
        elif reoffer_eligible(existing):
            assignment = assignments_repo.reactivate(existing.assignment_id)
            reoffer = True
        else:
            # Active assignment, or a terminal/exhausted refusal — not
            # offerable to this worker. (The scheduler normally filters these
            # out; this guards a race where state changed after the pick.)
            return AssignmentResponse(work_unit=None)

        work_units_repo.mark_in_progress(pick.work_unit.unit_id)

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="assignment.reoffer" if reoffer else "assignment.create",
            resource_type="assignment",
            resource_id=assignment.assignment_id,
            payload={
                "experiment_id": pick.experiment_id,
                "unit_id": pick.work_unit.unit_id,
                "worker_id": worker.worker_id,
                "attempt": assignment.attempt_count,
            },
        )

        envelope = WorkUnitEnvelopeOut(
            schema_version="0.1",
            unit_id=pick.work_unit.unit_id,
            tenant_id=pick.tenant_id,
            experiment_id=pick.tenant_experiment_label,
            manifest_sha256=pick.manifest_hash,
            created_at=pick.work_unit.created_at,
            payload=pick.work_unit.payload,
        )

        # All fields PUBLIC; filter would no-op here AND the exposure
        # filter doesn't recurse into nested models per its docstring,
        # so skip it for this nested-shape response.
        return AssignmentResponse(
            assignment_id=assignment.assignment_id,
            assigned_at=assignment.assigned_at,
            experiment_id=pick.experiment_id,
            work_unit=envelope,
        )

    # ---- POST result --------------------------------------------------

    @router.post(
        "/workers/{worker_id}/assignments/{unit_id}/result",
        response_model=ResultSubmissionResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_result(
        worker_id: str,
        unit_id: str,
        body: ResultSubmissionRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ResultSubmissionResponse:
        _require_self_worker(credential, worker_id)
        # F1: quarantine/suspension must reach the INGESTION path, not just
        # `GET /assignments`. A worker quarantined (or whose account is
        # suspended) while holding an assignment otherwise still lands results
        # into consensus. `refuse` is intentionally NOT gated — it releases a
        # held unit back to the pool, which is harmless and better than a stall.
        enforce_worker_active(credential, worker_repository, account_repository)

        if body.unit_id != unit_id:
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT
                detail={
                    "error": {
                        "code": "unit_id_mismatch",
                        "message": "body.unit_id does not match URL unit_id",
                        "details": {
                            "body_unit_id": body.unit_id,
                            "url_unit_id": unit_id,
                        },
                    }
                },
            )

        if body.worker_pubkey.lower() != (credential.pubkey_hex or "").lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "worker_pubkey_mismatch",
                        "message": (
                            "Result.worker_pubkey does not match the signing credential's pubkey"
                        ),
                        "details": {
                            "body_pubkey": body.worker_pubkey,
                            "credential_pubkey": credential.pubkey_hex,
                        },
                    }
                },
            )

        # Find the assignment — scan all per-job DBs is expensive, but the
        # worker-side flow normally knows the experiment_id (it just got
        # one from /assignments). Terminal experiments are skipped and the
        # body's assignment_id (workers ≥ v0.2.2) disambiguates exactly.
        experiment_id, per_job_db, assignment = _find_assignment(
            per_job_factory,
            unit_id,
            worker_id,
            experiment_repository=experiment_repository,
            assignment_id=body.assignment_id,
        )
        if assignment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "assignment_not_found",
                        "message": (f"no assignment for unit {unit_id!r} and worker {worker_id!r}"),
                    }
                },
            )
        if assignment.result_id is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "result_already_submitted",
                        "message": "this assignment already has a result attached",
                        "details": {
                            "assignment_id": assignment.assignment_id,
                            "existing_result_id": assignment.result_id,
                        },
                    }
                },
            )

        results_repo = ResultRepository(per_job_db)
        assignments_repo = AssignmentRepository(per_job_db)
        work_units_repo = WorkUnitRepository(per_job_db)

        # §9 #13a: VERIFY the worker's body signature before accepting the result
        # into the consensus set. Historically the body signature was stored but
        # not verified until receipt issuance; verifying here keeps an
        # unauthentic / tampered result out entirely, and (for a v1 result)
        # cryptographically binds the served-weights digest #13b enforces below.
        # Reconstructs the legacy (v0) or v1 canonical body per schema_version.
        if not verify_result_signature(
            worker_pubkey=body.worker_pubkey,
            signature_b64=body.worker_signature,
            unit_id=unit_id,
            completed_at=body.completed_at,
            exit_code=body.exit_code,
            payload=body.payload,
            schema_version=body.schema_version,
            served_weights=body.served_weights,
            ran_under=body.ran_under,
        ):
            assignments_repo.mark_refused(
                assignment_id=assignment.assignment_id,
                kind="worker_signature_invalid",
                reason="worker_signature does not verify over the canonical result body",
            )
            audit_repository.append(
                actor_class=CredentialClass.WORKER,
                actor_identifier=worker_id,
                action="result.worker_signature_invalid",
                resource_type="work_unit",
                resource_id=unit_id,
                payload={"experiment_id": experiment_id},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "error": {
                        "code": "worker_signature_invalid",
                        "message": (
                            "result rejected: worker_signature does not verify over the "
                            "canonical result body (§9 #13a)"
                        ),
                    }
                },
            )

        # A2 #32 (equal-trust flip activation): a v2 result SIGNS the containment it
        # ran under. If the worker ran WEAKER than the experiment requires, it has
        # signed an admission of non-compliance → reject + record provable
        # misconduct (charter: "sandbox violation" — the maintainer demote/suspend
        # lever). v0/v1 results carry no signed claim → no-op for the un-rolled
        # fleet. NB this catches honest non-compliance; a malicious worker would
        # sign the required level (a lie), but then the signed claim is on record
        # as the demotion evidence if a violation is later independently detected.
        if body.ran_under is not None:
            _exp = experiment_repository.get_by_id(experiment_id)
            _required = _exp.required_containment if _exp is not None else None
            if containment_rank(body.ran_under) < containment_rank(_required):
                assignments_repo.mark_refused(
                    assignment_id=assignment.assignment_id,
                    kind="containment_violation",
                    reason=(
                        f"worker signed ran_under={body.ran_under!r} but the experiment "
                        f"requires {_required!r}"
                    ),
                )
                # AUTO-QUARANTINE: the worker SIGNED an admission of running weaker
                # than required — provable misconduct, so the response is automated
                # (charter: a provable sandbox violation loses standing; distinct
                # from divergence, which must NEVER auto-penalize). The assignment
                # endpoint then refuses it work; reversible via unquarantine and it
                # surfaces for the maintainer's demote/suspend call. Best-effort:
                # an escalation hiccup must never mask the refusal/409.
                auto_quarantined = False
                try:
                    worker_repository.quarantine(
                        worker_id,
                        reason=(
                            f"containment_violation: signed ran_under={body.ran_under!r} "
                            f"< required {_required!r} (unit {unit_id})"
                        ),
                    )
                    auto_quarantined = True
                except Exception:
                    import logging

                    logging.getLogger(__name__).exception(
                        "auto-quarantine failed for worker %s after containment_violation",
                        worker_id,
                    )
                audit_repository.append(
                    actor_class=CredentialClass.WORKER,
                    actor_identifier=worker_id,
                    action="result.containment_violation",
                    resource_type="work_unit",
                    resource_id=unit_id,
                    payload={
                        "experiment_id": experiment_id,
                        "ran_under": body.ran_under,
                        "required_containment": _required,
                        "auto_quarantined": auto_quarantined,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": {
                            "code": "containment_violation",
                            "message": (
                                "result rejected: signed ran_under is weaker than the "
                                "experiment's required containment (A2 #32 — provable misconduct)"
                            ),
                            "details": {
                                "ran_under": body.ran_under,
                                "required_containment": _required,
                            },
                        }
                    },
                )

        # §9 #13a: a v1 result's served-weights digest is now signature-covered
        # (verified just above) — prefer it over the best-effort heartbeat
        # snapshot for both the environment leg and #13b enforcement.
        is_v1_result = (body.schema_version or 0) >= 1

        # EB-1 (§9 #47): snapshot the coordinator-asserted serving environment
        # at submission — the reproducibility triple's environment leg. Sourced
        # from the worker's last heartbeat-declared capabilities (what the
        # coordinator authoritatively knows); the richer worker-REPORTED
        # per-result environment (gguf digest) rides a future worker release.
        environment: dict[str, Any] | None = None
        worker_row = worker_repository.get_by_id(worker_id)
        served_digests: dict[str, str] | None = None
        if worker_row is not None:
            caps = worker_row.capabilities or {}
            served_digests = caps.get("served_model_digests")  # heartbeat (v0 fallback)
            # Attested (v1) digest preferred — it is per-result and signature-
            # bound; the heartbeat value is fleet-wide last-beat best-effort.
            snapshot_digests = body.served_weights if is_v1_result else served_digests
            snapshot = {
                # AUD-34 (A9 audit): the worker transmits its build under the
                # capabilities key `worker_version` (detect.py) — reading `version`
                # (a key the worker never sends) silently dropped the reproducibility
                # triple's worker-software leg from every result's environment.
                "worker_version": caps.get("worker_version"),
                "ollama_version": caps.get("ollama_version"),
                "served_models": caps.get("served_models"),
                "served_model_digests": snapshot_digests,  # M3 reproducibility leg
            }
            environment = {k: v for k, v in snapshot.items() if v is not None} or None

        # M3 / #13b (v0_2): when a manifest model pins `expected_gguf_sha256`, the
        # worker's served digest MUST match — else the declared model did not
        # provably run. A mismatch refuses the unit terminally for THIS worker
        # (excluded; re-offered to another eligible worker) + audits. Dormant
        # unless a manifest pins a digest AND the rolled worker reports one.
        if manifest_repository is not None:
            exp = experiment_repository.get_by_id(experiment_id)
            manifest = manifest_repository.get(exp.manifest_hash) if exp is not None else None
            # §9 #13b: enforce against the WORKER-SIGNED served_weights for a v1
            # result (anti-fabrication — covered by the verified signature);
            # fall back to the best-effort heartbeat snapshot for legacy v0.
            enforce_digests = body.served_weights if is_v1_result else served_digests
            mismatch = (
                served_weights_verdict(manifest.manifest_json, enforce_digests)
                if manifest is not None
                else None
            )
            if mismatch is not None:
                assignments_repo.mark_refused(
                    assignment_id=assignment.assignment_id,
                    kind="served_weights_mismatch",
                    reason=mismatch,
                )
                audit_repository.append(
                    actor_class=CredentialClass.WORKER,
                    actor_identifier=worker_id,
                    action="result.served_weights_mismatch",
                    resource_type="work_unit",
                    resource_id=unit_id,
                    payload={"experiment_id": experiment_id, "reason": mismatch},
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": {
                            "code": "served_weights_mismatch",
                            "message": (
                                "result rejected: the served model weights do not match the "
                                "manifest's declared digest (§9 #13b)"
                            ),
                            "details": {"reason": mismatch},
                        }
                    },
                )

        # D16.1 §7 (Inc 4): enforce the manifest's declared feature_schema on the
        # emitted payload. Under §7 the declared feature set is the ENTIRE
        # interpretability surface (raw outputs are never retained), so an
        # undeclared / out-of-bounds field is either a §7 leak or an
        # executor/schema mismatch. A CERTIFIED experiment REJECTS it (terminal
        # for the UNIT — the executor is the same certified code for every worker,
        # so re-offering would just rerun the fault; the maintainer is alerted via
        # the E14 needs-attention surface). A BYOT experiment FLAGS it (records +
        # accepts) so a new tenant sees mismatches without their run hard-failing.
        # Integrity gate → reject immediately, never debounce.
        exp_fs = experiment_repository.get_by_id(experiment_id)
        manifest_fs = (
            manifest_repository.get(exp_fs.manifest_hash)
            if manifest_repository is not None and exp_fs is not None
            else None
        )
        feature_schema = (
            manifest_fs.manifest_json.get("feature_schema") if manifest_fs is not None else None
        )
        # D20 (ratified 2026-07-06): raw-content live collection. `raw_response`
        # is a RESERVED key — permitted ONLY when the manifest declares capture,
        # and popped BEFORE schema conformance + persistence so it NEVER rests on
        # the coordinator (features persist as today; raw parks in the ephemeral
        # transit buffer for the R3 driver to collect during the run). If capture
        # is NOT declared, `raw_response` stays in the payload and conformance
        # rejects it as an undeclared §7 leak — no silent capture, ever.
        capture_raw = bool(
            manifest_fs is not None and (manifest_fs.manifest_json.get("capture") or {}).get("raw")
        )
        _raw_text: str | None = None
        _raw_sig: str | None = None
        if capture_raw and body.raw_response is not None:
            # AUD-26: new worker — raw arrives OUT of the signed payload with a
            # detached signature. Authenticate it before parking (never park
            # unauthenticated model text); the signed/stored payload is untouched,
            # so its worker signature verifies on export.
            if not (
                body.raw_signature
                and verify_raw_signature(
                    worker_pubkey=body.worker_pubkey,
                    signature_b64=body.raw_signature,
                    unit_id=unit_id,
                    raw_response=body.raw_response,
                )
            ):
                assignments_repo.mark_refused(
                    assignment_id=assignment.assignment_id,
                    kind="raw_signature_invalid",
                    reason="detached raw_signature does not verify over the raw content",
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={
                        "error": {
                            "code": "raw_signature_invalid",
                            "message": "raw_response present but raw_signature is missing/invalid",
                        }
                    },
                )
            _raw_text = body.raw_response
            _raw_sig = body.raw_signature
        elif capture_raw and isinstance(body.payload, dict) and "raw_response" in body.payload:
            # LEGACY (pre-AUD-26 worker): raw was signed INSIDE the payload. Pop it
            # so conformance + storage exclude it. NOTE: the stored signature was
            # taken over the FULL payload, so such a bundle's worker signature will
            # NOT verify on export — the AUD-26 defect, now confined to un-rolled
            # workers; a worker roll (out-of-payload raw) resolves it.
            popped = body.payload.pop("raw_response")
            if isinstance(popped, str):
                _raw_text = popped  # parked in the transit buffer after result_id is minted
        if feature_schema:
            violations = check_payload_conformance(feature_schema, body.payload)
            if violations:
                certified = bool(getattr(exp_fs, "certified", False))
                if receipt_index_repository is not None:
                    receipt_index_repository.record_schema_rejection(
                        experiment_id=experiment_id,
                        worker_id=worker_id,
                        worker_pubkey=body.worker_pubkey,
                        unit_id=unit_id,
                        certified=certified,
                        violations=violations,
                    )
                audit_repository.append(
                    actor_class=CredentialClass.WORKER,
                    actor_identifier=worker_id,
                    action="result.schema_violation",
                    resource_type="work_unit",
                    resource_id=unit_id,
                    payload={
                        "experiment_id": experiment_id,
                        "certified": certified,
                        "violations": violations[:20],
                    },
                )
                if certified:
                    assignments_repo.mark_refused(
                        assignment_id=assignment.assignment_id,
                        kind="schema_violation",
                        reason="; ".join(violations[:5]),
                    )
                    # Terminal for the UNIT, not just this worker (a code fault is
                    # systematic — every worker runs the same certified executor).
                    work_units_repo.mark_failed(unit_id)
                    # AUD-27: the unit is now terminal but the EXPERIMENT stays
                    # APPROVED, so already-submitted results from other workers on
                    # this unit will never earn a receipt. Record their terminal
                    # receipt_outcomes markers now (the D22-B every-result-gets-a-
                    # receipt-or-terminal-outcome contract) so they don't poll
                    # canonical-receipt 404 forever. Best-effort; the recurring
                    # settle sweep is the durable backstop for any straggler.
                    if receipt_index_repository is not None:
                        try:
                            _mark_terminal_unit_receiptless_results(
                                experiment_id=experiment_id,
                                per_job_db=per_job_db,
                                receipt_index_repository=receipt_index_repository,
                                only_unit_id=unit_id,
                            )
                        except Exception:
                            logger.exception(
                                "mark_failed: receiptless sweep failed exp=%s unit=%s",
                                experiment_id,
                                unit_id,
                            )
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail={
                            "error": {
                                "code": "schema_violation",
                                "message": (
                                    "result rejected: the emitted payload does not conform to "
                                    "the manifest's declared feature_schema (D16.1 §7)"
                                ),
                                "details": {"violations": violations[:20]},
                            }
                        },
                    )
                # BYOT: flagged + recorded above; fall through and accept the row.

        result = results_repo.insert(
            result_id=_generate_result_id(),
            unit_id=unit_id,
            worker_id=worker_id,
            worker_pubkey_hex=body.worker_pubkey,
            exit_code=body.exit_code,
            payload=body.payload,
            worker_signature=body.worker_signature,
            completed_at=body.completed_at,
            environment=environment,
            # §9 #13a: persist the worker-signed version + attested digest so the
            # receipt/attestation reconstructs the right canonical body and the
            # attested digest survives for evidence.
            schema_version=body.schema_version,
            served_weights=body.served_weights,
            # A2 #32: persist the worker-signed sandbox policy so issuance reads
            # the SIGNED containment (not the heartbeat capability) for trust.
            ran_under=body.ran_under,
        )
        assignments_repo.attach_result(assignment.assignment_id, result.result_id)
        # Serve-SUCCESS signal (rate-aware OOM ground truth, migration 0063): the worker just
        # DELIVERED a result, so it served the model at its usable size. Record it so a past
        # serve-OOM record for a worker this size is tempered — a fit-but-flaky model (serves
        # most of the time, OOMs only under memory pressure) is then not benched forever by one
        # OOM. Mirrors the OOM-record path in /refuse; best-effort, never disturbs acceptance.
        try:
            _sc_caps = getattr(worker_row, "capabilities", None) or {}
            _sc_usable = _sc_caps.get("usable_memory_gb") or _sc_caps.get("ram_total_gb")
            _sc_exp = experiment_repository.get_by_id(experiment_id)
            _sc_models = (
                (getattr(_sc_exp, "required_capabilities", None) or {}).get("models") or []
                if _sc_exp
                else []
            )
            if _sc_models and isinstance(_sc_usable, (int, float)):
                from auspexai_platform.db.repositories.model_serve_failures import (
                    ModelServeFailureRepository,
                )

                ModelServeFailureRepository(worker_repository.db).record_serve_success(
                    _sc_models[0], float(_sc_usable), now=datetime.now(UTC).isoformat()
                )
        except Exception:
            logger.debug("serve-success record failed (ignored)", exc_info=True)
        # D20: park the raw in the ephemeral transit buffer keyed by the now-minted
        # result_id — never persisted, R3-collectable during the run. AUD-26: also
        # park the detached signature + worker pubkey so the R3 driver can verify the
        # worker actually produced the collected raw.
        if _raw_text is not None and raw_transit is not None:
            import time as _time

            raw_transit.put(
                experiment_id=experiment_id,
                result_id=result.result_id,
                raw_text=_raw_text,
                raw_signature=_raw_sig,
                worker_pubkey=body.worker_pubkey,
                now=_time.monotonic(),
            )
        updated_unit, just_completed = work_units_repo.increment_completions(unit_id)

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="result.submit",
            resource_type="result",
            resource_id=result.result_id,
            payload={
                "unit_id": unit_id,
                "worker_id": worker_id,
                "exit_code": body.exit_code,
                "unit_status_after": updated_unit.status.value,
                "completions_so_far": updated_unit.completions_so_far,
                "replication_target": updated_unit.replication_target,
            },
        )

        # M8: live progress event — drives the dashboard/console progress bar
        # without polling. One per submission (so completions tick up live).
        if event_bus is not None:
            event_bus.publish(
                "unit.progress",
                experiment_id=experiment_id,
                data={
                    "unit_id": unit_id,
                    "unit_status": updated_unit.status.value,
                    "completions_so_far": updated_unit.completions_so_far,
                    "replication_target": updated_unit.replication_target,
                },
            )

        # M6e auto-complete: if this result completed the unit AND the
        # experiment was finalized AND no other non-completed units remain,
        # auto-transition the experiment to 'completed'. Only fires on
        # status=approved — paused experiments stay paused until resumed,
        # and the resume action re-checks.
        # M9 leg 3: gate on `just_completed` (the FIRST transition), not on the
        # completed status — so a late/extra result from a rejoined worker doesn't
        # re-issue receipts / re-promote consensus / re-emit the attestation.
        if just_completed:
            # M7c + M6e + M7-tail: issuance → consensus-promote → worker promotion →
            # auto-complete → attestation. Factored into finalize_completed_unit so the
            # C14 settle-sweep runs the IDENTICAL path. The submitting worker is the sole
            # promotion candidate here (unchanged behavior).
            finalize_completed_unit(
                unit_id=unit_id,
                experiment_id=experiment_id,
                updated_unit=updated_unit,
                per_job_db=per_job_db,
                promote_worker_ids=[worker_id],
                experiment_repository=experiment_repository,
                receipt_signing_key=receipt_signing_key,
                receipt_index_repository=receipt_index_repository,
                worker_repository=worker_repository,
                account_repository=account_repository,
                audit_repository=audit_repository,
                eligibility_thresholds=eligibility_thresholds,
                vouch_repository=vouch_repository,
                promotion_auto_t1_t2=promotion_auto_t1_t2,
                trust_model_policy_repository=trust_model_policy_repository,
                attestation_repository=attestation_repository,
                event_bus=event_bus,
                governance_footprint_builder=governance_footprint_builder,
                manifest_repository=manifest_repository,
                pre_registration_repository=pre_registration_repository,
            )

        return ResultSubmissionResponse(
            result_id=result.result_id,
            unit_id=unit_id,
            unit_status_after=updated_unit.status.value,
            completions_so_far=updated_unit.completions_so_far,
            replication_target=updated_unit.replication_target,
        )

    # ---- POST refuse --------------------------------------------------

    @router.post(
        "/workers/{worker_id}/assignments/{unit_id}/refuse",
        response_model=RefuseResponse,
        response_model_exclude_none=True,
    )
    async def refuse_assignment(
        worker_id: str,
        unit_id: str,
        body: RefuseRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> RefuseResponse:
        """Worker explicitly declines a previously-assigned unit. The
        assignment row is marked refused so the operator console can see
        the reason; the unit remains eligible for offer to other workers
        (per the scheduler's unit-state semantics).
        """
        _require_self_worker(credential, worker_id)

        experiment_id, per_job_db, assignment = _find_assignment(
            per_job_factory,
            unit_id,
            worker_id,
            experiment_repository=experiment_repository,
            assignment_id=body.assignment_id,
        )
        if assignment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "assignment_not_found",
                        "message": (f"no assignment for unit {unit_id!r} and worker {worker_id!r}"),
                    }
                },
            )

        assignments_repo = AssignmentRepository(per_job_db)
        try:
            updated = assignments_repo.mark_refused(
                assignment_id=assignment.assignment_id,
                kind=body.kind,
                reason=body.reason,
            )
        except AssignmentAlreadyResolvedError as exc:
            logger.warning(
                "refuse on already-resolved assignment %s: %s", assignment.assignment_id, exc
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "assignment_already_resolved",
                        "message": "this assignment has already been resolved",
                        "details": {
                            "assignment_id": assignment.assignment_id,
                            "has_result": assignment.result_id is not None,
                            "already_refused_at": (
                                assignment.refused_at.isoformat() if assignment.refused_at else None
                            ),
                        },
                    }
                },
            ) from exc

        # #1 learn-from-failures: a GPU-OOM refusal (Layer-1 "insufficient GPU memory
        # to serve <model>") is ground truth that this model does NOT fit a worker
        # with this much CAPACITY. Record it (at the worker's static usable budget, the
        # stable notion the catalog gates on) so the catalog stops labelling the model
        # "fits" for boxes this size. Best-effort — never disturbs the refusal.
        try:
            _rl = (body.reason or "").lower()
            if "insufficient gpu memory" in _rl or "out of memory" in _rl:
                _exp = experiment_repository.get_by_id(experiment_id)
                _models = (
                    (getattr(_exp, "required_capabilities", None) or {}).get("models") or []
                    if _exp
                    else []
                )
                _caps = getattr(worker_repository.get_by_id(worker_id), "capabilities", None) or {}
                _capacity = _caps.get("usable_memory_gb") or _caps.get("ram_total_gb")
                if _models and isinstance(_capacity, (int, float)):
                    from auspexai_platform.db.repositories.model_serve_failures import (
                        ModelServeFailureRepository,
                    )

                    ModelServeFailureRepository(worker_repository.db).record_oom(
                        _models[0], float(_capacity), now=datetime.now(UTC).isoformat()
                    )
        except Exception:
            logger.debug("serve-OOM record failed (ignored)", exc_info=True)

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="assignment.refuse",
            resource_type="assignment",
            resource_id=assignment.assignment_id,
            payload={
                "experiment_id": experiment_id,
                "unit_id": unit_id,
                "worker_id": worker_id,
                "kind": body.kind,
                "reason": body.reason,
            },
        )

        return RefuseResponse(
            assignment_id=updated.assignment_id,
            unit_id=updated.unit_id,
            refused_at=updated.refused_at,
            refused_kind=updated.refused_kind,
        )

    @router.post(
        "/workers/{worker_id}/serve-recovered",
        response_model=ServeRecoveredResponse,
        response_model_exclude_none=True,
    )
    async def serve_recovered(
        worker_id: str,
        body: ServeRecoveredRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ServeRecoveredResponse:
        """The worker's operator REMEDIATED a serve condition (freed memory / restarted the
        backend) after `model_id` OOM'd on it — recorded so THIS worker may retry the model
        despite the model-level OOM exclusion, before the 6h cooldown lifts (surgical recovery:
        one node's fix never re-offers the model to other, un-remediated nodes). A re-OOM writes
        a newer last_observed_at and the shadow lifts; a serve success tempers the shared record.
        Idempotent; best-effort audit."""
        _require_self_worker(credential, worker_id)
        from auspexai_platform.db.repositories.model_serve_failures import (
            ModelServeFailureRepository,
        )

        ModelServeFailureRepository(worker_repository.db).note_worker_recovered(
            worker_id, body.model_id, now=datetime.now(UTC).isoformat()
        )
        try:
            audit_repository.append(
                actor_class=CredentialClass.WORKER,
                actor_identifier=credential.pubkey_hex,
                action="worker.serve_recovered",
                resource_type="worker",
                resource_id=worker_id,
                payload={"model_id": body.model_id},
            )
        except Exception:
            logger.debug("serve-recovered audit failed (ignored)", exc_info=True)
        return ServeRecoveredResponse(worker_id=worker_id, model_id=body.model_id, recorded=True)

    # ---- GET prestage directives (M3b eager conductor) ----------------

    @router.get(
        "/workers/{worker_id}/prestage",
        response_model=PrestageResponse,
        response_model_exclude_none=True,
    )
    async def get_prestage(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> PrestageResponse:
        """Models the conductor wants this worker to pre-stage (pull ahead of
        assignment), so a model-gated experiment isn't bottlenecked on
        first-assignment pulls. The worker (auto-acquire on) pulls each via its M3
        path; the directive is marked acquired once the model appears in the
        worker's heartbeat inventory. Returns empty when the conductor isn't wired
        (`prestage_repository`/`manifest_repository` absent), the worker is
        retired/quarantined/paused, or nothing is under-supplied."""
        _require_self_worker(credential, worker_id)
        if prestage_repository is None or manifest_repository is None:
            return PrestageResponse(prestage=[])
        worker = worker_repository.get_by_id(worker_id)
        if worker is None or worker.retired_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no active worker with id {worker_id!r}",
                    }
                },
            )
        if worker.quarantined_at is not None or worker.paused_at is not None:
            return PrestageResponse(prestage=[])
        directives = plan_prestage_for_worker(
            worker,
            experiment_repository=experiment_repository,
            manifest_repository=manifest_repository,
            worker_repository=worker_repository,
            prestage_repository=prestage_repository,
            heartbeat_cutoff=heartbeat_cutoff(datetime.now(UTC)),
        )
        return PrestageResponse(
            prestage=[
                PrestageItem(model_id=d.model_id, hf_repo=d.hf_repo, hf_filename=d.hf_filename)
                for d in directives
            ]
        )

    return router


# ---- module-level helpers --------------------------------------------------


_TERMINAL_EXPERIMENT_STATUSES = ("aborted", "archived")


def _find_assignment(
    per_job_factory: PerJobDatabaseFactory,
    unit_id: str,
    worker_id: str,
    *,
    experiment_repository: ExperimentRepository | None = None,
    assignment_id: str | None = None,
):
    """Scan cached per-job DBs for an assignment matching (unit_id, worker_id).

    Returns (experiment_id, per_job_db, assignment) or (None, None, None).
    Hot DBs are cached by definition — a worker submitting a result just
    received the assignment from a recent GET, so the DB is in cache.

    §9 #46 D6 finding (2026-06-10): unit_ids are TENANT-CHOSEN and collide
    across experiments — the bare scan once matched (and accepted a result
    into) an ABORTED experiment's stale assignment. Two fixes here:
    - experiments in a terminal status (aborted/archived) are skipped, so a
      stale assignment can never receive a late result or refusal;
    - an explicit `assignment_id` (sent by workers ≥ v0.2.2) must match
      exactly, removing the ambiguity entirely.
    """
    for experiment_id, db in per_job_factory.iter_cached_dbs():
        if experiment_repository is not None:
            exp = experiment_repository.get_by_id(experiment_id)
            if exp is not None and exp.status in _TERMINAL_EXPERIMENT_STATUSES:
                continue
        repo = AssignmentRepository(db)
        assignment = repo.get_for_unit_and_worker(unit_id, worker_id)
        if assignment is None:
            continue
        if assignment_id is not None and assignment.assignment_id != assignment_id:
            continue
        return experiment_id, db, assignment
    return None, None, None


def _maybe_emit_completion_attestation(
    *,
    experiment_id: str,
    per_job_db,
    experiment_repository: ExperimentRepository,
    receipt_index_repository: ReceiptIndexRepository,
    signing_key: SigningKey,
    audit_repository: AuditRepository,
    attestation_repository: AttestationRepository | None = None,
    event_bus=None,
    governance_footprint_builder=None,
    pre_registration_repository=None,  # D16.2: bind the finding to its design
) -> None:
    """If the experiment is now COMPLETED, build + PERSIST (+ audit + emit) the
    canonical result-set completion attestation (#34 §6.3, M7-tail / A1).

    Persisting (A1) makes the attestation canonical — a stable id/bytes/anchor —
    and durable past per-job DB deletion (the on-demand GET re-derives the same
    root but would otherwise mint a fresh id each call and vanish with the
    per-job DB). Idempotent: a no-op once a final attestation is persisted, so it
    is safe to call from BOTH completion paths (result-submit + finalize-on-
    convergence) and on every late result. Best-effort — wrapped so it never
    blocks the result response; the on-demand GET canonicalizes lazily as a
    backstop."""
    experiment = experiment_repository.get_by_id(experiment_id)
    if experiment is None or experiment.status is not ExperimentStatus.COMPLETED:
        return
    if (
        attestation_repository is not None
        and attestation_repository.get_final(experiment_id) is not None
    ):
        return  # already canonical
    try:
        # Leaf membership from the AUTHORITATIVE per-job receipts table — the
        # control-DB receipt_index is a best-effort display cache whose write
        # failures are swallowed at issuance (signature-scope finding,
        # 2026-06-12). The recount guard below refuses to canonicalize a set
        # that diverges from the consensus table.
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=receipt_map_from_per_job(per_job_db)
        )
        try:
            assert_entries_cover_consensus(per_job_db, entries)
        except IncompleteAttestationSetError as e:
            audit_repository.append(
                actor_class=CredentialClass.SYSTEM,
                action="attestation.incomplete_set",
                resource_type="experiment",
                resource_id=experiment_id,
                payload={
                    "missing_units": e.missing_units,
                    "extra_units": e.extra_units,
                    "trigger": "auto_complete",
                },
            )
            raise
        emit_diverged = collect_diverged_units(per_job_db)
        # D16.2 (maximal tier): the submit-time pre-registration reference rides
        # the signed predicate — the finding is bound to the design it tested.
        prereg = (
            pre_registration_repository.get(experiment_id)
            if pre_registration_repository is not None
            else None
        )
        attestation = build_result_set_attestation(
            attestation_id=f"att-{secrets.token_urlsafe(9)}",
            tenant_experiment_label=experiment.tenant_experiment_label,
            tenant_id=experiment.tenant_id,
            entries=entries,
            signing_key=signing_key,
            rekor_client=None,
            diverged_units=emit_diverged,
            governance_footprint=(
                governance_footprint_builder(experiment, entries, emit_diverged, per_job_db)
                if governance_footprint_builder is not None
                else None
            ),
            pre_registration=prereg.predicate_ref() if prereg is not None else None,
            # AUD-30: re-derive each unit's basis from the receipts at sign time.
            quorum_by_unit=unit_quorum_by_unit(per_job_db),
        )
        if attestation_repository is not None:
            try:
                attestation_repository.insert(
                    attestation_id=attestation.attestation_id,
                    experiment_id=experiment_id,
                    tenant_id=attestation.tenant_id,
                    tenant_experiment_label=attestation.experiment_id,
                    merkle_root=attestation.merkle_root,
                    algorithm=attestation.algorithm,
                    unit_count=attestation.unit_count,
                    cose_signed_blob=attestation.cose_signed_blob,
                    signing_key_pubkey_hex=attestation.signing_key_pubkey_hex,
                    rekor_log_index=attestation.rekor_log_index,
                    rekor_entry_uuid=attestation.rekor_entry_uuid,
                    partial=attestation.partial,
                )
            except DuplicateAttestationError:
                # Another completion path persisted it first — that row is the
                # canonical one; don't double-audit/emit.
                return
        audit_repository.append(
            actor_class=CredentialClass.SYSTEM,
            action="attestation.emitted",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "attestation_id": attestation.attestation_id,
                "merkle_root": attestation.merkle_root,
                "unit_count": attestation.unit_count,
                "trigger": "auto_complete",
            },
        )
        if event_bus is not None:
            event_bus.publish(
                "attestation.issued",
                experiment_id=experiment_id,
                data={
                    "attestation_id": attestation.attestation_id,
                    "merkle_root": attestation.merkle_root,
                    "unit_count": attestation.unit_count,
                },
            )
    except Exception:
        import logging

        logging.getLogger(__name__).exception(
            "completion attestation emit failed for %s; the on-demand GET can rebuild it",
            experiment_id,
        )


def finalize_completed_unit(
    *,
    unit_id: str,
    experiment_id: str,
    updated_unit,
    per_job_db,
    promote_worker_ids: list[str],
    experiment_repository,
    receipt_signing_key,
    receipt_index_repository,
    worker_repository,
    account_repository,
    audit_repository,
    eligibility_thresholds,
    vouch_repository,
    promotion_auto_t1_t2,
    trust_model_policy_repository,
    attestation_repository=None,
    event_bus=None,
    governance_footprint_builder=None,
    manifest_repository=None,  # C7: resolves manifest_json so within_cell_tolerance reads its envelope
    pre_registration_repository=None,  # D16.2: bind the attestation to the pre-registered design
) -> None:
    """Post-completion processing for a unit that JUST transitioned to `completed`:
    issue receipts (best-effort), promote the consensus result, run the worker
    promotion check for each `promote_worker_ids`, auto-complete the experiment, and
    emit the result-set attestation.

    Factored verbatim out of the result-submit route so the C14 regime-2 settle-sweep
    runs the IDENTICAL sequence — one source of truth for the integrity path. The route
    passes the submitting worker as the sole `promote_worker_ids` (a 1-element loop ==
    today's behavior); the settle-sweep passes every agreeing contributor (whose receipts
    are minted here for the first time)."""
    try:
        experiment = experiment_repository.get_by_id(experiment_id)
        results = ResultRepository(per_job_db).list_for_unit(unit_id)
        receipt_repo = ReceiptRepository(per_job_db)
        # AUD-32 (A9 audit): never issue receipts/attestation for a unit whose
        # experiment already went terminal (aborted/archived) — the abort cascade
        # cancels + marks those receiptless instead. Defense-in-depth beside the
        # increment_completions flip guard; issuance must be grounded in an ACTIVE
        # experiment, not merely a non-None one.
        if experiment is not None and experiment.status not in (
            ExperimentStatus.ABORTED,
            ExperimentStatus.ARCHIVED,
        ):
            # C7: resolve the signed manifest so the reducer dispatch can read a
            # within_cell_tolerance envelope (None ⇒ the default hash-agreement).
            manifest_record = (
                manifest_repository.get(experiment.manifest_hash)
                if manifest_repository is not None
                else None
            )
            issuance_outcome = issue_receipts_for_completed_unit(
                work_unit=updated_unit,
                experiment=experiment,
                results=results,
                receipt_repo=receipt_repo,
                signing_key=receipt_signing_key,
                receipt_index_repo=receipt_index_repository,
                containment_resolver=lambda result: _result_ran_strict(worker_repository, result),
                attribution_resolver=lambda result: _result_account_opted_in(
                    worker_repository, account_repository, result
                ),
                manifest=(manifest_record.manifest_json if manifest_record is not None else None),
            )
            audit_repository.append(
                actor_class=CredentialClass.SYSTEM,
                action=(
                    "receipts.issue.agreed"
                    if issuance_outcome.agreement.agreed
                    else "receipts.issue.disagreed"
                ),
                resource_type="work_unit",
                resource_id=unit_id,
                payload={
                    "experiment_id": experiment_id,
                    "method": issuance_outcome.agreement.method,
                    "agreeing_workers": issuance_outcome.agreement.agreeing_workers,
                    "replication_target": updated_unit.replication_target,
                    "issued_receipt_ids": issuance_outcome.issued_receipt_ids,
                },
            )
            if event_bus is not None and issuance_outcome.issued_receipt_ids:
                # M8: live receipt event — the experiment's verifiable
                # work record just grew; dashboards update the count.
                event_bus.publish(
                    "receipt.issued",
                    experiment_id=experiment_id,
                    data={
                        "unit_id": unit_id,
                        "agreed": issuance_outcome.agreement.agreed,
                        "agreeing_workers": issuance_outcome.agreement.agreeing_workers,
                        "issued_receipt_ids": issuance_outcome.issued_receipt_ids,
                    },
                )
            if issuance_outcome.agreement.agreed and issuance_outcome.agreeing_result_ids:
                # M-Results: promote one AGREEING result to the durable T-C
                # consensus copy (hash-agreement: all agreeing are byte-identical;
                # within_cell_tolerance: an envelope member, never an outlier).
                # Deterministic pick (min) so re-runs are idempotent.
                consensus_result_id = min(issuance_outcome.agreeing_result_ids)
                ResultRepository(per_job_db).promote_consensus(unit_id, consensus_result_id)
                audit_repository.append(
                    actor_class=CredentialClass.SYSTEM,
                    action="results.consensus_promoted",
                    resource_type="work_unit",
                    resource_id=unit_id,
                    payload={
                        "experiment_id": experiment_id,
                        "result_id": consensus_result_id,
                    },
                )
                # C7 Inc 4: persist the tolerance-consensus evidence beside the
                # promotion — the durable record of HOW the unit agreed
                # (representative / spread / envelope-in-force / outlier count).
                # Raw replicas age off, so issuance time is the only chance.
                # Best-effort like the receipt index: never blocks completion —
                # a missing row degrades the unit to the legacy promoted-row
                # attestation leaf, it never falsifies anything.
                if issuance_outcome.tolerance_evidence is not None:
                    try:
                        ev = issuance_outcome.tolerance_evidence
                        UnitConsensusRepository(per_job_db).record(
                            unit_id=unit_id,
                            method=ev["method"],
                            representative=ev["representative"],
                            representative_hash=ev["representative_hash"],
                            spread=ev["spread"],
                            envelope=ev["envelope"],
                            agreeing_workers=ev["agreeing_workers"],
                            outlier_count=ev["outlier_count"],
                            outlier_result_hashes=ev.get("outlier_result_hashes"),
                        )
                    except Exception:
                        logger.exception(
                            "unit_consensus evidence write failed for unit %s — the unit "
                            "falls back to the promoted-replica attestation leaf",
                            unit_id,
                        )
            if issuance_outcome.issued_receipt_ids:
                for _promote_wid in promote_worker_ids:
                    _maybe_auto_promote(
                        worker_id=_promote_wid,
                        worker_repository=worker_repository,
                        account_repository=account_repository,
                        receipt_index_repository=receipt_index_repository,
                        eligibility_thresholds=eligibility_thresholds,
                        vouch_repository=vouch_repository,
                        audit_repository=audit_repository,
                        promotion_auto_t1_t2=promotion_auto_t1_t2,
                        equal_trust_enabled=(
                            trust_model_policy_repository.get().equal_trust_enabled
                            if trust_model_policy_repository is not None
                            else False
                        ),
                    )
    except Exception:
        import logging

        logging.getLogger(__name__).exception(
            "receipt issuance failed for unit %s; the unit stays "
            "completed but receipts may need re-issuance",
            unit_id,
        )

    _maybe_auto_complete(
        experiment_id=experiment_id,
        per_job_db=per_job_db,
        experiment_repository=experiment_repository,
        audit_repository=audit_repository,
        event_bus=event_bus,
    )
    # M7-tail: emit the result-set completion attestation when the experiment just
    # finished — a permanent, model-blind record of the final set's merkle root.
    _maybe_emit_completion_attestation(
        experiment_id=experiment_id,
        per_job_db=per_job_db,
        experiment_repository=experiment_repository,
        receipt_index_repository=receipt_index_repository,
        signing_key=receipt_signing_key,
        audit_repository=audit_repository,
        attestation_repository=attestation_repository,
        event_bus=event_bus,
        governance_footprint_builder=governance_footprint_builder,
        pre_registration_repository=pre_registration_repository,
    )


def _maybe_auto_complete(
    *,
    experiment_id: str,
    per_job_db,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    event_bus=None,
) -> None:
    """Auto-transition an experiment to COMPLETED iff it is APPROVED, all work
    units are 'completed', AND either:

      - submissions_finalized is True (the driver signaled "no more work"), or
      - the run reached its maintainer-set max_units cap (a clean quota end).

    The cap trigger makes wrap-up a coordinator responsibility that does not hang
    on a live driver reaching its finalize call: a driver that dies AT the cap no
    longer strands the run in APPROVED forever. A driver that dies BELOW the cap
    is a genuinely-short run — not completed here; the settle sweep auto-aborts it
    (it didn't meet the maintainer default). Paused experiments wait for resume.

    Called from the result-submission path after a unit transitions to completed.
    No-op when conditions aren't met. Logs an audit entry with actor_class=SYSTEM
    (M6e — coordinator-driven action class).
    """
    experiment = experiment_repository.get_by_id(experiment_id)
    if experiment is None:  # pragma: no cover — defensive
        return
    if experiment.status is not ExperimentStatus.APPROVED:
        return

    # Cheap check: any unit not yet completed?
    rows = per_job_db.execute("SELECT COUNT(*) AS n FROM work_units WHERE status != 'completed'")
    remaining = int(rows[0]["n"]) if rows else 0
    if remaining != 0:
        return
    trows = per_job_db.execute("SELECT COUNT(*) AS n FROM work_units")
    total_units = int(trows[0]["n"]) if trows else 0

    capped = reached_unit_cap(experiment.max_units, total_units)
    if not (experiment.submissions_finalized or capped):
        return
    trigger = "finalized" if experiment.submissions_finalized else "reached_max_units_cap"

    try:
        experiment_repository.update_status(
            experiment_id,
            ExperimentStatus.COMPLETED,
            actor_class=CredentialClass.SYSTEM,
        )
    except InvalidStatusTransitionError:  # pragma: no cover — guarded by checks above
        return

    audit_repository.append(
        actor_class=CredentialClass.SYSTEM,
        action="experiment.auto_complete",
        resource_type="experiment",
        resource_id=experiment_id,
        payload={"trigger": trigger},
    )
    if event_bus is not None:
        # M8: surface the coordinator-driven completion live, same shape as the
        # operator-driven `experiment.status` events from `_transition`.
        event_bus.publish(
            "experiment.status",
            experiment_id=experiment_id,
            data={
                "status": ExperimentStatus.COMPLETED.value,
                "from_status": ExperimentStatus.APPROVED.value,
                "actor_class": CredentialClass.SYSTEM.value,
                "trigger": "auto_complete",
            },
        )


def _maybe_auto_promote(
    *,
    worker_id: str,
    worker_repository: WorkerRepository,
    account_repository,
    receipt_index_repository: ReceiptIndexRepository,
    eligibility_thresholds,
    vouch_repository,
    audit_repository: AuditRepository,
    promotion_auto_t1_t2=None,
    equal_trust_enabled: bool = False,
) -> None:
    """Auto-promote T1→T2 when both gates are satisfied after receipt issuance.

    Called from the result-submission path after receipts are issued. No-op
    when any prerequisite is missing (no account binding, already T2+, gates
    not met). Logs an audit entry with actor_class=SYSTEM.

    `promotion_auto_t1_t2` is the §6.2 mode reader: () -> bool. When it returns
    False (the maintainer set `manual`), the coordinator never auto-promotes —
    the qualifying account waits in the promotion queue (the accounts-list
    readiness signal still flags it) for a maintainer click. Unwired (tests)
    defaults to auto, preserving the pre-toggle behavior.
    """
    if account_repository is None or eligibility_thresholds is None:
        return
    if promotion_auto_t1_t2 is not None and not promotion_auto_t1_t2():
        return

    worker = worker_repository.get_by_id(worker_id)
    if worker is None or worker.account_id is None:
        return

    account = account_repository.get_by_id(worker.account_id)
    if account is None or account.retired_at or account.suspended_at:
        return
    if account.trust_tier != int(TrustTier.T1_AUTHENTICATED):
        return

    from auspexai_platform.eligibility import compute_t2_eligibility

    active_vouches = []
    if vouch_repository is not None:
        active_vouches = vouch_repository.list_for_target(worker.account_id)

    # A4 firewall #3 floor: trust = DISTINCT UNITS the account corroborated, not
    # raw receipts — so an operator's N workers under one account can't farm the
    # T2 threshold by redundantly covering the same units.
    # firewall #1 (A2): post-flip, trust = STRICT-contained units, agreement AND
    # divergence equal (D7). OFF (default / unwired) = the current agreement-only count.
    corroborations, distinct_tenants = receipt_index_repository.account_corroboration_summary(
        worker.account_id, equal_trust_enabled=equal_trust_enabled
    )

    elig = compute_t2_eligibility(
        receipt_count=corroborations,
        distinct_tenants=distinct_tenants,
        thresholds=eligibility_thresholds,
        account=account,
        active_vouches=active_vouches,
    )

    if not elig.ready_for_human_review:
        return

    try:
        account_repository.promote(
            worker.account_id,
            target_tier=TrustTier.T2_TRUSTED,
            set_by_class=CredentialClass.SYSTEM,
        )
        worker_repository.update_tier_for_account(
            worker.account_id, trust_tier=TrustTier.T2_TRUSTED
        )
    except Exception:
        import logging

        logging.getLogger(__name__).exception(
            "auto-promote failed for account %s", worker.account_id
        )
        return

    audit_repository.append(
        actor_class=CredentialClass.SYSTEM,
        action="account.auto_promote",
        resource_type="account",
        resource_id=worker.account_id,
        payload={
            "old_tier": int(TrustTier.T1_AUTHENTICATED),
            "new_tier": int(TrustTier.T2_TRUSTED),
            "trigger": "receipt_breadth_age_and_identity_gate_satisfied",
            "corroborations": corroborations,  # A4: distinct units, not raw receipts
            "distinct_tenants": distinct_tenants,
            "account_age_days": elig.actuals["account_age_days"],
            "identity_gate_method": elig.identity_gate.method,
        },
    )
