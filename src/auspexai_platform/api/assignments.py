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

**The body-level worker_signature is stored but NOT verified in M6d.**
The HTTP-level RFC 9421 signature on the request is the M6d acceptance
proof. M7's receipt issuance will re-verify the body signature when
binding it into a signed receipt; that's the right place to ratify the
body chain since receipts are what external verifiers consume.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_worker
from auspexai_platform.db.models import ExperimentStatus, TrustTier
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    AttestationRepository,
    AuditRepository,
    ExperimentRepository,
    ReceiptIndexRepository,
    ResultRepository,
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
from auspexai_platform.receipts import (
    ReceiptRepository,
    SigningKey,
    issue_receipts_for_completed_unit,
)
from auspexai_platform.receipts.attestation import (
    IncompleteAttestationSetError,
    assert_entries_cover_consensus,
    build_result_set_attestation,
    collect_result_set_entries,
    receipt_map_from_per_job,
)
from auspexai_platform.scheduler import Scheduler, reoffer_eligible
from auspexai_platform.scheduler.conductor import plan_prestage_for_worker
from auspexai_platform.worker_status import heartbeat_cutoff

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
    manifest_repository=None,  # M3b conductor: read acquisition coords from the manifest
    prestage_repository=None,  # M3b conductor: the model_prestage table
    attestation_repository: AttestationRepository | None = None,  # A1: persist on complete
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
            return AssignmentResponse(work_unit=None)

        per_job_db = per_job_factory.get_or_create(pick.experiment_id)
        assignments_repo = AssignmentRepository(per_job_db)
        work_units_repo = WorkUnitRepository(per_job_db)

        # §2.1 #8 (dispatch-retry): the scheduler may pick a unit this worker
        # previously refused for a *retryable* reason (env/transient failure
        # under the attempt cap). In that case an assignment row already exists
        # (refused) — re-arm it rather than INSERT into the UNIQUE (unit,worker)
        # slot. A fresh pairing has no row and takes the create path.
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

        # EB-1 (§9 #47): snapshot the coordinator-asserted serving environment
        # at submission — the reproducibility triple's environment leg. Sourced
        # from the worker's last heartbeat-declared capabilities (what the
        # coordinator authoritatively knows); the richer worker-REPORTED
        # per-result environment (gguf digest) rides a future worker release.
        environment: dict[str, Any] | None = None
        worker_row = worker_repository.get_by_id(worker_id)
        if worker_row is not None:
            caps = worker_row.capabilities or {}
            snapshot = {
                "worker_version": caps.get("version"),
                "ollama_version": caps.get("ollama_version"),
                "served_models": caps.get("served_models"),
            }
            environment = {k: v for k, v in snapshot.items() if v is not None} or None

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
        )
        assignments_repo.attach_result(assignment.assignment_id, result.result_id)
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
            # M7c: hash_agreement reducer + receipt issuance. Best-effort
            # from the route's perspective — if it fails, the unit stays
            # `completed` (it really is done from a scheduling standpoint)
            # and the operator can re-issue receipts manually. Receipt
            # issuance is wrapped in a broad try/except so a bug here
            # never blocks the M6d response.
            try:
                experiment = experiment_repository.get_by_id(experiment_id)
                results = ResultRepository(per_job_db).list_for_unit(unit_id)
                receipt_repo = ReceiptRepository(per_job_db)
                if experiment is not None:
                    issuance_outcome = issue_receipts_for_completed_unit(
                        work_unit=updated_unit,
                        experiment=experiment,
                        results=results,
                        receipt_repo=receipt_repo,
                        signing_key=receipt_signing_key,
                        receipt_index_repo=receipt_index_repository,
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
                    if issuance_outcome.agreement.agreed and results:
                        # M-Results: promote one agreed result to the durable T-C
                        # consensus copy (all agreeing results are byte-identical;
                        # the rest are T-X replicas that age off first). Deterministic
                        # pick so re-runs are idempotent.
                        consensus_result_id = min(r.result_id for r in results)
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
                    if issuance_outcome.issued_receipt_ids:
                        _maybe_auto_promote(
                            worker_id=worker_id,
                            worker_repository=worker_repository,
                            account_repository=account_repository,
                            receipt_index_repository=receipt_index_repository,
                            eligibility_thresholds=eligibility_thresholds,
                            vouch_repository=vouch_repository,
                            audit_repository=audit_repository,
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
            # M7-tail: emit the result-set completion attestation when the
            # experiment just finished — a permanent, model-blind record of the
            # final set's merkle root at completion (the on-demand GET stays the
            # canonical fetch; this anchors it without waiting for a caller).
            _maybe_emit_completion_attestation(
                experiment_id=experiment_id,
                per_job_db=per_job_db,
                experiment_repository=experiment_repository,
                receipt_index_repository=receipt_index_repository,
                signing_key=receipt_signing_key,
                audit_repository=audit_repository,
                attestation_repository=attestation_repository,
                event_bus=event_bus,
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
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "assignment_already_resolved",
                        "message": str(exc),
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
        attestation = build_result_set_attestation(
            attestation_id=f"att-{secrets.token_urlsafe(9)}",
            tenant_experiment_label=experiment.tenant_experiment_label,
            tenant_id=experiment.tenant_id,
            entries=entries,
            signing_key=signing_key,
            rekor_client=None,
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


def _maybe_auto_complete(
    *,
    experiment_id: str,
    per_job_db,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    event_bus=None,
) -> None:
    """Auto-transition an experiment to COMPLETED iff:

      - submissions_finalized is True (researcher has signaled "no more work")
      - all work units are in 'completed' status
      - experiment status is currently APPROVED (paused experiments wait for resume)

    Called from the result-submission path after a unit transitions to
    completed. No-op when conditions aren't met. Logs an audit entry with
    actor_class=SYSTEM (M6e — coordinator-driven action class).
    """
    experiment = experiment_repository.get_by_id(experiment_id)
    if experiment is None:  # pragma: no cover — defensive
        return
    if experiment.status is not ExperimentStatus.APPROVED:
        return
    if not experiment.submissions_finalized:
        return

    # Cheap check: any unit not yet completed?
    rows = per_job_db.execute("SELECT COUNT(*) AS n FROM work_units WHERE status != 'completed'")
    remaining = int(rows[0]["n"]) if rows else 0
    if remaining != 0:
        return

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
        payload={"trigger": "all_units_completed_and_finalized"},
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
) -> None:
    """Auto-promote T1→T2 when both gates are satisfied after receipt issuance.

    Called from the result-submission path after receipts are issued. No-op
    when any prerequisite is missing (no account binding, already T2+, gates
    not met). Logs an audit entry with actor_class=SYSTEM.
    """
    if account_repository is None or eligibility_thresholds is None:
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

    entries = receipt_index_repository.list_for_account(worker.account_id)
    distinct_experiments = len({e.experiment_id for e in entries})

    elig = compute_t2_eligibility(
        receipt_count=len(entries),
        distinct_experiments=distinct_experiments,
        thresholds=eligibility_thresholds,
        account=account,
        active_vouches=active_vouches,
    )

    if not elig.ready_for_human_review:
        return

    try:
        account_repository.promote(worker.account_id, target_tier=TrustTier.T2_TRUSTED)
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
            "trigger": "receipt_threshold_and_identity_gate_satisfied",
            "receipt_count": len(entries),
            "distinct_experiments": distinct_experiments,
            "identity_gate_method": elig.identity_gate.method,
        },
    )
