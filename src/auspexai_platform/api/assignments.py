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
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_worker
from auspexai_platform.db.models import ExperimentStatus, TrustTier, WorkUnitStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
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
from auspexai_platform.db.repositories.experiments import (
    InvalidStatusTransitionError,
)
from auspexai_platform.exposure import ExposureTag
from auspexai_platform.receipts import (
    ReceiptRepository,
    SigningKey,
    issue_receipts_for_completed_unit,
)
from auspexai_platform.scheduler import Scheduler

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
    reason: str = Field(
        max_length=2048,
        description="Free-form human-readable detail (operator-visible).",
    )


class RefuseResponse(BaseModel):
    assignment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    refused_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    refused_kind: Annotated[str | None, ExposureTag.PUBLIC] = None


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
            # network with no assignments. Reason text intentionally NOT
            # included in the response — that's operator-only per the
            # WorkerResponse exposure-tag config.
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

        work_units_repo.mark_in_progress(pick.work_unit.unit_id)

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="assignment.create",
            resource_type="assignment",
            resource_id=assignment.assignment_id,
            payload={
                "experiment_id": pick.experiment_id,
                "unit_id": pick.work_unit.unit_id,
                "worker_id": worker.worker_id,
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
        # one from /assignments). For M6d we don't take experiment_id in
        # the URL — we scan. M6d-polish or M8 may add a hint header.
        experiment_id, per_job_db, assignment = _find_assignment(
            per_job_factory, unit_id, worker_id
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

        result = results_repo.insert(
            result_id=_generate_result_id(),
            unit_id=unit_id,
            worker_id=worker_id,
            worker_pubkey_hex=body.worker_pubkey,
            exit_code=body.exit_code,
            payload=body.payload,
            worker_signature=body.worker_signature,
            completed_at=body.completed_at,
        )
        assignments_repo.attach_result(assignment.assignment_id, result.result_id)
        updated_unit = work_units_repo.increment_completions(unit_id)

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

        # M6e auto-complete: if this result completed the unit AND the
        # experiment was finalized AND no other non-completed units remain,
        # auto-transition the experiment to 'completed'. Only fires on
        # status=approved — paused experiments stay paused until resumed,
        # and the resume action re-checks.
        if updated_unit.status is WorkUnitStatus.COMPLETED:
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
            per_job_factory, unit_id, worker_id
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

    return router


# ---- module-level helpers --------------------------------------------------


def _find_assignment(
    per_job_factory: PerJobDatabaseFactory,
    unit_id: str,
    worker_id: str,
):
    """Scan cached per-job DBs for an assignment matching (unit_id, worker_id).

    Returns (experiment_id, per_job_db, assignment) or (None, None, None).
    Hot DBs are cached by definition — a worker submitting a result just
    received the assignment from a recent GET, so the DB is in cache.
    Cold-load (post-restart) is rare; M8 may replace this with an indexed
    lookup once the control DB tracks assignment→experiment_id.
    """
    for experiment_id, db in per_job_factory.iter_cached_dbs():
        repo = AssignmentRepository(db)
        assignment = repo.get_for_unit_and_worker(unit_id, worker_id)
        if assignment is not None:
            return experiment_id, db, assignment
    return None, None, None


def _maybe_auto_complete(
    *,
    experiment_id: str,
    per_job_db,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
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
