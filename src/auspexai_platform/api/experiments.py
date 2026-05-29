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

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.repositories import (
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
)
from auspexai_platform.db.repositories.experiments import (
    DuplicateExperimentLabelError,
    InvalidStatusTransitionError,
)
from auspexai_platform.db.repositories.manifests import DuplicateManifestError
from auspexai_platform.exposure import ExposureTag, filter_for_credential

# ---- response models -------------------------------------------------------


class ExperimentResponse(BaseModel):
    """Wire shape for an experiment. Fields are Optional so the exposure
    filter can mask non-visible ones."""

    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    tenant_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    status: Annotated[ExperimentStatus | None, ExposureTag.PUBLIC] = None
    submitted_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    started_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    completed_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    submissions_finalized: Annotated[bool | None, ExposureTag.PUBLIC] = None
    last_action_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    last_action_by_class: Annotated[str | None, ExposureTag.PUBLIC] = None
    tenant_experiment_label: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    manifest_hash: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    revision: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    error_summary: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    integrity_policy: Annotated[str | None, ExposureTag.PUBLIC] = None
    max_unit_duration_seconds: Annotated[int | None, ExposureTag.PUBLIC] = None
    max_units: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    max_concurrent_assignments: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    max_payload_bytes: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None


class ExperimentListResponse(BaseModel):
    experiments: Annotated[list[ExperimentResponse] | None, ExposureTag.PUBLIC] = None


class ExperimentSubmissionRequest(BaseModel):
    """POST /api/v0/experiments body. Manifest + ManifestSignature."""

    manifest: dict[str, Any] = Field(description="Manifest body (opaque to v0)")
    signature: dict[str, Any] = Field(description="SDK ManifestSignature object")


# ---- helpers ---------------------------------------------------------------


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
        max_unit_duration_seconds=experiment.max_unit_duration_seconds,
        max_units=experiment.max_units,
        max_concurrent_assignments=experiment.max_concurrent_assignments,
        max_payload_bytes=experiment.max_payload_bytes,
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


# ---- router ----------------------------------------------------------------


def build_router(
    credential_dep,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
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
        if not credential.is_researcher():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_required",
                        "message": "experiment submission requires a researcher credential",
                        "details": {"credential_class": credential.kind.value},
                    }
                },
            )

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
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_manifest",
                        "message": "an identical manifest is already stored",
                        "details": {"db_error": str(e)},
                    }
                },
            ) from e

        try:
            experiment = experiment_repository.create(
                tenant_id=manifest_tenant,
                tenant_experiment_label=manifest_label,
                manifest_hash=manifest.manifest_hash,
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

        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.submit",
            resource_type="experiment",
            resource_id=experiment.experiment_id,
            payload={
                "tenant_experiment_label": experiment.tenant_experiment_label,
                "manifest_hash": experiment.manifest_hash,
            },
        )

        return filter_for_credential(
            _to_response(experiment),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    @router.get(
        "/experiments",
        response_model=ExperimentListResponse,
        response_model_exclude_none=True,
    )
    async def list_experiments(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentListResponse:
        experiments = experiment_repository.list_all()
        filtered = [
            filter_for_credential(
                _to_response(e),
                credential,
                resource_tenant_id=e.tenant_id,
            )
            for e in experiments
        ]
        return ExperimentListResponse(experiments=filtered)

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
        return filter_for_credential(
            _to_response(experiment),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/approve",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def approve_experiment(
        experiment_id: str,
        integrity_policy: str | None = None,
        max_unit_duration_seconds: int | None = None,
        max_units: int | None = None,
        max_concurrent_assignments: int | None = None,
        max_payload_bytes: int | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        require_maintainer(credential)
        if integrity_policy is not None:
            from auspexai_platform.db.models import IntegrityPolicy

            try:
                policy = IntegrityPolicy(integrity_policy)
            except ValueError:
                raise HTTPException(
                    status_code=422,
                    detail=f"invalid integrity_policy: {integrity_policy!r}; "
                    f"must be one of: standard, high, trusted",
                ) from None
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
        )

    @router.post(
        "/experiments/{experiment_id}/actions/abort",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def abort_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.ABORTED,
            credential=credential,
            allow_researcher=True,
            action="experiment.abort",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
        )

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
        return filter_for_credential(
            _to_response(updated),
            credential,
            resource_tenant_id=updated.tenant_id,
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
) -> ExperimentResponse:
    """Common path for the action endpoints. Authorization + transition +
    audit + response filter."""
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
        payload={"from_status": experiment.status.value, "to_status": new_status.value},
    )
    return filter_for_credential(
        _to_response(updated),
        credential,
        resource_tenant_id=updated.tenant_id,
    )
