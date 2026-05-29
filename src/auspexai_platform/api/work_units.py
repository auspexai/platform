"""Work-unit routes — /api/v0/experiments/{experiment_id}/work-units.

  POST  …/work-units                         — researcher; batch submit
  GET   …/work-units                         — list (filtered)
  GET   …/work-units/{unit_id}               — detail

Authorization model mirrors experiment-detail: researchers see/write only
their own tenant's work units; maintainers see all.

Validation on submit (per SDK schemas/workunit_v0_1.json):
  - experiment.status in {approved, paused} (cannot submit while
    submitted/aborted/completed/archived)
  - body.tenant_id == credential.tenant_id (researcher only)
  - work_unit.tenant_id == experiment.tenant_id
  - work_unit.experiment_id == experiment.tenant_experiment_label
    (the body's `experiment_id` is the tenant's label per the SDK schema,
    not the coordinator's `exp-<id>`)
  - work_unit.manifest_sha256 == experiment.manifest_hash
    (per §5.14: forecloses mid-flight manifest swap)
  - unit_ids unique within batch and not previously submitted

The per-job DB is created lazily on the first successful submission for
this experiment (see `PerJobDatabaseFactory.get_or_create`). Lookups
return 404 if no per-job DB exists yet (no submissions ever).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import ExperimentStatus, WorkUnitStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AuditRepository,
    ExperimentRepository,
    WorkUnitRepository,
)
from auspexai_platform.db.repositories.work_units import DuplicateWorkUnitError
from auspexai_platform.exposure import ExposureTag, filter_for_credential

# ---- request / response models --------------------------------------------


class WorkUnitEnvelope(BaseModel):
    """SDK work-unit envelope (workunit_v0_1.json) — subset coordinator
    validates. Extra fields (schema_version, created_at) are accepted but
    ignored; the coordinator records its own created_at on the row."""

    unit_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    tenant_id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    experiment_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload: dict[str, Any] = Field(
        description="Tenant-defined work content; opaque to the coordinator"
    )


class WorkUnitSubmissionRequest(BaseModel):
    work_units: list[WorkUnitEnvelope] = Field(
        min_length=1,
        description="One or more work-unit envelopes",
    )


class WorkUnitResponse(BaseModel):
    """Wire shape for a single work unit. All fields Optional so the
    exposure filter can mask non-visible ones."""

    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    status: Annotated[str | None, ExposureTag.PUBLIC] = None
    replication_target: Annotated[int | None, ExposureTag.PUBLIC] = None
    completions_so_far: Annotated[int | None, ExposureTag.PUBLIC] = None
    created_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    payload: Annotated[dict[str, Any] | None, ExposureTag.TENANT_SCOPED] = None


class WorkUnitListResponse(BaseModel):
    work_units: Annotated[list[WorkUnitResponse] | None, ExposureTag.PUBLIC] = None
    counts_by_status: Annotated[dict[str, int] | None, ExposureTag.PUBLIC] = None


class WorkUnitSubmissionResponse(BaseModel):
    submitted_unit_ids: Annotated[list[str] | None, ExposureTag.PUBLIC] = None
    count: Annotated[int | None, ExposureTag.PUBLIC] = None


# ---- helpers --------------------------------------------------------------


def _unit_to_response(unit) -> WorkUnitResponse:
    return WorkUnitResponse(
        unit_id=unit.unit_id,
        status=unit.status.value,
        replication_target=unit.replication_target,
        completions_so_far=unit.completions_so_far,
        created_at=unit.created_at,
        payload=unit.payload,
    )


def _load_experiment_or_404(
    experiment_id: str,
    experiment_repository: ExperimentRepository,
):
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
    return experiment


def _check_view_authz(credential: Credential, experiment) -> None:
    """Tenant-private (researcher_dashboard_design.md §3): a non-owning
    researcher / anonymous caller gets the same `experiment_not_found` 404 as a
    genuinely-absent experiment, so work-units never confirm an experiment id
    exists. Maintainer sees all; owning-tenant researcher sees its own."""
    if credential.is_maintainer():
        return
    if credential.is_researcher() and credential.tenant_id == experiment.tenant_id:
        return
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": {
                "code": "experiment_not_found",
                "message": f"no experiment with id {experiment.experiment_id!r}",
                "details": {"experiment_id": experiment.experiment_id},
            }
        },
    )


# ---- router ---------------------------------------------------------------


def build_router(
    credential_dep,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    per_job_factory: PerJobDatabaseFactory,
) -> APIRouter:
    router = APIRouter()

    # ---- POST submit batch ---------------------------------------------

    @router.post(
        "/experiments/{experiment_id}/work-units",
        response_model=WorkUnitSubmissionResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_work_units(
        experiment_id: str,
        body: WorkUnitSubmissionRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkUnitSubmissionResponse:
        if not credential.is_researcher():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_required",
                        "message": "work-unit submission requires a researcher credential",
                        "details": {"credential_class": credential.kind.value},
                    }
                },
            )

        experiment = _load_experiment_or_404(experiment_id, experiment_repository)

        if experiment.tenant_id != credential.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "experiment_tenant_mismatch",
                        "message": (
                            "this experiment belongs to a different tenant than the "
                            "signing credential"
                        ),
                        "details": {
                            "experiment_tenant": experiment.tenant_id,
                            "credential_tenant": credential.tenant_id,
                        },
                    }
                },
            )

        if experiment.status not in {ExperimentStatus.APPROVED, ExperimentStatus.PAUSED}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "experiment_not_open_for_submissions",
                        "message": (
                            f"experiment is {experiment.status.value}; work units "
                            "can only be submitted while approved or paused"
                        ),
                        "details": {"experiment_status": experiment.status.value},
                    }
                },
            )

        if experiment.submissions_finalized:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "submissions_finalized",
                        "message": (
                            "submissions for this experiment have been finalized; "
                            "no new work units can be added"
                        ),
                        "details": {"experiment_id": experiment.experiment_id},
                    }
                },
            )

        # Per-unit validation.
        seen_ids: set[str] = set()
        for unit in body.work_units:
            if unit.tenant_id != experiment.tenant_id:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "work_unit_tenant_mismatch",
                            "message": (
                                f"work unit {unit.unit_id!r} has tenant_id "
                                f"{unit.tenant_id!r} but experiment belongs to "
                                f"{experiment.tenant_id!r}"
                            ),
                            "details": {"unit_id": unit.unit_id},
                        }
                    },
                )
            if unit.experiment_id != experiment.tenant_experiment_label:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "work_unit_experiment_label_mismatch",
                            "message": (
                                f"work unit {unit.unit_id!r} references "
                                f"experiment label {unit.experiment_id!r} but the "
                                f"experiment's tenant label is "
                                f"{experiment.tenant_experiment_label!r}"
                            ),
                            "details": {"unit_id": unit.unit_id},
                        }
                    },
                )
            if unit.manifest_sha256 != experiment.manifest_hash:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "work_unit_manifest_mismatch",
                            "message": (
                                f"work unit {unit.unit_id!r} references manifest "
                                f"{unit.manifest_sha256!r} but the experiment is "
                                f"bound to {experiment.manifest_hash!r} (§5.14 "
                                "manifest-swap protection)"
                            ),
                            "details": {"unit_id": unit.unit_id},
                        }
                    },
                )
            if unit.unit_id in seen_ids:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "duplicate_unit_id_in_batch",
                            "message": (
                                f"unit_id {unit.unit_id!r} appears more than once in this batch"
                            ),
                            "details": {"unit_id": unit.unit_id},
                        }
                    },
                )
            seen_ids.add(unit.unit_id)

        # ---- resource bounds enforcement (set by Maintainer at approval) ----
        from auspexai_platform.db.models import INTEGRITY_POLICY_REPLICATION

        if experiment.max_payload_bytes is not None:
            import json as _json

            for unit in body.work_units:
                payload_size = len(_json.dumps(unit.payload).encode("utf-8"))
                if payload_size > experiment.max_payload_bytes:
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "error": {
                                "code": "payload_too_large",
                                "message": (
                                    f"work unit {unit.unit_id!r} payload is {payload_size} bytes; "
                                    f"experiment limit is {experiment.max_payload_bytes} bytes"
                                ),
                                "details": {"unit_id": unit.unit_id, "size": payload_size},
                            }
                        },
                    )

        if experiment.max_units is not None:
            per_job_db_check = per_job_factory.get(experiment_id)
            existing_count = 0
            if per_job_db_check is not None:
                existing_units = WorkUnitRepository(per_job_db_check).list_all()
                existing_count = len(existing_units)
            if existing_count + len(body.work_units) > experiment.max_units:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error": {
                            "code": "max_units_exceeded",
                            "message": (
                                f"submitting {len(body.work_units)} units would exceed "
                                f"the experiment limit of {experiment.max_units} "
                                f"(currently {existing_count} submitted)"
                            ),
                        }
                    },
                )

        replication_target = INTEGRITY_POLICY_REPLICATION.get(experiment.integrity_policy, 3)

        per_job_db = per_job_factory.get_or_create(experiment_id)
        repo = WorkUnitRepository(per_job_db)
        try:
            inserted = repo.submit_batch(
                [{"unit_id": u.unit_id, "payload": u.payload} for u in body.work_units],
                replication_target=replication_target,
            )
        except DuplicateWorkUnitError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "unit_id_already_submitted",
                        "message": (
                            "one or more unit_ids in this batch were already "
                            "submitted for this experiment"
                        ),
                        "details": {"db_error": str(e)},
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="work_units.submit_batch",
            resource_type="experiment",
            resource_id=experiment.experiment_id,
            payload={"unit_count": len(inserted)},
        )

        return filter_for_credential(
            WorkUnitSubmissionResponse(
                submitted_unit_ids=[u.unit_id for u in inserted],
                count=len(inserted),
            ),
            credential,
        )

    # ---- GET list ------------------------------------------------------

    @router.get(
        "/experiments/{experiment_id}/work-units",
        response_model=WorkUnitListResponse,
        response_model_exclude_none=True,
    )
    async def list_work_units(
        experiment_id: str,
        status_filter: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkUnitListResponse:
        experiment = _load_experiment_or_404(experiment_id, experiment_repository)
        _check_view_authz(credential, experiment)

        if status_filter is not None:
            try:
                status_enum = WorkUnitStatus(status_filter)
            except ValueError as e:
                raise HTTPException(
                    status_code=422,  # UNPROCESSABLE_CONTENT
                    detail={
                        "error": {
                            "code": "unknown_status_filter",
                            "message": (
                                f"unknown status {status_filter!r}; valid: "
                                f"{[s.value for s in WorkUnitStatus]}"
                            ),
                            "details": {"status_filter": status_filter},
                        }
                    },
                ) from e
        else:
            status_enum = None

        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            # No work units ever submitted for this experiment.
            return WorkUnitListResponse(work_units=[], counts_by_status={})

        repo = WorkUnitRepository(per_job_db)
        units = repo.list_all(status=status_enum)
        counts = repo.count_by_status()
        return WorkUnitListResponse(
            work_units=[
                filter_for_credential(
                    _unit_to_response(u),
                    credential,
                    resource_tenant_id=experiment.tenant_id,
                )
                for u in units
            ],
            counts_by_status=counts,
        )

    # ---- GET detail ----------------------------------------------------

    @router.get(
        "/experiments/{experiment_id}/work-units/{unit_id}",
        response_model=WorkUnitResponse,
        response_model_exclude_none=True,
    )
    async def get_work_unit(
        experiment_id: str,
        unit_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkUnitResponse:
        experiment = _load_experiment_or_404(experiment_id, experiment_repository)
        _check_view_authz(credential, experiment)

        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "work_unit_not_found",
                        "message": f"no work unit with id {unit_id!r}",
                        "details": {"unit_id": unit_id},
                    }
                },
            )
        repo = WorkUnitRepository(per_job_db)
        unit = repo.get_by_unit_id(unit_id)
        if unit is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "work_unit_not_found",
                        "message": f"no work unit with id {unit_id!r}",
                        "details": {"unit_id": unit_id},
                    }
                },
            )
        return filter_for_credential(
            _unit_to_response(unit),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    return router
