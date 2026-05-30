"""Experiment-activity rollup endpoint (R-D3, tenant-scoped anonymized read).

GET /api/v0/experiments/{experiment_id}/activity — an anonymized liveness
rollup for one experiment: the "is my experiment really running?" signal for
the researcher dashboard. Returns a distinct active-contributor *count* (no
worker identities), the work-unit status breakdown, the latest-activity
timestamp, and replication fill.

Worker identity is never surfaced here: third-party volunteers stay
aggregate-only per the volunteer-anonymity rule (principles §5.9 / §11), and
own-account non-anonymized enrichment is a later step that needs the §8.2
account linkage. Every field is an aggregate count or a timestamp.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import ExperimentRepository
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.exposure import ExposureTag


class ExperimentActivityResponse(BaseModel):
    """Anonymized liveness rollup for one experiment. Every field is an
    aggregate count or timestamp — no per-worker identity is ever included."""

    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    # Distinct workers that have submitted >=1 result. Integer only: the
    # volunteer-anonymity rule forbids surfacing *which* volunteers ran the work.
    active_contributor_count: Annotated[int | None, ExposureTag.PUBLIC] = None
    total_work_units: Annotated[int | None, ExposureTag.PUBLIC] = None
    work_unit_counts: Annotated[dict[str, int] | None, ExposureTag.PUBLIC] = None
    # Most recent result received_at across the experiment (omitted when no
    # results have been submitted yet).
    last_activity_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    # Replication fill: total completions vs total target across all units.
    completions_total: Annotated[int | None, ExposureTag.PUBLIC] = None
    replication_target_total: Annotated[int | None, ExposureTag.PUBLIC] = None


def build_router(
    credential_dep,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
) -> APIRouter:
    router = APIRouter()

    def _can_view(credential: Credential, experiment) -> bool:
        if credential.is_maintainer():
            return True
        return credential.is_researcher() and credential.tenant_id == experiment.tenant_id

    @router.get(
        "/experiments/{experiment_id}/activity",
        response_model=ExperimentActivityResponse,
        response_model_exclude_none=True,
    )
    async def get_experiment_activity(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentActivityResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        # Tenant-private (mirrors work-units / experiment-detail): a non-owning
        # researcher or anonymous caller gets the same 404 as a genuinely-absent
        # experiment, so the rollup never confirms an experiment id exists.
        if experiment is None or not _can_view(credential, experiment):
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

        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            # No work units ever submitted for this experiment → empty rollup.
            return ExperimentActivityResponse(
                experiment_id=experiment_id,
                active_contributor_count=0,
                total_work_units=0,
                work_unit_counts={},
                completions_total=0,
                replication_target_total=0,
            )

        work_units = WorkUnitRepository(per_job_db)
        results = ResultRepository(per_job_db)

        counts = work_units.count_by_status()
        completions_total, target_total = work_units.replication_totals()

        return ExperimentActivityResponse(
            experiment_id=experiment_id,
            active_contributor_count=results.count_distinct_workers(),
            total_work_units=sum(counts.values()),
            work_unit_counts=counts,
            last_activity_at=results.latest_received_at(),
            completions_total=completions_total,
            replication_target_total=target_total,
        )

    return router
