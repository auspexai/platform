"""Health endpoints.

Both endpoints share a single response model; field-exposure tags determine
which subset each credential class sees:

  - `GET /api/v0/health` — operator-facing liveness. Maintainer sees every
    field; researchers see tenant-scoped + public; anonymous sees public.
  - `GET /api/v0/health/public` — same model, no auth required. Anonymous
    callers always get only public fields.

For M3 all health fields are `public` (the network being up and its server
clock are not sensitive). Later milestones add operator-only fields like
`db_status`, `scheduler_queue_depth`, `pending_alerts`.

`network_active_workers` is a PUBLIC count of workers active network-wide
(heartbeat-fresh, not retired/quarantined). It's the same identity-free
network-size signal the activity rollup carries, surfaced here so a worker
(or anyone) can see "how big is the collective" without an experiment context.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from auspexai_platform import __version__
from auspexai_platform.auth.credential import Credential
from auspexai_platform.db.repositories.workers import WorkerRepository
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.hf_catalog import catalog_fetched_at, catalog_is_stale
from auspexai_platform.worker_status import heartbeat_cutoff


class HealthResponse(BaseModel):
    """Liveness payload.

    All fields are Optional so the field-exposure filter can set them to None
    for credential classes that aren't allowed to see them. Combined with
    `response_model_exclude_none=True` on the route, None fields drop from
    the rendered JSON.
    """

    status: Annotated[str | None, ExposureTag.PUBLIC] = None
    version: Annotated[str | None, ExposureTag.PUBLIC] = None
    server_time: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    network_active_workers: Annotated[int | None, ExposureTag.PUBLIC] = None
    # Operator-only: the provisionable HF menu is stale (curated fallback in use, or the
    # daily refresh timer hasn't run in >48h). A maintainer / the ops console sees it here
    # so a silently-stopped `refresh-hf-catalog` timer gets caught, not just self-reported.
    catalog_stale: Annotated[bool | None, ExposureTag.OPERATOR_ONLY] = None


def _full_payload(
    worker_repository: WorkerRepository, hf_catalog_path: Path | None = None
) -> HealthResponse:
    now = datetime.now(UTC)
    fetched = catalog_fetched_at(hf_catalog_path) if hf_catalog_path else None
    source = "hf" if fetched else "curated"
    return HealthResponse(
        status="ok",
        version=__version__,
        server_time=now,
        network_active_workers=worker_repository.count_active(
            heartbeat_cutoff=heartbeat_cutoff(now)
        ),
        catalog_stale=catalog_is_stale(source, fetched, now=now),
    )


def build_router(
    credential_dep, worker_repository: WorkerRepository, hf_catalog_path: Path | None = None
) -> APIRouter:
    """Build the /health router bound to a credential dependency.

    Same factory pattern as the auth router so each app instance carries
    its own dependency closure."""

    router = APIRouter()

    @router.get(
        "/health",
        response_model=HealthResponse,
        response_model_exclude_none=True,
    )
    async def health(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> HealthResponse:
        return filter_for_credential(_full_payload(worker_repository, hf_catalog_path), credential)

    @router.get(
        "/health/public",
        response_model=HealthResponse,
        response_model_exclude_none=True,
    )
    async def health_public() -> HealthResponse:
        """Anonymous-public liveness. No credential dependency; filter for the
        anonymous class so the response shape matches what an anonymous caller
        would see on the operator endpoint."""
        return filter_for_credential(
            _full_payload(worker_repository, hf_catalog_path), Credential.anonymous()
        )

    return router
