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
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from auspexai_platform import __version__
from auspexai_platform.auth.credential import Credential
from auspexai_platform.exposure import ExposureTag, filter_for_credential


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


def _full_payload() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        server_time=datetime.now(UTC),
    )


def build_router(credential_dep) -> APIRouter:
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
        return filter_for_credential(_full_payload(), credential)

    @router.get(
        "/health/public",
        response_model=HealthResponse,
        response_model_exclude_none=True,
    )
    async def health_public() -> HealthResponse:
        """Anonymous-public liveness. No credential dependency; filter for the
        anonymous class so the response shape matches what an anonymous caller
        would see on the operator endpoint."""
        return filter_for_credential(_full_payload(), Credential.anonymous())

    return router
