"""Health endpoints.

`GET /api/v0/health` is the operator-facing liveness check used by the operator
console, CI, and ops tooling. `GET /api/v0/health/public` is the
anonymous-public variant — same shape, but returns only `public`-tagged fields
once the exposure filter lands (M3). For M1 the two endpoints return the same
minimal payload.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel

from auspexai_platform import __version__

router = APIRouter()


class HealthResponse(BaseModel):
    """Liveness payload. Fields gain exposure tags in M3."""

    status: str
    version: str
    server_time: datetime


def _health_payload() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        server_time=datetime.now(UTC),
    )


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Operator-facing liveness. Adds DB connectivity + scheduler state in M4."""
    return _health_payload()


@router.get("/health/public", response_model=HealthResponse)
async def health_public() -> HealthResponse:
    """Anonymous-public liveness. Gains field-exposure filtering in M3 and
    aggregate network counters (experiments active, workers connected, receipts
    issued last 24h) in M5-M7."""
    return _health_payload()
