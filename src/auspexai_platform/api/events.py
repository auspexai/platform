"""Server-Sent Events (SSE) live streams — M8.

Two read-only streams over the in-process `EventBus`:

  - `GET /api/v0/experiments/{experiment_id}/events` — tenant-scoped. The
    owning researcher (or a maintainer) watches one experiment's lifecycle
    transitions, work-unit progress, and receipt issuance live. Same 404-as-
    privacy gate as `GET /experiments/{id}` so the stream never confirms an
    experiment id to a non-owner.
  - `GET /api/v0/events` — maintainer-only firehose: every experiment's events.

SSE (not WebSocket) per the §5.18 contract; auth uses the same credential
headers as the rest of the REST API (RFC 9421 signature for researchers,
bearer for the maintainer). The response is `text/event-stream`; each frame is

    id: <seq>
    event: <type>
    data: <json>

with `: ping` keepalive comments on idle so proxies don't time the connection
out. The bus is best-effort (see `events/bus.py`): a slow client drops its
oldest events, and `seq` lets a client detect the gap.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import ExperimentRepository
from auspexai_platform.events import GLOBAL, Event, EventBus

# Idle keepalive cadence (seconds). On no event within this window the stream
# emits a comment line to keep intermediaries from dropping the connection.
PING_INTERVAL_SECONDS = 15.0

_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    # Disable proxy/buffering (nginx) so frames flush immediately.
    "X-Accel-Buffering": "no",
}


def _sse_frame(event: Event) -> str:
    """Render one `Event` as an SSE frame. `experiment_id` is folded into the
    payload so a firehose consumer can route without parsing the `event:` line."""
    payload = {"experiment_id": event.experiment_id, **event.data}
    return (
        f"id: {event.seq}\n"
        f"event: {event.type}\n"
        f"data: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n"
    )


async def _stream(
    bus: EventBus, channel: str, request: Request, *, ping_interval: float
) -> AsyncIterator[str]:
    """Subscribe to `channel` and yield SSE frames until the client disconnects.

    The `bus.subscribe` context manager tears the subscription down on exit —
    including when Starlette cancels this generator on client disconnect — so
    there is no subscriber leak. An immediate `: connected` comment flushes
    headers and lets clients (and tests) confirm the stream is live."""
    with bus.subscribe(channel) as queue:
        yield ": connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=ping_interval)
            except (TimeoutError, asyncio.TimeoutError):  # noqa: UP041 - 3.11 alias safety
                yield ": ping\n\n"
                continue
            yield _sse_frame(event)


def build_router(
    *,
    credential_dep,
    experiment_repository: ExperimentRepository,
    event_bus: EventBus,
    ping_interval: float = PING_INTERVAL_SECONDS,
) -> APIRouter:
    router = APIRouter()

    def _can_view(credential: Credential, experiment) -> bool:
        if credential.is_maintainer():
            return True
        return credential.is_researcher() and credential.tenant_id == experiment.tenant_id

    @router.get("/experiments/{experiment_id}/events", include_in_schema=True)
    async def experiment_events(
        experiment_id: str,
        request: Request,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> StreamingResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        # Tenant-private (§3): non-owner / anonymous gets the same 404 as a
        # genuinely-absent experiment — the stream never confirms existence.
        if experiment is None or not _can_view(credential, experiment):
            from auspexai_platform.api.experiments import _experiment_not_found

            raise _experiment_not_found(experiment_id)
        return StreamingResponse(
            _stream(event_bus, experiment_id, request, ping_interval=ping_interval),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    @router.get("/events", include_in_schema=True)
    async def firehose(
        request: Request,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> StreamingResponse:
        """Maintainer-only: every experiment's events (operator live view)."""
        require_maintainer(credential)
        return StreamingResponse(
            _stream(event_bus, GLOBAL, request, ping_interval=ping_interval),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    def _event_json(e) -> dict:
        return {
            "seq": e.seq,
            "type": e.type,
            "experiment_id": e.experiment_id,
            "data": e.data,
            "at": e.at,
        }

    @router.get("/experiments/{experiment_id}/events/recent", include_in_schema=True)
    async def experiment_events_recent(
        experiment_id: str,
        limit: int = 500,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ):
        """UI fix C (2026-07-06): the bounded replay ring, so heartbeat views
        REHYDRATE on mount instead of losing history to navigation. Same
        tenant-privacy contract as the SSE twin (non-owner → 404)."""
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None or not _can_view(credential, experiment):
            from auspexai_platform.api.experiments import _experiment_not_found

            raise _experiment_not_found(experiment_id)
        return {
            "events": [
                _event_json(e)
                for e in event_bus.recent(experiment_id=experiment_id, limit=min(limit, 2000))
            ]
        }

    @router.get("/events/recent", include_in_schema=True)
    async def firehose_recent(
        limit: int = 500,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ):
        """Maintainer-only replay of the operator firehose ring."""
        require_maintainer(credential)
        return {"events": [_event_json(e) for e in event_bus.recent(limit=min(limit, 2000))]}

    return router
