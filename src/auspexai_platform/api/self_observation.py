"""Firewall #5 self-observation endpoint — /api/v0/self-observation.

  GET /api/v0/self-observation — maintainer-only network self-observation snapshot.

Surfaces the firewall-#5 (A5) signals — autonomy ratio, fleet diversity, trust
flow, vouch topology, and divergence health — computed deterministically from the
control DB (no writes, no enforcement; the footprint pattern). This is the
maintainer-facing surface that makes the equal-trust flip *observable*: the signals
existed as a library (`signals.compute_self_observation`) but had no production
caller, so flip-gaming could not be watched live. This route is that caller.

Time-series persistence, cross-experiment aggregation, and a signed/published
self-observation report stay deferred (reviewer #4) until there is a non-maintainer
T1 + a second tenant; this endpoint is the on-demand live read.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.database import Database
from auspexai_platform.signals import compute_self_observation


def build_router(credential_dep, db: Database) -> APIRouter:
    """Build the /self-observation router bound to a credential dependency and the control DB."""

    router = APIRouter()

    @router.get("/self-observation")
    async def self_observation(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        require_maintainer(credential)
        return {
            "firewall": 5,
            "description": (
                "Deterministic control-DB self-observation signals (reward-independent, "
                "externally verifiable, no enforcement). The metric to watch for flip-gaming."
            ),
            "signals": compute_self_observation(db),
        }

    return router
