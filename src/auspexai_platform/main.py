"""FastAPI application factory for the AuspexAI coordinator daemon.

This module assembles the ASGI app: routes, middleware (added in M2),
exception handlers, and lifespan hooks. The app is created via
`create_app()` so tests can instantiate it with custom config without
reaching for global state.

Run via the CLI: `auspexai-coordinator serve` (see `cli.py`).
"""

from __future__ import annotations

from fastapi import FastAPI

from auspexai_platform import __version__
from auspexai_platform.api import health


def create_app() -> FastAPI:
    """Build and return the coordinator's FastAPI application.

    Composition order (one section per M-milestone):
      - M1: health endpoint
      - M2: auth middleware (three credential classes)
      - M3: field-exposure filter
      - M4: storage layer wiring (DB lifespan hook)
      - M5+: resource routes (tenants, experiments, workers, receipts, ...)
    """
    app = FastAPI(
        title="AuspexAI Coordinator",
        version=__version__,
        description=(
            "Coordinator daemon for the AuspexAI volunteer compute network. "
            "JSON-only HTTP API. Four Phase 1 consumers per §5.18 of the "
            "Principles & Scope: worker daemon, tenant SDK, operator console, "
            "researcher dashboard. A fifth consumer (public receipt verifier) "
            "uses the anonymous-public credential class."
        ),
        # OpenAPI / docs disabled by default in production via env flag (M2+).
        # Left on here for early development.
    )

    app.include_router(health.router, prefix="/api/v0", tags=["system"])

    return app


app = create_app()
