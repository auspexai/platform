"""FastAPI application factory for the AuspexAI coordinator daemon.

`create_app()` is the composition root. It takes an optional `Config` and
optional auth-layer overrides so tests can swap in fixtures (a temp token
store, a pre-populated tenant registry) without monkey-patching globals.

Composition order (one section per M-milestone):
  - M1: health endpoint
  - M2 (this milestone): config, token store, tenant registry, auth dependency,
    `/auth/whoami` endpoint
  - M3: field-exposure filter
  - M4: storage layer wiring (DB lifespan hook; tenant registry moves to DB)
  - M5+: resource routes (tenants, experiments, workers, receipts, ...)
"""

from __future__ import annotations

from fastapi import FastAPI

from auspexai_platform import __version__
from auspexai_platform.api import auth as auth_routes
from auspexai_platform.api import health
from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.dependency import make_credential_dependency
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.config import Config


def create_app(
    config: Config | None = None,
    *,
    token_store: TokenStore | None = None,
    tenant_registry: TenantRegistry | None = None,
) -> FastAPI:
    """Build and return the coordinator's FastAPI application.

    Args:
        config: runtime configuration. If None, built from env via
            `Config.from_env()`.
        token_store: maintainer-token store. If None, bound to
            `config.maintainer_token_path`.
        tenant_registry: researcher pubkey → tenant_id lookup. If None, an
            empty in-memory registry is created; tests typically pre-populate.
    """
    config = config or Config.from_env()
    token_store = token_store or TokenStore(config.maintainer_token_path)
    tenant_registry = tenant_registry or TenantRegistry()

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
    )

    # Stash the layer state on the app so tests + CLI helpers can introspect.
    app.state.config = config
    app.state.token_store = token_store
    app.state.tenant_registry = tenant_registry

    credential_dep = make_credential_dependency(token_store, tenant_registry)

    app.include_router(health.router, prefix="/api/v0", tags=["system"])
    app.include_router(auth_routes.build_router(credential_dep), prefix="/api/v0", tags=["auth"])

    return app


app = create_app()
