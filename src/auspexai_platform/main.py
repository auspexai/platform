"""FastAPI application factory for the AuspexAI coordinator daemon.

`create_app()` is the composition root. It takes an optional `Config` and
optional auth-layer overrides so tests can swap in fixtures (a temp token
store, a pre-populated tenant registry) without monkey-patching globals.

Composition order (one section per M-milestone):
  - M1: health endpoint
  - M2: config, token store, tenant registry, auth dependency, `/auth/whoami`
  - M3: field-exposure filter
  - M4 (this milestone): SQLite control DB + repository pattern + migrations.
    DB is opened at app-construct time and migrations applied; repositories
    are exposed on `app.state`. The auth-side tenant_registry stays
    in-memory for now; M5 will migrate the auth path to read from the DB.
  - M5+: resource routes (tenants, experiments, workers, receipts, ...)
"""

from __future__ import annotations

from fastapi import FastAPI

from auspexai_platform import __version__
from auspexai_platform.api import auth as auth_routes
from auspexai_platform.api import experiments as experiment_routes
from auspexai_platform.api import health
from auspexai_platform.api import tenants as tenant_routes
from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.dependency import make_credential_dependency
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.config import Config
from auspexai_platform.db import Database, MigrationRunner
from auspexai_platform.db.repositories import (
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
    TenantRepository,
)


def create_app(
    config: Config | None = None,
    *,
    token_store: TokenStore | None = None,
    tenant_registry: TenantRegistry | None = None,
    db: Database | None = None,
) -> FastAPI:
    """Build and return the coordinator's FastAPI application.

    Args:
        config: runtime configuration. If None, built from env via
            `Config.from_env()`.
        token_store: maintainer-token store. If None, bound to
            `config.maintainer_token_path`.
        tenant_registry: researcher pubkey → tenant_id lookup. If None, an
            empty in-memory registry is created; tests typically pre-populate.
        db: control-DB connection. If None, opened at
            `config.control_db_path`. Migrations are applied unconditionally
            (idempotent).
    """
    config = config or Config.from_env()
    token_store = token_store or TokenStore(config.maintainer_token_path)
    db = db or Database(config.control_db_path)

    # Apply pending migrations on every startup. Idempotent: no-op if
    # already up-to-date.
    MigrationRunner(db).apply_all()

    tenant_repository = TenantRepository(db)
    manifest_repository = ManifestRepository(db)
    experiment_repository = ExperimentRepository(db)
    audit_repository = AuditRepository(db)
    # Registry is a façade over the repository. Constructed here so the auth
    # path reads from the DB on every request.
    tenant_registry = tenant_registry or TenantRegistry(tenant_repository)

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
    app.state.db = db
    app.state.tenant_repository = tenant_repository
    app.state.manifest_repository = manifest_repository
    app.state.experiment_repository = experiment_repository
    app.state.audit_repository = audit_repository

    credential_dep = make_credential_dependency(token_store, tenant_registry)

    app.include_router(health.build_router(credential_dep), prefix="/api/v0", tags=["system"])
    app.include_router(auth_routes.build_router(credential_dep), prefix="/api/v0", tags=["auth"])
    app.include_router(
        tenant_routes.build_router(credential_dep, tenant_repository, audit_repository),
        prefix="/api/v0",
        tags=["tenants"],
    )
    app.include_router(
        experiment_routes.build_router(
            credential_dep,
            manifest_repository,
            experiment_repository,
            audit_repository,
        ),
        prefix="/api/v0",
        tags=["experiments"],
    )

    return app


app = create_app()
