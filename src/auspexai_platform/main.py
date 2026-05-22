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
from auspexai_platform.api import accounts as account_routes
from auspexai_platform.api import assignments as assignment_routes
from auspexai_platform.api import auth as auth_routes
from auspexai_platform.api import experiments as experiment_routes
from auspexai_platform.api import health
from auspexai_platform.api import tenants as tenant_routes
from auspexai_platform.api import work_units as work_unit_routes
from auspexai_platform.api import workers as worker_routes
from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.dependency import make_credential_dependency
from auspexai_platform.auth.resolver import CredentialResolver
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.auth.worker_registry import WorkerRegistry
from auspexai_platform.config import Config
from auspexai_platform.db import Database, MigrationRunner
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
    RetiredKeyRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.oauth import IdentityVerifier, build_default_verifier
from auspexai_platform.receipts import load_or_generate_signing_key
from auspexai_platform.scheduler import Scheduler


def create_app(
    config: Config | None = None,
    *,
    token_store: TokenStore | None = None,
    tenant_registry: TenantRegistry | None = None,
    db: Database | None = None,
    identity_verifier: IdentityVerifier | None = None,
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
        identity_verifier: OAuth IdP token verifier (M6a). If None, the
            default production verifier is built (GitHub only). Tests inject
            a fake.
    """
    config = config or Config.from_env()
    token_store = token_store or TokenStore(config.maintainer_token_path)
    db = db or Database(config.control_db_path)
    identity_verifier = identity_verifier or build_default_verifier()

    # Apply pending migrations on every startup. Idempotent: no-op if
    # already up-to-date.
    MigrationRunner(db).apply_all()

    account_repository = AccountRepository(db)
    tenant_repository = TenantRepository(db)
    manifest_repository = ManifestRepository(db)
    experiment_repository = ExperimentRepository(db)
    audit_repository = AuditRepository(db)
    worker_repository = WorkerRepository(db)
    retired_key_repository = RetiredKeyRepository(db)
    per_job_factory = PerJobDatabaseFactory(config.jobs_dir)

    # M7b: load or generate the persistent receipt-signing key. The same
    # key file is used in both `dev` and `operational` receipts_mode; the
    # mode flag controls how the verifier endpoint (M7d) renders the trust
    # posture of the resulting receipts, not which key signs them.
    receipt_signing_key = load_or_generate_signing_key(config.receipt_signing_key_path)
    # Registries are façades over the repositories. Constructed here so the
    # auth path reads from the DB on every request.
    tenant_registry = tenant_registry or TenantRegistry(tenant_repository)
    worker_registry = WorkerRegistry(worker_repository)
    credential_resolver = CredentialResolver(tenant_registry, worker_registry)
    scheduler = Scheduler(experiment_repository, per_job_factory)

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
    app.state.worker_registry = worker_registry
    app.state.credential_resolver = credential_resolver
    app.state.db = db
    app.state.account_repository = account_repository
    app.state.tenant_repository = tenant_repository
    app.state.manifest_repository = manifest_repository
    app.state.experiment_repository = experiment_repository
    app.state.audit_repository = audit_repository
    app.state.worker_repository = worker_repository
    app.state.per_job_factory = per_job_factory
    app.state.scheduler = scheduler
    app.state.identity_verifier = identity_verifier
    app.state.receipt_signing_key = receipt_signing_key

    credential_dep = make_credential_dependency(token_store, credential_resolver)

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
    app.include_router(
        account_routes.build_router(
            credential_dep,
            account_repository,
            audit_repository,
            identity_verifier,
        ),
        prefix="/api/v0",
        tags=["accounts"],
    )
    app.include_router(
        worker_routes.build_router(
            credential_dep,
            worker_repository,
            account_repository,
            audit_repository,
            retired_key_repository,
            tenant_registry,
            worker_registry,
        ),
        prefix="/api/v0",
        tags=["workers"],
    )
    app.include_router(
        work_unit_routes.build_router(
            credential_dep,
            experiment_repository,
            audit_repository,
            per_job_factory,
        ),
        prefix="/api/v0",
        tags=["work-units"],
    )
    app.include_router(
        assignment_routes.build_router(
            credential_dep,
            worker_repository,
            scheduler,
            per_job_factory,
            audit_repository,
            experiment_repository,
            receipt_signing_key,
        ),
        prefix="/api/v0",
        tags=["assignments"],
    )

    return app


app = create_app()
