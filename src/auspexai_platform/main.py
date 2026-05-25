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

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware

from auspexai_platform import __version__
from auspexai_platform.api import accounts as account_routes
from auspexai_platform.api import assignments as assignment_routes
from auspexai_platform.api import audit as audit_routes
from auspexai_platform.api import auth as auth_routes
from auspexai_platform.api import experiments as experiment_routes
from auspexai_platform.api import health
from auspexai_platform.api import receipts as receipt_routes
from auspexai_platform.api import tenants as tenant_routes
from auspexai_platform.api import work_units as work_unit_routes
from auspexai_platform.api import workers as worker_routes
from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.dependency import make_credential_dependency, require_maintainer
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
    ReceiptIndexRepository,
    RetiredKeyRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.eligibility import EligibilityThresholds
from auspexai_platform.oauth import IdentityVerifier, build_default_verifier
from auspexai_platform.rate_limit import limiter
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
    receipt_index_repository = ReceiptIndexRepository(db)
    from auspexai_platform.db.repositories.vouches import VouchRepository

    vouch_repository = VouchRepository(db)
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
        # Disable FastAPI's auto-mounted Swagger UI / ReDoc / openapi.json.
        # Re-served below as maintainer-only custom routes so the API surface
        # isn't anonymously enumerable on a publicly-reachable coord.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # CORS — allow the operator console and any env-configured origins.
    cors_origins = (
        config.cors_allowed_origins
        if hasattr(config, "cors_allowed_origins")
        else ["https://auspexai.network"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    # Per-IP rate limits on anonymous-public endpoints. Decorators are
    # applied inside the routers (api/workers.py, api/accounts.py,
    # api/receipts.py); here we wire the slowapi limiter onto the app and
    # register the 429 exception handler.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
    app.state.receipt_index_repository = receipt_index_repository

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
    eligibility_thresholds = EligibilityThresholds(
        t2_receipt_threshold=config.tier_t2_receipt_threshold,
        t2_distinct_experiments=config.tier_t2_distinct_experiments,
    )
    app.include_router(
        account_routes.build_router(
            credential_dep,
            account_repository,
            audit_repository,
            identity_verifier,
            worker_repository=worker_repository,
            vouch_repository=vouch_repository,
            receipt_index_repository=receipt_index_repository,
            eligibility_thresholds=eligibility_thresholds,
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
            receipt_index_repository,
            account_repository=account_repository,
            eligibility_thresholds=eligibility_thresholds,
            vouch_repository=vouch_repository,
        ),
        prefix="/api/v0",
        tags=["assignments"],
    )
    app.include_router(
        receipt_routes.build_router(
            coordinator_mode=config.receipts_mode,
            credential_dep=credential_dep,
            receipt_index_repository=receipt_index_repository,
            worker_repository=worker_repository,
            account_repository=account_repository,
            per_job_factory=per_job_factory,
            eligibility_thresholds=eligibility_thresholds,
            vouch_repository=vouch_repository,
        ),
        prefix="/api/v0",
        tags=["receipts"],
    )
    app.include_router(
        audit_routes.build_router(credential_dep, audit_repository),
        prefix="/api/v0",
        tags=["audit"],
    )

    _install_root_and_docs(app, credential_dep)
    return app


# NOTE: do NOT add a module-level `# `app = create_app()` removed; uvicorn factory pattern in cli.py` here.
# uvicorn's factory pattern (configured in cli.py) calls create_app()
# exactly once. A module-level call would also fire at import time —
# any test that imports `from auspexai_platform.main import create_app`
# and then calls `create_app()` itself would double-register slowapi
# rate-limit decorators because slowapi's @limiter.limit decorator
# appends to the per-route registry on every invocation with no
# idempotency check, effectively halving any configured limit.


_ROOT_HTML = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AuspexAI Coordinator</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px; margin: 4em auto; padding: 0 1em; color: #1a1a2e; background: #f5f5fa; line-height: 1.5; }}
    h1 {{ font-weight: 600; margin-top: 0; }}
    code {{ font-family: ui-monospace, monospace; background: #e3e3eb; padding: 0.1em 0.35em; border-radius: 3px; }}
    a {{ color: #5a4af4; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .endpoint {{ display: block; margin: 0.4em 0; }}
    .meta {{ color: #555; font-size: 0.9em; margin-top: 2em; }}
    .version {{ color: #888; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>AuspexAI Coordinator <span class="version">v{__version__}</span></h1>
  <p>Coordinator daemon for the <a href="https://github.com/auspexai">AuspexAI</a> volunteer compute network. Phase 2 closed-beta.</p>
  <p>Public endpoints:</p>
  <code class="endpoint"><a href="/api/v0/health/public">GET /api/v0/health/public</a></code>
  <code class="endpoint">POST /api/v0/receipts/verify — <a href="https://auspexai.network/verify.html">web verifier</a></code>
  <code class="endpoint"><a href="/api/v0/receipts/">GET /api/v0/receipts/{{receipt_id}}</a></code>
  <p>Maintainer endpoints: <code><a href="/api/v0/audit">GET /api/v0/audit</a></code> · <code><a href="/docs">API docs</a></code> (requires auth)</p>
  <p>Signing roster: <a href="https://github.com/auspexai/.github/blob/main/security/AUTHORIZED_SIGNERS.md">AUTHORIZED_SIGNERS.md</a></p>
  <p class="meta">Worker installer: <a href="https://getworker.auspexai.network">getworker.auspexai.network</a> · <a href="https://github.com/auspexai/worker/releases">releases</a> · Operator console: <a href="https://ops.auspexai.network">ops.auspexai.network</a></p>
  <p class="meta">Last updated: 2026-05-25</p>
</body>
</html>
"""


def _install_root_and_docs(app: FastAPI, credential_dep) -> None:
    """Mount the public root-discovery doc + maintainer-only docs UIs.

    Public surface: `GET /` returns HTML to browsers and JSON to programs.
    Operator surface: `/docs`, `/redoc`, `/openapi.json` require maintainer
    auth (the FastAPI auto-mounted versions are disabled at construct time).
    Browser visits to `/docs` after authing render the Swagger UI shell,
    but the page's JS fetch of `/openapi.json` carries no Authorization
    header — maintainers can curl the schema with their bearer token for
    actual inspection. Full browser-side Swagger auth (security-scheme
    plumbing) is deferred.
    """

    @app.get("/", include_in_schema=False)
    async def root(request: Request) -> Response:
        accept = request.headers.get("accept", "")
        if "text/html" in accept.lower():
            return HTMLResponse(content=_ROOT_HTML)
        return JSONResponse(
            content={
                "name": "AuspexAI Coordinator",
                "version": __version__,
                "phase": "Phase 2 closed-beta",
                "last_updated": "2026-05-25",
                "public_endpoints": {
                    "health": "GET /api/v0/health/public",
                    "receipts_verify": "POST /api/v0/receipts/verify",
                    "receipt_by_id": "GET /api/v0/receipts/{receipt_id}",
                },
                "maintainer_endpoints": {
                    "audit": "GET /api/v0/audit",
                    "docs": "GET /docs (requires auth)",
                },
                "receipt_verifier": "https://auspexai.network/verify.html",
                "github_org": "https://github.com/auspexai",
                "authorized_signers": (
                    "https://github.com/auspexai/.github/blob/main/security/AUTHORIZED_SIGNERS.md"
                ),
                "worker_install": "https://getworker.auspexai.network",
                "worker_releases": "https://github.com/auspexai/worker/releases",
                "operator_console": "https://ops.auspexai.network",
            }
        )

    # Old-style `Depends(...)` in default (with B008 noqa) rather than the
    # Annotated[T, Depends(...)] form, because PEP 563 stringification at
    # the top of this module makes FastAPI eval the annotation against
    # module globals — `credential_dep` is a local in this enclosing
    # function and can't be resolved that way. Matches existing routes
    # (see api/tenants.py).

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_authed(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> JSONResponse:
        require_maintainer(credential)
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False)
    async def docs_authed(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> HTMLResponse:
        require_maintainer(credential)
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{app.title} — Swagger UI",
        )

    @app.get("/redoc", include_in_schema=False)
    async def redoc_authed(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> HTMLResponse:
        require_maintainer(credential)
        return get_redoc_html(
            openapi_url="/openapi.json",
            title=f"{app.title} — ReDoc",
        )


# `app = create_app()` removed; uvicorn factory pattern in cli.py
