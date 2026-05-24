"""Worker routes — /api/v0/workers.

  POST   /api/v0/workers/enroll                        — anonymous; T0
  POST   /api/v0/workers/{worker_id}/upgrade           — worker; consumes M6a
                                                          binding token, T0→T1
  POST   /api/v0/workers/{worker_id}/heartbeat         — worker
  GET    /api/v0/workers                               — maintainer (list)
  GET    /api/v0/workers/{worker_id}                   — worker (own) or maintainer
  POST   /api/v0/workers/{worker_id}/actions/retire    — worker (own) or maintainer

Enrollment is anonymous-public — the worker signs its very first call but
isn't yet known to the coordinator. The coordinator validates that the
supplied pubkey isn't already a tenant or worker pubkey (cross-table
disjointness invariant) and inserts a T0 row keyed by a coordinator-
generated worker_id.

Subsequent worker calls authenticate via RFC 9421 signature (same path as
researcher); the keyid resolves to a `worker` Credential via the
CredentialResolver.

Field-exposure note: most worker fields are `tenant-scoped` in the
exposure-filter sense, but the relevant "scope" here is the worker
itself, not a tenant. M6b reuses the TENANT_SCOPED tag with a
worker-self-or-maintainer check at route time rather than introducing a
new exposure tag — the filter machinery is generic enough that this works
cleanly. Future Phase 2 work may add an explicit WORKER_SCOPED tag if the
self-or-maintainer pattern needs reuse.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer, require_worker
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.auth.worker_registry import WorkerRegistry
from auspexai_platform.db.models import TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
    RetiredKeyRepository,
    WorkerRepository,
)
from auspexai_platform.db.repositories.accounts import (
    BindingTokenConsumedError,
    BindingTokenExpiredError,
    BindingTokenNotFoundError,
)
from auspexai_platform.db.repositories.workers import (
    DuplicateWorkerError,
    WorkerNotFoundError,
)
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.rate_limit import limiter

# ---- request / response models --------------------------------------------


class WorkerResponse(BaseModel):
    """Wire shape for a worker. All fields Optional so the exposure filter
    can mask non-visible ones."""

    worker_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    trust_tier: Annotated[int | None, ExposureTag.PUBLIC] = None
    registered_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    last_heartbeat_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    retired_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    quarantined_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    quarantine_reason: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    pubkey_hex: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    account_id: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    capabilities: Annotated[dict[str, Any] | None, ExposureTag.OPERATOR_ONLY] = None


class WorkerListResponse(BaseModel):
    workers: Annotated[list[WorkerResponse] | None, ExposureTag.PUBLIC] = None


class WorkerEnrollRequest(BaseModel):
    pubkey_hex: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]+$",
        description="Worker's Ed25519 public key, 64 lowercase hex chars",
    )
    capabilities: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Worker-declared capabilities (os, ram_gb, gpus, locally-available "
            "models, etc.). Opaque to v0; the M6d scheduler parses specific "
            "keys for capability-matched scheduling per §5.8."
        ),
    )


class WorkerEnrollResponse(BaseModel):
    worker_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    trust_tier: Annotated[int | None, ExposureTag.PUBLIC] = None
    registered_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None


class WorkerUpgradeRequest(BaseModel):
    binding_token: str = Field(
        min_length=1,
        description="One-shot binding token from POST /accounts/oauth/exchange",
    )


class WorkerHeartbeatRequest(BaseModel):
    capabilities: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional capabilities update. When omitted, only last_heartbeat_at advances."
        ),
    )


class WorkerQuarantineRequest(BaseModel):
    reason: str | None = Field(
        default=None,
        max_length=2000,
        description=(
            "Free-form note from the maintainer; surfaces to operator-only "
            "views. Volunteer-visible response carries only the quarantine "
            "timestamp, not this reason."
        ),
    )


# ---- helpers --------------------------------------------------------------


def _generate_worker_id() -> str:
    """Generate a coordinator-side worker_id. Format: 'wkr-<12 url-safe chars>'."""
    return f"wkr-{secrets.token_urlsafe(9)}"


def _worker_to_response(worker) -> WorkerResponse:
    return WorkerResponse(
        worker_id=worker.worker_id,
        trust_tier=int(worker.trust_tier),
        registered_at=worker.registered_at,
        last_heartbeat_at=worker.last_heartbeat_at,
        retired_at=worker.retired_at,
        quarantined_at=worker.quarantined_at,
        quarantine_reason=worker.quarantine_reason,
        pubkey_hex=worker.pubkey_hex,
        account_id=worker.account_id,
        capabilities=worker.capabilities,
    )


def _self_or_maintainer(credential: Credential, worker_id: str) -> None:
    """403 unless caller is the worker itself OR a maintainer."""
    if credential.is_maintainer():
        return
    if credential.is_worker() and credential.worker_id == worker_id:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "worker_self_or_maintainer_required",
                "message": ("this endpoint requires the worker itself or a maintainer credential"),
                "details": {
                    "credential_class": credential.kind.value,
                    "worker_id": worker_id,
                },
            }
        },
    )


# ---- router ---------------------------------------------------------------


def build_router(
    credential_dep,
    worker_repository: WorkerRepository,
    account_repository: AccountRepository,
    audit_repository: AuditRepository,
    retired_key_repository: RetiredKeyRepository,
    tenant_registry: TenantRegistry,
    worker_registry: WorkerRegistry,
) -> APIRouter:
    router = APIRouter()

    # ---- POST /workers/enroll — anonymous, T0 ---------------------------

    @router.post(
        "/workers/enroll",
        response_model=WorkerEnrollResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    @limiter.limit("10/hour")
    async def enroll_worker(
        request: Request,
        body: WorkerEnrollRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerEnrollResponse:
        pubkey_hex = body.pubkey_hex.lower()

        # M7a: refuse re-enrollment of a withdrawn key. The retired_keys
        # registry is populated by the M6b retire endpoint and is intended
        # to be permanent — the §5.15 withdrawal commitment is that a
        # withdrawn key cannot be re-bound to a new worker_id.
        if retired_key_repository.contains(pubkey_hex):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "pubkey_retired",
                        "message": (
                            "this pubkey was previously retired and cannot be "
                            "re-enrolled; generate a fresh keypair to enroll "
                            "as a new worker"
                        ),
                        "details": {"pubkey_hex": pubkey_hex},
                    }
                },
            )

        # Cross-table disjointness: the same pubkey can't be both a tenant
        # maintainer and a worker. The CredentialResolver tries tenants first
        # at signature time anyway, but rejecting at enrollment prevents the
        # confusing "I registered a worker but my signatures resolve to
        # researcher" case.
        if tenant_registry.get_tenant_for_pubkey(pubkey_hex) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "pubkey_already_tenant",
                        "message": (
                            "this pubkey is registered as a tenant maintainer; "
                            "workers must use a distinct keypair"
                        ),
                        "details": {"pubkey_hex": pubkey_hex},
                    }
                },
            )

        try:
            worker = worker_repository.enroll(
                worker_id=_generate_worker_id(),
                pubkey_hex=pubkey_hex,
                capabilities=body.capabilities,
            )
        except DuplicateWorkerError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "pubkey_already_enrolled",
                        "message": "this pubkey is already registered as a worker",
                        "details": {"db_error": str(e)},
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=CredentialClass.ANONYMOUS,
            action="worker.enroll",
            resource_type="worker",
            resource_id=worker.worker_id,
            payload={
                "pubkey_hex": worker.pubkey_hex,
                "capabilities": worker.capabilities,
            },
        )

        return filter_for_credential(
            WorkerEnrollResponse(
                worker_id=worker.worker_id,
                trust_tier=int(worker.trust_tier),
                registered_at=worker.registered_at,
            ),
            credential,
        )

    # ---- POST /workers/{id}/upgrade — worker; T0→T1 ---------------------

    @router.post(
        "/workers/{worker_id}/upgrade",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def upgrade_worker(
        worker_id: str,
        body: WorkerUpgradeRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        require_worker(credential)
        # The worker upgrading must be the worker named in the URL.
        if credential.worker_id != worker_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "worker_id_mismatch",
                        "message": ("credential worker_id does not match URL worker_id"),
                        "details": {
                            "credential_worker_id": credential.worker_id,
                            "url_worker_id": worker_id,
                        },
                    }
                },
            )

        try:
            binding = account_repository.consume_binding(body.binding_token)
        except BindingTokenNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "binding_token_not_found",
                        "message": "binding token is unknown",
                    }
                },
            ) from e
        except BindingTokenExpiredError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "binding_token_expired",
                        "message": (
                            "binding token has expired; complete a new OAuth "
                            "exchange to mint a fresh one"
                        ),
                    }
                },
            ) from e
        except BindingTokenConsumedError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "binding_token_consumed",
                        "message": "binding token has already been consumed",
                    }
                },
            ) from e

        try:
            worker = worker_repository.bind_account(
                worker_id,
                account_id=binding.account_id,
                trust_tier=TrustTier.T1_AUTHENTICATED,
            )
        except WorkerNotFoundError as e:  # pragma: no cover — credential check above prevents
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="worker.upgrade",
            resource_type="worker",
            resource_id=worker.worker_id,
            payload={
                "account_id": binding.account_id,
                "new_trust_tier": int(worker.trust_tier),
            },
        )

        return filter_for_credential(_worker_to_response(worker), credential)

    # ---- POST /workers/{id}/heartbeat -----------------------------------

    @router.post(
        "/workers/{worker_id}/heartbeat",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def heartbeat_worker(
        worker_id: str,
        body: WorkerHeartbeatRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        require_worker(credential)
        if credential.worker_id != worker_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "worker_id_mismatch",
                        "message": ("credential worker_id does not match URL worker_id"),
                        "details": {
                            "credential_worker_id": credential.worker_id,
                            "url_worker_id": worker_id,
                        },
                    }
                },
            )
        try:
            worker = worker_repository.record_heartbeat(worker_id, capabilities=body.capabilities)
        except WorkerNotFoundError as e:  # pragma: no cover — credential check above prevents
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            ) from e
        return filter_for_credential(_worker_to_response(worker), credential)

    # ---- GET /workers — maintainer list --------------------------------

    @router.get(
        "/workers",
        response_model=WorkerListResponse,
        response_model_exclude_none=True,
    )
    async def list_workers(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerListResponse:
        require_maintainer(credential)
        workers = worker_repository.list_all()
        return WorkerListResponse(
            workers=[filter_for_credential(_worker_to_response(w), credential) for w in workers]
        )

    # ---- GET /workers/{id} — self or maintainer -------------------------

    @router.get(
        "/workers/{worker_id}",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def get_worker(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        _self_or_maintainer(credential, worker_id)
        worker = worker_repository.get_by_id(worker_id)
        if worker is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            )
        return filter_for_credential(_worker_to_response(worker), credential)

    # ---- POST /workers/{id}/actions/retire ------------------------------

    @router.post(
        "/workers/{worker_id}/actions/retire",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def retire_worker(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        _self_or_maintainer(credential, worker_id)
        try:
            worker = worker_repository.retire(worker_id)
        except WorkerNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            ) from e

        # M7a: record the pubkey in retired_keys so future enroll attempts
        # with the same key are refused. `retire` is idempotent (re-retire
        # of an already-retired worker is a no-op upstream), so the
        # DuplicateRetiredKeyError path here is the second-retire case —
        # treat as success since the registry already has the row.
        from auspexai_platform.db.repositories.retired_keys import (
            DuplicateRetiredKeyError,
        )

        try:
            retired_key_repository.retire(
                pubkey_hex=worker.pubkey_hex,
                worker_id=worker.worker_id,
                reason="withdraw",
            )
        except DuplicateRetiredKeyError:
            # Already in registry from a prior retire call — fine.
            pass

        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            action="worker.retire",
            resource_type="worker",
            resource_id=worker.worker_id,
        )

        return filter_for_credential(_worker_to_response(worker), credential)

    # ---- POST /workers/{id}/actions/quarantine (maintainer-only) --------

    @router.post(
        "/workers/{worker_id}/actions/quarantine",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def quarantine_worker(
        worker_id: str,
        body: WorkerQuarantineRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        require_maintainer(credential)
        try:
            worker = worker_repository.quarantine(worker_id, body.reason)
        except WorkerNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            ) from e
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "worker_retired",
                        "message": str(e),
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            action="worker.quarantine",
            resource_type="worker",
            resource_id=worker.worker_id,
            payload={"reason": body.reason} if body.reason else None,
        )

        return filter_for_credential(_worker_to_response(worker), credential)

    # ---- POST /workers/{id}/actions/unquarantine (maintainer-only) ------

    @router.post(
        "/workers/{worker_id}/actions/unquarantine",
        response_model=WorkerResponse,
        response_model_exclude_none=True,
    )
    async def unquarantine_worker(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WorkerResponse:
        require_maintainer(credential)
        try:
            worker = worker_repository.unquarantine(worker_id)
        except WorkerNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "worker_not_found",
                        "message": f"no worker with id {worker_id!r}",
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            action="worker.unquarantine",
            resource_type="worker",
            resource_id=worker.worker_id,
        )

        return filter_for_credential(_worker_to_response(worker), credential)

    return router
