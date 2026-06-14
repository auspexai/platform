"""Demand-board + researcher "new requirement" review queue (M2, §9 #32/#39).

The §3a layer-2/3 reframe on the M1 capability substrate:

  GET  /api/v0/models/catalog                  — bottom-up network catalog (the
                                                  emergent set of models active
                                                  workers declare + counts).
  POST /api/v0/model-requests                  — a researcher signals demand for
                                                  a model. Recorded as `available`
                                                  if an active worker already holds
                                                  it, else `pending` (review queue).
  GET  /api/v0/model-requests[?status=]        — maintainer review queue.
  POST /api/v0/model-requests/{id}/actions/fulfil|decline
                                               — maintainer resolves a request with
                                                  a mandatory, audited reason.

The catalog is a live aggregate over `worker.capabilities["models"]` (no curated
table); `model_id` is the worker store id (`<repo-slug>-<quant>`) — the same
exact-match space the M1 scheduler routes on, so "available" reflects what the
network can actually run now.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.repositories import (
    AuditRepository,
    ModelRequestRepository,
    WorkerRepository,
)
from auspexai_platform.db.repositories.model_requests import ModelRequest
from auspexai_platform.worker_status import heartbeat_cutoff


class ModelRequestCreate(BaseModel):
    model_id: str = Field(min_length=1, max_length=256)
    hf_repo: str | None = Field(default=None, max_length=256)
    reason: str = Field(min_length=1, max_length=2000)


class ResolveRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class ModelRequestResponse(BaseModel):
    request_id: str
    tenant_id: str
    model_id: str
    hf_repo: str | None = None
    reason: str
    status: str
    created_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None


class ModelRequestListResponse(BaseModel):
    requests: list[ModelRequestResponse]


class CatalogEntry(BaseModel):
    model_id: str
    worker_count: int


class CatalogResponse(BaseModel):
    models: list[CatalogEntry]
    total_active_workers: int


def _require_maintainer(credential: Credential) -> None:
    if not credential.is_maintainer():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")


def _to_response(r: ModelRequest) -> ModelRequestResponse:
    return ModelRequestResponse(
        request_id=r.request_id,
        tenant_id=r.tenant_id,
        model_id=r.model_id,
        hf_repo=r.hf_repo,
        reason=r.reason,
        status=r.status,
        created_at=r.created_at,
        resolved_at=r.resolved_at,
        resolved_by=r.resolved_by,
        resolution_reason=r.resolution_reason,
    )


def build_router(
    credential_dep,
    model_request_repository: ModelRequestRepository,
    worker_repository: WorkerRepository,
    audit_repository: AuditRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/models/catalog", response_model=CatalogResponse, status_code=status.HTTP_200_OK)
    async def get_catalog(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> CatalogResponse:
        # The catalog is the network's servable-model set. Authenticated
        # researchers (the consumers) + maintainers; not anonymous.
        if not (credential.is_researcher() or credential.is_maintainer()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="researcher or maintainer credential required",
            )
        now = datetime.now(UTC)
        cutoff = heartbeat_cutoff(now)
        counts = worker_repository.model_inventory_counts(heartbeat_cutoff=cutoff)
        models = [
            CatalogEntry(model_id=m, worker_count=c)
            for m, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
        return CatalogResponse(
            models=models,
            total_active_workers=worker_repository.count_active(heartbeat_cutoff=cutoff),
        )

    @router.post(
        "/model-requests",
        response_model=ModelRequestResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_model_request(
        body: ModelRequestCreate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ModelRequestResponse:
        if not credential.is_researcher() or not credential.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_required",
                        "message": "a researcher credential is required to request a model",
                    }
                },
            )
        # Feasibility triage (the Tier A/B/C model-supply gate):
        #   A: a worker already holds it                  -> available
        #   B: no holder, but an auto_acquire worker can   -> acquirable (#44: it
        #      pull it in-line from the request's coords      pulls when the
        #      when the experiment runs                       experiment runs)
        #   C: neither                                     -> pending (maintainer)
        cutoff = heartbeat_cutoff(datetime.now(UTC))
        capable = worker_repository.count_capable(
            required_models=[body.model_id], heartbeat_cutoff=cutoff
        )
        if capable > 0:
            new_status = "available"
        elif body.hf_repo and worker_repository.count_auto_acquire(heartbeat_cutoff=cutoff) > 0:
            new_status = "acquirable"
        else:
            new_status = "pending"
        req = model_request_repository.create(
            tenant_id=credential.tenant_id,
            model_id=body.model_id,
            hf_repo=body.hf_repo,
            reason=body.reason,
            status=new_status,
        )
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="model_request.create",
            resource_type="model_request",
            resource_id=req.request_id,
            payload={"model_id": body.model_id, "status": new_status},
        )
        return _to_response(req)

    @router.get(
        "/model-requests",
        response_model=ModelRequestListResponse,
        status_code=status.HTTP_200_OK,
    )
    async def list_model_requests(
        status: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ModelRequestListResponse:
        # Maintainers see the whole queue; a researcher gets a tenant-forced
        # view of their own requests (the dashboard "my requests" surface).
        if credential.is_maintainer():
            reqs = model_request_repository.list(status=status)
        elif credential.is_researcher() and credential.tenant_id:
            reqs = model_request_repository.list(status=status, tenant_id=credential.tenant_id)
        else:
            _require_maintainer(credential)
            raise AssertionError("unreachable")
        return ModelRequestListResponse(requests=[_to_response(r) for r in reqs])

    def _resolve(
        request_id: str, new_status: str, reason: str, credential: Credential
    ) -> ModelRequestResponse:
        _require_maintainer(credential)
        existing = model_request_repository.get_by_id(request_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="model request not found"
            )
        req = model_request_repository.resolve(
            request_id,
            status=new_status,
            resolved_by=credential.maintainer_login or "maintainer",
            reason=reason,
        )
        assert req is not None
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action=f"model_request.{'fulfil' if new_status == 'fulfilled' else 'decline'}",
            resource_type="model_request",
            resource_id=request_id,
            payload={"model_id": req.model_id, "new_status": new_status, "reason": reason},
        )
        return _to_response(req)

    @router.post(
        "/model-requests/{request_id}/actions/fulfil",
        response_model=ModelRequestResponse,
        status_code=status.HTTP_200_OK,
    )
    async def fulfil_model_request(
        request_id: str,
        body: ResolveRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ModelRequestResponse:
        return _resolve(request_id, "fulfilled", body.reason, credential)

    @router.post(
        "/model-requests/{request_id}/actions/decline",
        response_model=ModelRequestResponse,
        status_code=status.HTTP_200_OK,
    )
    async def decline_model_request(
        request_id: str,
        body: ResolveRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ModelRequestResponse:
        return _resolve(request_id, "declined", body.reason, credential)

    return router
