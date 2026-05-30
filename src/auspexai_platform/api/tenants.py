"""Tenant routes — /api/v0/tenants.

  POST   /api/v0/tenants              — operator only; registers a new tenant
  GET    /api/v0/tenants              — list (filtered per credential class)
  GET    /api/v0/tenants/{tenant_id}  — detail (filtered)

Field-exposure:
  - tenant_id, display_name, description, contact_public, registered_at,
    revision — `public`
  - contact_email, maintainer_pubkey — `tenant-scoped` (the tenant's own
    fields; operator sees all, researcher sees their own, anonymous sees
    neither)
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
    TenantRepository,
)
from auspexai_platform.db.repositories.tenants import DuplicateTenantError
from auspexai_platform.exposure import ExposureTag, filter_for_credential

# ---- response models -------------------------------------------------------


class TenantResponse(BaseModel):
    """Wire shape for a single tenant. All fields are Optional so the
    field-exposure filter can mask them out for credential classes that
    aren't allowed to see them."""

    tenant_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    display_name: Annotated[str | None, ExposureTag.PUBLIC] = None
    description: Annotated[str | None, ExposureTag.PUBLIC] = None
    contact_public: Annotated[str | None, ExposureTag.PUBLIC] = None
    registered_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    revision: Annotated[int | None, ExposureTag.PUBLIC] = None
    contact_email: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    maintainer_pubkey: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None


class TenantListResponse(BaseModel):
    """List response wrapper. The `tenants` field is `public` because the
    LIST endpoint returns whatever the credential is allowed to see; the
    field filter is applied per-item before they land here."""

    tenants: Annotated[list[TenantResponse] | None, ExposureTag.PUBLIC] = None


class TenantCreateRequest(BaseModel):
    """POST /api/v0/tenants body."""

    tenant_id: str = Field(min_length=1, pattern=r"^[a-z0-9_-]+$")
    maintainer_pubkey: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]+$")
    display_name: str | None = None
    contact_email: str | None = None
    contact_public: str | None = None
    description: str | None = None
    # b-lite: optional operator-set link to an existing OAuth account. Validated
    # for existence in the route; None leaves the tenant unlinked.
    account_id: str | None = None


# ---- helpers ---------------------------------------------------------------


def _tenant_to_response(tenant) -> TenantResponse:
    """Lift a db.models.Tenant into the API's TenantResponse (pre-filter)."""
    return TenantResponse(
        tenant_id=tenant.tenant_id,
        display_name=tenant.display_name,
        description=tenant.description,
        contact_public=tenant.contact_public,
        registered_at=tenant.registered_at,
        revision=tenant.revision,
        contact_email=tenant.contact_email,
        maintainer_pubkey=tenant.maintainer_pubkey,
    )


# ---- router ----------------------------------------------------------------


def build_router(
    credential_dep,
    tenant_repository: TenantRepository,
    audit_repository: AuditRepository,
    account_repository: AccountRepository,
) -> APIRouter:
    """Build /tenants router bound to repository instances + the
    credential dependency."""

    router = APIRouter()

    @router.post(
        "/tenants",
        response_model=TenantResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_tenant(
        body: TenantCreateRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantResponse:
        require_maintainer(credential)
        if body.account_id is not None and account_repository.get_by_id(body.account_id) is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "unknown_account",
                        "message": f"no account with id {body.account_id!r}",
                        "details": {"account_id": body.account_id},
                    }
                },
            )
        try:
            tenant = tenant_repository.register(
                tenant_id=body.tenant_id,
                maintainer_pubkey=body.maintainer_pubkey,
                display_name=body.display_name,
                contact_email=body.contact_email,
                contact_public=body.contact_public,
                description=body.description,
                account_id=body.account_id,
            )
        except DuplicateTenantError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_tenant",
                        "message": "tenant_id or maintainer_pubkey already registered",
                        "details": {"db_error": str(e)},
                    }
                },
            ) from e

        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            action="tenant.register",
            resource_type="tenant",
            resource_id=tenant.tenant_id,
            payload={
                "maintainer_pubkey": tenant.maintainer_pubkey,
                "display_name": tenant.display_name,
                "account_id": tenant.account_id,
            },
        )

        return filter_for_credential(
            _tenant_to_response(tenant),
            credential,
            resource_tenant_id=tenant.tenant_id,
        )

    @router.get(
        "/tenants",
        response_model=TenantListResponse,
        response_model_exclude_none=True,
    )
    async def list_tenants(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantListResponse:
        # Anonymous + researcher both see all tenants, but with public-field
        # filtering (researcher additionally sees their own tenant's full
        # fields). Maintainer sees everything.
        tenants = tenant_repository.list_all()
        filtered_items: list[TenantResponse] = []
        for t in tenants:
            response = _tenant_to_response(t)
            filtered = filter_for_credential(
                response,
                credential,
                resource_tenant_id=t.tenant_id,
            )
            filtered_items.append(filtered)
        return TenantListResponse(tenants=filtered_items)

    @router.get(
        "/tenants/{tenant_id}",
        response_model=TenantResponse,
        response_model_exclude_none=True,
    )
    async def get_tenant(
        tenant_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantResponse:
        tenant = tenant_repository.get_by_id(tenant_id)
        if tenant is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "tenant_not_found",
                        "message": f"no tenant with id {tenant_id!r}",
                        "details": {"tenant_id": tenant_id},
                    }
                },
            )
        return filter_for_credential(
            _tenant_to_response(tenant),
            credential,
            resource_tenant_id=tenant.tenant_id,
        )

    return router
