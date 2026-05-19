"""`/api/v0/auth/whoami` endpoint.

Echoes the resolved Credential back to the caller. With M3's exposure filter:

  - `credential_class` is `public` — every caller sees their own class.
  - `tenant_id` and `pubkey_hex` are `tenant-scoped` against
    `resource_tenant_id = credential.tenant_id` — researchers see their own
    binding, operator sees all (per the operator-sees-all rule), anonymous
    callers see neither.

Useful for:
  - The operator console at startup ("am I correctly configured with a
    maintainer token?")
  - The researcher dashboard at startup ("does the coordinator recognize my
    Ed25519 keypair?")
  - Tests covering all three credential paths.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.exposure import ExposureTag, filter_for_credential


class WhoamiResponse(BaseModel):
    """The shape returned by `/auth/whoami`.

    `credential_class` is always present (public). `tenant_id` and
    `pubkey_hex` are present only for the researcher viewing their own
    credential, or for an operator viewing anyone's credential.
    """

    credential_class: Annotated[CredentialClass | None, ExposureTag.PUBLIC] = Field(
        default=None,
        description="One of: maintainer | researcher | anonymous",
    )
    tenant_id: Annotated[str | None, ExposureTag.TENANT_SCOPED] = Field(
        default=None,
        description="Researcher only: the tenant the signing pubkey is bound to.",
    )
    pubkey_hex: Annotated[str | None, ExposureTag.TENANT_SCOPED] = Field(
        default=None,
        description="Researcher only: the signing Ed25519 pubkey (hex).",
    )


def build_router(credential_dep) -> APIRouter:
    """Build the /auth router bound to a credential dependency."""

    router = APIRouter()

    @router.get(
        "/auth/whoami",
        response_model=WhoamiResponse,
        response_model_exclude_none=True,
    )
    async def whoami(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WhoamiResponse:
        payload = WhoamiResponse(
            credential_class=credential.kind,
            tenant_id=credential.tenant_id,
            pubkey_hex=credential.pubkey_hex,
        )
        return filter_for_credential(
            payload,
            credential,
            resource_tenant_id=credential.tenant_id,
        )

    return router
