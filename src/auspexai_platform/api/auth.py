"""`/api/v0/auth/whoami` endpoint.

A single endpoint that echoes back the resolved Credential. Useful for:

  - The operator console at startup ("am I correctly configured with a
    maintainer token?")
  - The researcher dashboard at startup ("does the coordinator recognize my
    Ed25519 keypair?")
  - Tests covering all three credential paths.

Field-exposure filtering (M3) will hide `tenant_id` and `pubkey_hex` from
anonymous callers; v1 design retains operator and researcher visibility into
their own context.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass

router = APIRouter()


class WhoamiResponse(BaseModel):
    """The shape returned by `/auth/whoami`."""

    credential_class: CredentialClass = Field(
        description="One of: maintainer | researcher | anonymous"
    )
    tenant_id: str | None = Field(
        default=None,
        description="Researcher only: the tenant the signing pubkey is bound to.",
    )
    pubkey_hex: str | None = Field(
        default=None,
        description="Researcher only: the signing Ed25519 pubkey (hex).",
    )


def build_router(credential_dep) -> APIRouter:
    """Build the /auth router bound to a credential dependency.

    Returns a fresh APIRouter so `create_app()` can wire its own dependency
    closure without module-global state."""

    router = APIRouter()

    @router.get("/auth/whoami", response_model=WhoamiResponse)
    async def whoami(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WhoamiResponse:
        return WhoamiResponse(
            credential_class=credential.kind,
            tenant_id=credential.tenant_id,
            pubkey_hex=credential.pubkey_hex,
        )

    return router
