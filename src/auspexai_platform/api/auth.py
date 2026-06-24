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
    Ed25519 keypair?" — and "is my account suspended, and why?")
  - Tests covering all three credential paths.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.repositories.accounts import AccountRepository
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
    # Account-level suspension surfaced to the account holder (account-scoped):
    # a researcher whose account the maintainer suspended is entitled to know
    # that — and why — so the dashboard can show a banner. Mirrors the worker
    # quarantine_reason exposure (ratified 2026-05-30). Never visible to third
    # parties; the operator sees all.
    suspended_at: Annotated[datetime | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None,
        description="Account holder only: when the account was suspended, if it is.",
    )
    suspension_reason: Annotated[str | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None,
        description="Account holder only: the maintainer's reason for the suspension.",
    )
    # D9 Phase 4 (D4): the researcher's OWN research-standing + progress toward the
    # R2 review — surfaced to the account holder so the on-ramp is legible. Folded
    # into whoami so the dashboard renders it beside the existing identity/readiness
    # block (one coherent surface, no extra round-trip).
    research_standing: Annotated[int | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None, description="Account holder only: current research-standing (0-3)."
    )
    research_standing_distinct: Annotated[int | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None,
        description="Account holder only: distinct completed+attested experiments toward R2.",
    )
    research_standing_threshold: Annotated[int | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None, description="Account holder only: the R2-review threshold (K)."
    )
    research_standing_eligible_for_r2: Annotated[bool | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None, description="Account holder only: cleared the R2-review threshold."
    )
    orcid_id: Annotated[str | None, ExposureTag.ACCOUNT_SCOPED] = Field(
        default=None, description="Account holder only: the linked ORCID iD (D8), if any."
    )


def build_router(credential_dep, account_repository: AccountRepository | None = None) -> APIRouter:
    """Build the /auth router bound to a credential dependency.

    `account_repository` is used to surface the caller's own account-suspension
    state; when omitted (e.g. minimal test apps) suspension fields stay None."""

    router = APIRouter()

    @router.get(
        "/auth/whoami",
        response_model=WhoamiResponse,
        response_model_exclude_none=True,
    )
    async def whoami(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> WhoamiResponse:
        suspended_at = None
        suspension_reason = None
        research_standing = None
        rs_distinct = None
        rs_threshold = None
        rs_eligible = None
        orcid_id = None
        if account_repository is not None and credential.account_id is not None:
            account = account_repository.get_by_id(credential.account_id)
            if account is not None:
                suspended_at = account.suspended_at
                suspension_reason = account.suspension_reason
                orcid_id = account.orcid_id
                rs = account_repository.research_standing_summary(credential.account_id)
                research_standing = int(rs.current)
                rs_distinct = rs.distinct_clean_completed_verified
                rs_threshold = rs.threshold
                rs_eligible = rs.eligible_for_r2_review

        payload = WhoamiResponse(
            credential_class=credential.kind,
            tenant_id=credential.tenant_id,
            pubkey_hex=credential.pubkey_hex,
            suspended_at=suspended_at,
            suspension_reason=suspension_reason,
            research_standing=research_standing,
            research_standing_distinct=rs_distinct,
            research_standing_threshold=rs_threshold,
            research_standing_eligible_for_r2=rs_eligible,
            orcid_id=orcid_id,
        )
        return filter_for_credential(
            payload,
            credential,
            resource_tenant_id=credential.tenant_id,
            resource_account_id=credential.account_id,
        )

    return router
