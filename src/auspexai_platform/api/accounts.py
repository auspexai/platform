"""Account routes — /api/v0/accounts.

  POST /api/v0/accounts/oauth/exchange  — anonymous-public; exchange an IdP
                                            access token for an account
                                            binding.

Flow:

  1. Caller (worker, researcher dashboard) completes an OAuth 2.0 Device
     Authorization Flow (RFC 8628) with the IdP directly. The IdP returns
     an access token to the caller. Per the GitHub OAuth App's public-client
     model, the Client ID ships in caller source code; the coordinator does
     not proxy the device flow itself.
  2. Caller POSTs {idp, access_token} to /oauth/exchange. The coordinator
     calls the IdP's user-info endpoint to verify the token and resolve the
     stable IdP subject identifier (e.g., GitHub numeric user id).
  3. Coordinator creates (or fetches) an account row keyed on
     (idp, idp_sub) and mints a short-lived (5 min) one-shot binding token.
  4. Caller passes the binding token to a downstream binder endpoint
     (M6b's POST /workers/{id}/upgrade for worker promotion, or the
     researcher SDK init) which consumes it atomically and binds the
     caller's identity (pubkey) to the account.

Anonymous-public on the call boundary because the IdP access token is itself
the unforgeable proof — token forgery is the IdP's threat model. Rate
limiting falls out of the IdP's device-flow code expiry (one access token
per completed flow).
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import AccountRepository, AuditRepository
from auspexai_platform.db.repositories.accounts import DuplicateAccountError
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.oauth import (
    IdentityVerifier,
    InvalidAccessTokenError,
    UnknownIdentityProviderError,
)
from auspexai_platform.rate_limit import limiter

# ---- request / response models --------------------------------------------


class OAuthExchangeRequest(BaseModel):
    idp: IdentityProvider = Field(description="Identity provider that issued the access token")
    access_token: str = Field(
        min_length=1,
        description="Access token returned by the caller's IdP device flow",
    )


class OAuthExchangeResponse(BaseModel):
    """Wire shape for an exchange result. All fields PUBLIC — the caller is
    anonymous-by-class at exchange time."""

    account_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    binding_token: Annotated[str | None, ExposureTag.PUBLIC] = None
    expires_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    is_new_account: Annotated[bool | None, ExposureTag.PUBLIC] = None


# ---- helpers --------------------------------------------------------------


def _generate_account_id() -> str:
    """Generate a coordinator-side account_id. Format: 'acct-<12 url-safe chars>'."""
    return f"acct-{secrets.token_urlsafe(9)}"


# ---- router ---------------------------------------------------------------


def build_router(
    credential_dep,
    account_repository: AccountRepository,
    audit_repository: AuditRepository,
    identity_verifier: IdentityVerifier,
) -> APIRouter:
    """Build /accounts router bound to repository instances + verifier."""

    router = APIRouter()

    @router.post(
        "/accounts/oauth/exchange",
        response_model=OAuthExchangeResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit("30/hour")
    async def oauth_exchange(
        request: Request,
        body: OAuthExchangeRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> OAuthExchangeResponse:
        # Verify the access token with the IdP. The token itself is the
        # unforgeable proof; the call boundary is anonymous-public.
        try:
            claim = identity_verifier.verify(body.idp, body.access_token)
        except UnknownIdentityProviderError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "unsupported_idp",
                        "message": f"identity provider {body.idp.value!r} not enabled",
                        "details": {"idp": body.idp.value},
                    }
                },
            ) from e
        except InvalidAccessTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "invalid_access_token",
                        "message": "the IdP did not accept the supplied access token",
                        "details": {"reason": str(e)},
                    }
                },
            ) from e

        # Find or create the account row.
        existing = account_repository.get_by_idp_subject(claim.idp, claim.idp_sub)
        if existing is not None:
            account = existing
            is_new = False
        else:
            try:
                account = account_repository.create(
                    account_id=_generate_account_id(),
                    idp=claim.idp,
                    idp_sub=claim.idp_sub,
                    display_name=claim.display_name,
                    email=claim.email,
                )
                is_new = True
            except DuplicateAccountError:
                # Race: another request created it between get + create.
                # Re-read; it must exist now.
                reread = account_repository.get_by_idp_subject(claim.idp, claim.idp_sub)
                if reread is None:  # pragma: no cover — defensive
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail={
                            "error": {
                                "code": "account_create_race",
                                "message": "account create raced and reread failed",
                            }
                        },
                    ) from None
                account = reread
                is_new = False

        binding = account_repository.issue_binding(account.account_id)

        audit_repository.append(
            actor_class=CredentialClass.ANONYMOUS,
            action="account.oauth_exchange",
            resource_type="account",
            resource_id=account.account_id,
            payload={
                "idp": claim.idp.value,
                "is_new_account": is_new,
                "binding_token_expires_at": binding.expires_at.isoformat(),
            },
        )

        return filter_for_credential(
            OAuthExchangeResponse(
                account_id=account.account_id,
                binding_token=binding.binding_token,
                expires_at=binding.expires_at,
                is_new_account=is_new,
            ),
            credential,
        )

    return router
