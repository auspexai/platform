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

NOTE: this module deliberately does NOT use `from __future__ import annotations`.
Its routes are wrapped by slowapi's `@limiter.limit`, whose wrapper carries
slowapi's module globals; with stringized annotations FastAPI resolves the
`body:` param against the wrong globals, fails to find the request model, and
mis-classifies it as a Query param (every POST-body route then 422s). Keeping
annotations as real objects sidesteps that. See CI-red postmortem 2026-05-30.
"""

import secrets
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import (
    IdentityProvider,
    IdentityVerificationMethod,
    TrustTier,
)
from auspexai_platform.db.repositories import AccountRepository, AuditRepository
from auspexai_platform.db.repositories.accounts import AccountNotFoundError, DuplicateAccountError
from auspexai_platform.db.repositories.vouches import VouchRepository
from auspexai_platform.db.repositories.workers import WorkerRepository
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


class PromoteRequest(BaseModel):
    target_tier: int = Field(ge=1, le=3)
    verification_method: IdentityVerificationMethod | None = None
    verification_note: str | None = None


class DemoteRequest(BaseModel):
    target_tier: int = Field(ge=0, le=2)
    reason: str


class SuspendRequest(BaseModel):
    reason: str | None = None


class AccountTrustResponse(BaseModel):
    account_id: str
    trust_tier: int
    trust_tier_name: str
    affected_worker_ids: list[str] = Field(default_factory=list)
    gate_override: bool = False
    gate_warnings: list[str] = Field(default_factory=list)


class VouchRequest(BaseModel):
    rationale: str | None = None


class VouchResponse(BaseModel):
    vouch_id: str
    voucher_account_id: str
    target_account_id: str
    rationale: str | None = None
    created_at: datetime
    revoked_at: datetime | None = None


# ---- helpers --------------------------------------------------------------


def _generate_account_id() -> str:
    """Generate a coordinator-side account_id. Format: 'acct-<12 url-safe chars>'."""
    return f"acct-{secrets.token_urlsafe(9)}"


# ---- router ---------------------------------------------------------------


def _require_maintainer(credential: Credential) -> None:
    if credential.kind != CredentialClass.MAINTAINER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")


def _tier_name(tier: int) -> str:
    names = {0: "T0 anonymous", 1: "T1 authenticated", 2: "T2 trusted", 3: "T3 vetted"}
    return names.get(tier, f"T{tier}")


def build_router(
    credential_dep,
    account_repository: AccountRepository,
    audit_repository: AuditRepository,
    identity_verifier: IdentityVerifier,
    worker_repository: WorkerRepository | None = None,
    vouch_repository: VouchRepository | None = None,
    receipt_index_repository=None,
    eligibility_thresholds=None,
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

    # ---- account list (maintainer-only) ------------------------------------

    @router.get("/accounts", status_code=status.HTTP_200_OK)
    async def list_accounts(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        _require_maintainer(credential)
        accounts = account_repository.list_all()
        return {
            "accounts": [
                {
                    "account_id": a.account_id,
                    "idp": a.idp.value,
                    "idp_sub": a.idp_sub,
                    "display_name": a.display_name,
                    "trust_tier": int(a.trust_tier),
                    "trust_tier_name": _tier_name(int(a.trust_tier)),
                    "created_at": a.created_at.isoformat(),
                    "retired_at": a.retired_at.isoformat() if a.retired_at else None,
                    "suspended_at": a.suspended_at.isoformat() if a.suspended_at else None,
                    "identity_verified_at": a.identity_verified_at.isoformat()
                    if a.identity_verified_at
                    else None,
                    "identity_verification_method": a.identity_verification_method.value
                    if a.identity_verification_method
                    else None,
                }
                for a in accounts
            ]
        }

    # ---- trust escalation (§6.2.3) ----------------------------------------

    @router.post(
        "/accounts/{account_id}/actions/promote",
        response_model=AccountTrustResponse,
        status_code=status.HTTP_200_OK,
    )
    async def promote_account(
        account_id: str,
        body: PromoteRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AccountTrustResponse:
        _require_maintainer(credential)
        assert worker_repository is not None

        account = account_repository.get_by_id(account_id)
        if account is None or account.retired_at is not None:
            raise HTTPException(status_code=404, detail="account not found")
        if account.suspended_at is not None:
            raise HTTPException(status_code=409, detail="account is suspended")

        current = account.trust_tier
        target = TrustTier(body.target_tier)
        if target != current + 1:
            raise HTTPException(
                status_code=422,
                detail=f"can only promote one step: current={current}, requested={int(target)}",
            )

        has_quarantined = any(
            w.quarantined_at is not None for w in worker_repository.list_for_account(account_id)
        )
        if has_quarantined:
            raise HTTPException(status_code=409, detail="account has quarantined workers")

        gate_warnings: list[str] = []
        if target == TrustTier.T2_TRUSTED:
            from auspexai_platform.eligibility import compute_t2_eligibility

            active_vouches = (
                vouch_repository.list_for_target(account_id) if vouch_repository else []
            )
            elig = compute_t2_eligibility(
                receipt_count=len(receipt_index_repository.list_for_account(account_id))
                if receipt_index_repository
                else 0,
                distinct_experiments=len(
                    {e.experiment_id for e in receipt_index_repository.list_for_account(account_id)}
                )
                if receipt_index_repository
                else 0,
                thresholds=eligibility_thresholds,
                account=account,
                active_vouches=active_vouches,
            )
            if not elig.receipt_threshold_met:
                gate_warnings.append(
                    f"receipt threshold not met ({elig.actuals['receipts']}/{elig.thresholds['receipts']})"
                )
            if not elig.distinct_experiments_threshold_met:
                gate_warnings.append(
                    f"distinct experiments threshold not met ({elig.actuals['distinct_experiments']}/{elig.thresholds['distinct_experiments']})"
                )
            if not elig.identity_gate.satisfied:
                gate_warnings.append("identity gate not satisfied (no verification or vouching)")
        elif target == TrustTier.T3_VETTED:
            if account.identity_verified_at is None:
                gate_warnings.append(
                    "identity not formally verified (T3 = personally vetted by Maintainer)"
                )
            entries = (
                receipt_index_repository.list_for_account(account_id)
                if receipt_index_repository
                else []
            )
            if not entries:
                gate_warnings.append("no receipt history")

        if body.verification_method is not None:
            account_repository.verify_identity(
                account_id,
                verified_by=credential.maintainer_login or "maintainer",
                method=body.verification_method,
                note=body.verification_note,
            )

        try:
            account = account_repository.promote(account_id, target_tier=target)
        except AccountNotFoundError:
            raise HTTPException(status_code=404, detail="account not found") from None

        affected = worker_repository.update_tier_for_account(account_id, trust_tier=target)

        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="account.promote",
            resource_type="account",
            resource_id=account_id,
            payload={
                "old_tier": int(current),
                "new_tier": int(target),
                "verification_method": body.verification_method.value
                if body.verification_method
                else None,
                "verification_note": body.verification_note,
                "affected_worker_ids": affected,
                "gate_override": bool(gate_warnings),
                "gate_warnings": gate_warnings,
            },
        )

        return AccountTrustResponse(
            account_id=account_id,
            trust_tier=int(target),
            trust_tier_name=_tier_name(int(target)),
            affected_worker_ids=affected,
            gate_override=bool(gate_warnings),
            gate_warnings=gate_warnings,
        )

    @router.post(
        "/accounts/{account_id}/actions/demote",
        response_model=AccountTrustResponse,
        status_code=status.HTTP_200_OK,
    )
    async def demote_account(
        account_id: str,
        body: DemoteRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AccountTrustResponse:
        _require_maintainer(credential)
        assert worker_repository is not None

        account = account_repository.get_by_id(account_id)
        if account is None or account.retired_at is not None:
            raise HTTPException(status_code=404, detail="account not found")

        current = account.trust_tier
        target = TrustTier(body.target_tier)
        if target >= current:
            raise HTTPException(
                status_code=422,
                detail=f"target tier must be lower: current={current}, requested={int(target)}",
            )

        try:
            account = account_repository.demote(account_id, target_tier=target)
        except AccountNotFoundError:
            raise HTTPException(status_code=404, detail="account not found") from None

        affected = worker_repository.update_tier_for_account(account_id, trust_tier=target)

        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="account.demote",
            resource_type="account",
            resource_id=account_id,
            payload={
                "old_tier": int(current),
                "new_tier": int(target),
                "reason": body.reason,
                "affected_worker_ids": affected,
            },
        )

        return AccountTrustResponse(
            account_id=account_id,
            trust_tier=int(target),
            trust_tier_name=_tier_name(int(target)),
            affected_worker_ids=affected,
        )

    @router.post(
        "/accounts/{account_id}/actions/suspend",
        response_model=AccountTrustResponse,
        status_code=status.HTTP_200_OK,
    )
    async def suspend_account(
        account_id: str,
        body: SuspendRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AccountTrustResponse:
        _require_maintainer(credential)
        assert worker_repository is not None

        try:
            account = account_repository.suspend(account_id)
        except AccountNotFoundError:
            raise HTTPException(status_code=404, detail="account not found") from None

        affected = worker_repository.quarantine_for_account(
            account_id, reason=f"account suspended: {body.reason or 'no reason given'}"
        )

        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="account.suspend",
            resource_type="account",
            resource_id=account_id,
            payload={
                "reason": body.reason,
                "affected_worker_ids": affected,
            },
        )

        return AccountTrustResponse(
            account_id=account_id,
            trust_tier=int(account.trust_tier),
            trust_tier_name=_tier_name(int(account.trust_tier)),
            affected_worker_ids=affected,
        )

    @router.post(
        "/accounts/{account_id}/actions/unsuspend",
        response_model=AccountTrustResponse,
        status_code=status.HTTP_200_OK,
    )
    async def unsuspend_account(
        account_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> AccountTrustResponse:
        _require_maintainer(credential)
        assert worker_repository is not None

        try:
            account = account_repository.unsuspend(account_id)
        except AccountNotFoundError:
            raise HTTPException(status_code=404, detail="account not found") from None

        affected = worker_repository.unquarantine_for_account(account_id)

        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="account.unsuspend",
            resource_type="account",
            resource_id=account_id,
            payload={"affected_worker_ids": affected},
        )

        return AccountTrustResponse(
            account_id=account_id,
            trust_tier=int(account.trust_tier),
            trust_tier_name=_tier_name(int(account.trust_tier)),
            affected_worker_ids=affected,
        )

    # ---- vouching (§6.2.2) ------------------------------------------------

    @router.post(
        "/accounts/{account_id}/vouches",
        response_model=VouchResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_vouch(
        account_id: str,
        body: VouchRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> VouchResponse:
        assert vouch_repository is not None

        if not credential.is_worker() or credential.account_id is None:
            raise HTTPException(
                status_code=403, detail="must be an authenticated worker with account binding"
            )
        if credential.trust_tier is None or credential.trust_tier < int(TrustTier.T2_TRUSTED):
            raise HTTPException(status_code=403, detail="voucher must be T2+")
        if credential.account_id == account_id:
            raise HTTPException(status_code=422, detail="cannot vouch for yourself")

        target = account_repository.get_by_id(account_id)
        if target is None or target.retired_at is not None:
            raise HTTPException(status_code=404, detail="target account not found")
        if target.trust_tier != TrustTier.T1_AUTHENTICATED:
            raise HTTPException(status_code=422, detail="can only vouch for T1 accounts")

        from auspexai_platform.db.repositories.vouches import DuplicateVouchError

        try:
            vouch = vouch_repository.create(
                voucher_account_id=credential.account_id,
                target_account_id=account_id,
                rationale=body.rationale,
            )
        except DuplicateVouchError:
            raise HTTPException(
                status_code=409, detail="already vouched for this account"
            ) from None

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="vouch.create",
            resource_type="account",
            resource_id=account_id,
            payload={
                "vouch_id": vouch.vouch_id,
                "voucher_account_id": credential.account_id,
                "rationale": body.rationale,
            },
        )

        return VouchResponse(
            vouch_id=vouch.vouch_id,
            voucher_account_id=vouch.voucher_account_id,
            target_account_id=vouch.target_account_id,
            rationale=vouch.rationale,
            created_at=vouch.created_at,
        )

    @router.delete(
        "/accounts/{account_id}/vouches/{vouch_id}",
        response_model=VouchResponse,
        status_code=status.HTTP_200_OK,
    )
    async def revoke_vouch(
        account_id: str,
        vouch_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> VouchResponse:
        assert vouch_repository is not None

        if not credential.is_worker() or credential.account_id is None:
            raise HTTPException(
                status_code=403, detail="must be an authenticated worker with account binding"
            )

        from auspexai_platform.db.repositories.vouches import VouchNotFoundError

        vouch = vouch_repository.get_by_id(vouch_id)
        if vouch is None or vouch.target_account_id != account_id:
            raise HTTPException(status_code=404, detail="vouch not found")
        if vouch.voucher_account_id != credential.account_id:
            raise HTTPException(status_code=403, detail="can only revoke your own vouches")

        try:
            vouch = vouch_repository.revoke(vouch_id)
        except VouchNotFoundError:
            raise HTTPException(status_code=404, detail="vouch not found") from None

        audit_repository.append(
            actor_class=CredentialClass.WORKER,
            actor_identifier=credential.pubkey_hex,
            action="vouch.revoke",
            resource_type="account",
            resource_id=account_id,
            payload={
                "vouch_id": vouch_id,
                "voucher_account_id": credential.account_id,
            },
        )

        return VouchResponse(
            vouch_id=vouch.vouch_id,
            voucher_account_id=vouch.voucher_account_id,
            target_account_id=vouch.target_account_id,
            rationale=vouch.rationale,
            created_at=vouch.created_at,
            revoked_at=vouch.revoked_at,
        )

    return router
