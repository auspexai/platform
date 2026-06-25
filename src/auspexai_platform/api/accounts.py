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

import os
import secrets
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import enforce_worker_active
from auspexai_platform.auth.self_signed import verify_self_signed_request
from auspexai_platform.db.models import (
    IdentityProvider,
    IdentityVerificationMethod,
    ResearchStanding,
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
from auspexai_platform.oauth.orcid import OrcidOAuthClient
from auspexai_platform.rate_limit import limiter

# Where the ORCID callback bounces the researcher's browser when done. It's
# their OWN local dashboard (127.0.0.1 resolves to each researcher's machine),
# so one default works for everyone; the SPA reads ?orcid=… and shows the result.
_ORCID_SUCCESS_URL = os.environ.get("AUSPEXAI_ORCID_SUCCESS_URL", "http://127.0.0.1:4228/")

# §6.2.2 anti-Sybil vouch gate: a voucher must have done real work across more
# than one tenant before its vouch can feed a peer's identity gate — so a single
# attacker can't spin up vouchers without first earning a cross-tenant track
# record. A single vouch is sufficient in Phase 1, which makes this threshold the
# load-bearing Sybil defense.
VOUCH_MIN_RECEIPTS = 20
VOUCH_MIN_DISTINCT_TENANTS = 2

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


class AccountBindResponse(BaseModel):
    """Wire shape for a Tier-1 account-key bind. PUBLIC — the calling key proved
    possession but isn't a registered credential at bind time."""

    account_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    idp: Annotated[str | None, ExposureTag.PUBLIC] = None
    display_name: Annotated[str | None, ExposureTag.PUBLIC] = None
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


class PromoteResearchStandingRequest(BaseModel):
    # R2 (established → BYOT) or R3 (trusted → high-risk eligible). R1 is the bound
    # default; R0 is the no-account state. One step up at a time.
    target: int = Field(ge=2, le=3)
    reason: str  # mandatory — every trust action carries a recorded reason


class ResearchStandingResponse(BaseModel):
    account_id: str
    research_standing: int
    research_standing_name: str
    gate_override: bool = False
    gate_warnings: list[str] = Field(default_factory=list)


class ResearchDossierResponse(BaseModel):
    """The reviewer's view (D8): the standing summary + the attested experiment
    history a human judges before promoting — not a rubber-stamp on a handle."""

    account_id: str
    current: int
    current_name: str
    distinct_clean_completed_verified: int
    threshold: int
    eligible_for_r2_review: bool
    experiments: list[dict] = Field(default_factory=list)


class LinkOrcidRequest(BaseModel):
    # The ORCID OAuth access token from the researcher's ORCID sign-in. idp is
    # implicitly ORCID — this endpoint links, it does not root an account.
    access_token: str = Field(min_length=1, description="ORCID OAuth access token")


class LinkOrcidResponse(BaseModel):
    account_id: str
    orcid_id: str
    identity_verified_at: datetime | None = None
    identity_verification_method: str | None = None


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
    vouch_min_receipts: int = VOUCH_MIN_RECEIPTS,
    vouch_min_distinct_tenants: int = VOUCH_MIN_DISTINCT_TENANTS,
    trust_model_policy_repository=None,  # firewall #1 (A2) flip toggle; OFF when unwired
    orcid_oauth_client: OrcidOAuthClient | None = None,  # D8; reads env config when None
) -> APIRouter:
    """Build /accounts router bound to repository instances + verifier."""

    router = APIRouter()
    orcid_oauth_client = orcid_oauth_client or OrcidOAuthClient()

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

    @router.post(
        "/accounts/bind",
        response_model=AccountBindResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit("30/hour")
    async def account_bind(
        request: Request,
        body: OAuthExchangeRequest,
    ) -> AccountBindResponse:
        """Tier-1 onboarding: bind the caller's dashboard key DIRECTLY to an
        account — no tenant, no approval (like a worker connecting GitHub). The
        request is RFC 9421-signed by the binding key (proof of possession); the
        body carries the verified IdP token (GitHub or ORCID). The bound key then
        resolves to a CredentialClass.ACCOUNT and can run certified public
        starters. Re-binding (even via a different IdP) rebinds to the current
        account (upsert)."""
        pubkey_hex = await verify_self_signed_request(request)
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

        # Find or create the account (same volunteer-enrollment pattern + create race).
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

        account_repository.bind_key(account.account_id, pubkey_hex)
        audit_repository.append(
            actor_class=CredentialClass.ACCOUNT,
            actor_identifier=account.display_name or account.account_id,
            action="account.key_bound",
            resource_type="account",
            resource_id=account.account_id,
            payload={"idp": claim.idp.value, "is_new_account": is_new},
        )
        return AccountBindResponse(
            account_id=account.account_id,
            idp=claim.idp.value,
            display_name=account.display_name,
            is_new_account=is_new,
        )

    # ---- account list (maintainer-only) ------------------------------------

    @router.get("/accounts", status_code=status.HTTP_200_OK)
    async def list_accounts(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        _require_maintainer(credential)
        accounts = account_repository.list_all()

        def _t2_readiness(account) -> dict | None:
            """Proactive promotion-readiness for a T1 account (the T1→T2 step):
            receipts/distinct progress + identity-gate status, so the maintainer
            sees WHO has earned it at a glance rather than learning post-hoc via a
            gate-override warning. Only computed for T1 (the promotable tier)."""
            if account.trust_tier != TrustTier.T1_AUTHENTICATED:
                return None
            if receipt_index_repository is None or eligibility_thresholds is None:
                return None
            from auspexai_platform.eligibility import compute_t2_eligibility

            receipt_count, distinct_tenants = receipt_index_repository.account_receipt_summary(
                account.account_id
            )
            active_vouches = (
                vouch_repository.list_for_target(account.account_id) if vouch_repository else []
            )
            elig = compute_t2_eligibility(
                receipt_count=receipt_count,
                distinct_tenants=distinct_tenants,
                thresholds=eligibility_thresholds,
                account=account,
                active_vouches=active_vouches,
            )
            return {
                "receipts": elig.actuals["receipts"],
                "receipts_required": elig.thresholds["receipts"],
                "distinct_tenants": elig.actuals["distinct_tenants"],
                "distinct_required": elig.thresholds["distinct_tenants"],
                "account_age_days": elig.actuals["account_age_days"],
                "min_account_age_days": elig.thresholds["min_account_age_days"],
                "identity_satisfied": elig.identity_gate.satisfied,
                "ready": elig.ready_for_human_review,
            }

        def _r2_readiness(account) -> dict | None:
            """Proactive R2 review-readiness for an R1 account (the R1→R2 step):
            distinct attested experiments toward the threshold, so the maintainer sees
            WHO has earned the review AT A GLANCE on the list, not buried in a detail
            page. Only computed for R1 (the promotable research tier). Mirrors
            `_t2_readiness` (compute side)."""
            if account.research_standing != ResearchStanding.R1_VERIFIED:
                return None
            s = account_repository.research_standing_summary(account.account_id)
            return {
                "distinct": s.distinct_clean_completed_verified,
                "threshold": s.threshold,
                "ready": s.eligible_for_r2_review,
            }

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
                    "suspension_reason": a.suspension_reason,
                    "identity_verified_at": a.identity_verified_at.isoformat()
                    if a.identity_verified_at
                    else None,
                    "identity_verification_method": a.identity_verification_method.value
                    if a.identity_verification_method
                    else None,
                    "orcid_id": a.orcid_id,
                    "t2_readiness": _t2_readiness(a),
                    "research_standing": int(a.research_standing),
                    "r2_readiness": _r2_readiness(a),
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
            _rc, _dt = (
                receipt_index_repository.account_receipt_summary(account_id)
                if receipt_index_repository
                else (0, 0)
            )
            elig = compute_t2_eligibility(
                receipt_count=_rc,
                distinct_tenants=_dt,
                thresholds=eligibility_thresholds,
                account=account,
                active_vouches=active_vouches,
            )
            if not elig.receipt_threshold_met:
                gate_warnings.append(
                    f"receipt threshold not met ({elig.actuals['receipts']}/{elig.thresholds['receipts']})"
                )
            if not elig.distinct_tenants_threshold_met:
                gate_warnings.append(
                    f"distinct-tenants breadth not met ({elig.actuals['distinct_tenants']}/{elig.thresholds['distinct_tenants']})"
                )
            if not elig.account_age_threshold_met:
                gate_warnings.append(
                    f"account-age window not met ({elig.actuals['account_age_days']}/{elig.thresholds['min_account_age_days']} days)"
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
            account = account_repository.promote(
                account_id, target_tier=target, set_by_class=CredentialClass.MAINTAINER
            )
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
        "/accounts/{account_id}/actions/promote-research-standing",
        response_model=ResearchStandingResponse,
        status_code=status.HTTP_200_OK,
    )
    async def promote_research_standing(
        account_id: str,
        body: PromoteResearchStandingRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ResearchStandingResponse:
        """Promote an account's research-standing ONE step (R1→R2 / R2→R3). A HUMAN
        act (ethics review / maintainer vetting) — NEVER auto: the standing summary
        only earns the review. Warn-but-allow on the R2 competence gate; the reason
        is recorded either way. See vigiles_onramp_phase4_design.md §0/§1/§8 D2."""
        _require_maintainer(credential)
        account = account_repository.get_by_id(account_id)
        if account is None or account.retired_at is not None:
            raise HTTPException(status_code=404, detail="account not found")
        if account.suspended_at is not None:
            raise HTTPException(status_code=409, detail="account is suspended")

        current = account.research_standing
        target = ResearchStanding(body.target)
        if int(target) != int(current) + 1:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"can only promote one step: current={int(current)}, requested={int(target)}"
                ),
            )

        gate_warnings: list[str] = []
        if target == ResearchStanding.R2_ESTABLISHED:
            summary = account_repository.research_standing_summary(account_id)
            if not summary.eligible_for_r2_review:
                gate_warnings.append(
                    "R2 competence threshold not met "
                    f"({summary.distinct_clean_completed_verified}/{summary.threshold} "
                    "distinct, completed, evidence-attested experiments) — promoting "
                    "below the floor"
                )
        elif target == ResearchStanding.R3_TRUSTED:
            # R2→R3 is a trust judgment competence can't prove (arc §3.3): NO
            # mechanical criterion — out-of-band vetting (verify a real affiliation /
            # linked ORCID) before granting high-risk eligibility.
            if account.identity_verified_at is None:
                gate_warnings.append(
                    "R3 is a trust judgment, not a competence threshold — verify the "
                    "researcher's real identity/affiliation (e.g. a linked ORCID) "
                    "out-of-band; on-network history cannot establish it"
                )

        account = account_repository.set_research_standing(account_id, new_standing=target)
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="account.promote_research_standing",
            resource_type="account",
            resource_id=account_id,
            payload={
                "old_standing": int(current),
                "new_standing": int(target),
                "reason": body.reason,
                "gate_override": bool(gate_warnings),
                "gate_warnings": gate_warnings,
            },
        )
        return ResearchStandingResponse(
            account_id=account_id,
            research_standing=int(target),
            research_standing_name=target.name,
            gate_override=bool(gate_warnings),
            gate_warnings=gate_warnings,
        )

    @router.post(
        "/accounts/{account_id}/actions/link-orcid",
        response_model=LinkOrcidResponse,
        status_code=status.HTTP_200_OK,
    )
    async def link_orcid(
        account_id: str,
        body: LinkOrcidRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> LinkOrcidResponse:
        """Link an ORCID iD to the account (D8) — the citation-grade academic
        identity. Self-service (the account owner) or maintainer-on-behalf.
        Verifies the ORCID access token via the IdP, stores the ORCID iD, and
        marks the account identity-verified (method=ORCID) — which the R2→R3
        vetting gate reads. A *linked* identity: the account stays GitHub-rooted.
        Audited."""
        is_maintainer = credential.kind == CredentialClass.MAINTAINER
        if not is_maintainer and credential.account_id != account_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="you can only link an ORCID to your own account",
            )
        account = account_repository.get_by_id(account_id)
        if account is None or account.retired_at is not None:
            raise HTTPException(status_code=404, detail="account not found")
        if account.suspended_at is not None:
            raise HTTPException(status_code=409, detail="account is suspended")
        try:
            claim = identity_verifier.verify(IdentityProvider.ORCID, body.access_token)
        except UnknownIdentityProviderError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ORCID identity provider is not enabled",
            ) from e
        except InvalidAccessTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": "invalid_access_token",
                        "message": "ORCID did not accept the supplied access token",
                        "details": {"reason": str(e)},
                    }
                },
            ) from e
        account = account_repository.link_orcid(
            account_id, orcid_id=claim.idp_sub, display_name=claim.display_name
        )
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.maintainer_login or credential.account_id or "self",
            action="account.link_orcid",
            resource_type="account",
            resource_id=account_id,
            payload={
                "orcid_id": claim.idp_sub,
                "linked_by": "maintainer" if is_maintainer else "self",
            },
        )
        return LinkOrcidResponse(
            account_id=account_id,
            orcid_id=claim.idp_sub,
            identity_verified_at=account.identity_verified_at,
            identity_verification_method=(
                account.identity_verification_method.value
                if account.identity_verification_method
                else None
            ),
        )

    @router.post("/accounts/orcid/start", status_code=status.HTTP_200_OK)
    async def orcid_start(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """Begin linking the caller's ORCID (D8). Returns the ORCID authorize URL
        the dashboard opens; a single-use state binds the eventual callback to the
        caller's account. Requires an account (researcher) credential."""
        if credential.account_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="an account credential is required to link ORCID",
            )
        if not orcid_oauth_client.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ORCID linking is not configured on this coordinator",
            )
        state = secrets.token_urlsafe(24)
        account_repository.create_orcid_state(state, credential.account_id)
        return {"authorize_url": orcid_oauth_client.authorize_url(state)}

    @router.get("/accounts/orcid/callback")
    async def orcid_callback(
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ) -> RedirectResponse:
        """ORCID redirects the researcher's browser here after they authorize.
        Public (no credential): the single-use `state` is the binding to the
        account. Exchanges the code for the ORCID iD, links it, and bounces the
        browser back to the researcher's local dashboard with ?orcid=…."""

        def _back(result: str) -> RedirectResponse:
            sep = "&" if "?" in _ORCID_SUCCESS_URL else "?"
            return RedirectResponse(f"{_ORCID_SUCCESS_URL}{sep}orcid={result}", status_code=302)

        if error or not code or not state:
            return _back("error")
        account_id = account_repository.consume_orcid_state(state)
        if account_id is None:
            return _back("expired")
        try:
            link = orcid_oauth_client.exchange_code(code)
        except InvalidAccessTokenError:
            return _back("error")
        try:
            account = account_repository.link_orcid(
                account_id, orcid_id=link.orcid_id, display_name=link.name
            )
        except AccountNotFoundError:
            return _back("error")
        # The browser callback is unauthenticated (an ORCID redirect carries no
        # credential), but the single-use `state` proves the ACCOUNT owner drove
        # it — attribute the link to that researcher account (its verified login),
        # not anonymous, so the audit is legible.
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=account.display_name or account_id,
            action="account.link_orcid",
            resource_type="account",
            resource_id=account_id,
            payload={"orcid_id": link.orcid_id, "linked_by": "self_orcid_oauth"},
        )
        return _back("linked")

    @router.get(
        "/accounts/{account_id}/research-standing",
        response_model=ResearchDossierResponse,
        status_code=status.HTTP_200_OK,
    )
    async def research_standing_dossier(
        account_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ResearchDossierResponse:
        """The reviewer's dossier (D8): the standing summary + the attested
        experiment history a human reads before promoting. Maintainer-only."""
        _require_maintainer(credential)
        account = account_repository.get_by_id(account_id)
        if account is None or account.retired_at is not None:
            raise HTTPException(status_code=404, detail="account not found")
        summary = account_repository.research_standing_summary(account_id)
        return ResearchDossierResponse(
            account_id=account_id,
            current=int(summary.current),
            current_name=summary.current.name,
            distinct_clean_completed_verified=summary.distinct_clean_completed_verified,
            threshold=summary.threshold,
            eligible_for_r2_review=summary.eligible_for_r2_review,
            experiments=account_repository.research_standing_history(account_id),
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
            account = account_repository.demote(
                account_id, target_tier=target, set_by_class=CredentialClass.MAINTAINER
            )
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
            account = account_repository.suspend(account_id, reason=body.reason)
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
        # F3: vouching is the anti-Sybil chokepoint. A suspended account's (or
        # quarantined worker's) vouch must not count — the tier on the
        # credential alone is not enough.
        enforce_worker_active(credential, worker_repository, account_repository)
        if credential.trust_tier is None or credential.trust_tier < int(TrustTier.T2_TRUSTED):
            raise HTTPException(status_code=403, detail="voucher must be T2+")
        # §6.2.2 anti-Sybil: the voucher must hold a real cross-tenant track
        # record before its vouch counts (a vouch is enough to satisfy the
        # target's identity gate, so this is the Sybil chokepoint).
        if receipt_index_repository is not None:
            # A4 firewall #3 floor: count DISTINCT corroborated units per account,
            # not raw receipts — a voucher can't farm the bar with N workers under
            # one account redundantly covering the same units.
            _equal_trust = (
                trust_model_policy_repository.get().equal_trust_enabled
                if trust_model_policy_repository is not None
                else False
            )
            corroborations, tenants = receipt_index_repository.account_corroboration_summary(
                credential.account_id, equal_trust_enabled=_equal_trust
            )
            if corroborations < vouch_min_receipts or tenants < vouch_min_distinct_tenants:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"voucher must hold ≥{vouch_min_receipts} corroborated units across "
                        f"≥{vouch_min_distinct_tenants} tenants (anti-Sybil, §6.2.2); "
                        f"has {corroborations} across {tenants}"
                    ),
                )
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
        # F3: a suspended/quarantined voucher cannot mutate the vouch graph.
        enforce_worker_active(credential, worker_repository, account_repository)

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
