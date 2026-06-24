"""Tenant-application pipeline — researcher onboarding Option D (ratified).

`auspexai-tenant apply` runs the GitHub Device Flow client-side, then POSTs an
application SIGNED BY THE APPLYING KEY:

  POST /api/v0/tenant-applications                — submit. RFC 9421-signed,
                                                    verified against ITS OWN
                                                    keyid (the applying pubkey,
                                                    an UNREGISTERED key — this
                                                    is deliberate proof of
                                                    possession, THIS surface
                                                    only). The GitHub access
                                                    token is verified via the
                                                    same identity machinery as
                                                    volunteer enrollment and
                                                    the account row is
                                                    resolved-or-created.
  GET  /api/v0/tenant-applications[?status_filter=] — maintainer-only queue.
                                                    Each row carries
                                                    account_existing_tenants:
                                                    tenant_ids already linked
                                                    to the application's
                                                    account (review context
                                                    for deliberate multi-
                                                    tenancy-per-account
                                                    decisions). NOT on /mine.
  GET  /api/v0/tenant-applications/mine           — signed by the applying key
                                                    (same self-keyid check);
                                                    that key's applications.
  POST .../actions/approve                        — maintainer: atomically
                                                    create the tenant (id =
                                                    override or requested),
                                                    bind the applying pubkey as
                                                    maintainer_pubkey, link
                                                    tenants.account_id.
  POST .../actions/decline                        — maintainer, with a
                                                    mandatory, audited reason.

NOTE: this module deliberately does NOT use `from __future__ import annotations`.
The submit route is wrapped by slowapi's `@limiter.limit`, whose wrapper
carries slowapi's module globals; with stringized annotations FastAPI resolves
the `body:` param against the wrong globals and mis-classifies it as a Query
param (the route then 422s). See CI-red postmortem 2026-05-30.
"""

import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.errors import AuthError
from auspexai_platform.auth.signature import RequestSummary, verify_request
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
    TenantApplicationRepository,
)
from auspexai_platform.db.repositories.accounts import DuplicateAccountError
from auspexai_platform.db.repositories.tenant_applications import (
    ApplicationNotPendingError,
    TenantApplication,
)
from auspexai_platform.db.repositories.tenants import DuplicateTenantError, TenantRepository
from auspexai_platform.events import EventBus
from auspexai_platform.oauth import (
    IdentityVerifier,
    InvalidAccessTokenError,
    UnknownIdentityProviderError,
)
from auspexai_platform.rate_limit import limiter

# ---- research-class taxonomy --------------------------------------------------

# The §11 research-envelope enabled-today classes. An application may declare
# which of these its work falls under (validated, deduplicated); `other` is
# the deliberate escape hatch for work the envelope does not yet name.
RESEARCH_CLASSES: tuple[str, ...] = (
    "behavioral_drift",
    "eval_sweeps",
    "refusal_boundary_mapping",
    "cross_model_comparison",
    "quantization_effects",
    "prompt_sensitivity",
    "other",
)

_RESEARCH_CLASS_SET = frozenset(RESEARCH_CLASSES)


# ---- request / response models ----------------------------------------------


class TenantApplicationCreate(BaseModel):
    # Exactly one identity token roots the account: GitHub (the default) or ORCID
    # (the researcher persona — an ORCID-rooted account is identity-verified at
    # creation, so it reaches R3 without a separate link). Enforced by
    # _require_exactly_one_identity below.
    github_access_token: str | None = Field(
        default=None, min_length=1, description="Access token from the caller's GitHub device flow"
    )
    orcid_access_token: str | None = Field(
        default=None,
        min_length=1,
        description="Access token from the caller's ORCID OAuth — roots the account on ORCID",
    )
    requested_tenant_id: str = Field(min_length=1, max_length=64)
    contact_name: str = Field(min_length=1, max_length=200)
    affiliation: str = Field(min_length=1, max_length=200)
    research_summary: str | None = Field(default=None, max_length=4000)
    research_classes: list[str] = Field(
        default_factory=list,
        description=f"Structured research classes; each must be one of {RESEARCH_CLASSES}",
    )

    @field_validator("research_classes")
    @classmethod
    def _validate_research_classes(cls, v: list[str]) -> list[str]:
        unknown = [c for c in v if c not in _RESEARCH_CLASS_SET]
        if unknown:
            raise ValueError(
                f"unknown research class(es) {unknown!r}; valid classes: {list(RESEARCH_CLASSES)}"
            )
        deduped = list(dict.fromkeys(v))  # order-preserving dedupe
        if len(deduped) > len(RESEARCH_CLASSES):  # pragma: no cover — taxonomy-bounded
            raise ValueError(f"at most {len(RESEARCH_CLASSES)} research classes")
        return deduped

    @model_validator(mode="after")
    def _require_classes_or_summary(self) -> "TenantApplicationCreate":
        if not self.research_classes and not self.research_summary:
            raise ValueError(
                "at least one of research_classes (non-empty list) or "
                "research_summary (non-empty string) is required"
            )
        return self

    @model_validator(mode="after")
    def _require_exactly_one_identity(self) -> "TenantApplicationCreate":
        if bool(self.github_access_token) == bool(self.orcid_access_token):
            raise ValueError("provide exactly one of github_access_token or orcid_access_token")
        return self


class TenantApplicationSubmitResponse(BaseModel):
    application_id: str
    status: str
    # #6 applicant-side multiplicity heads-up: tenant_ids the applicant's account
    # already operates. Multi-tenancy is ALLOWED (§6.9 — review is the gate), so
    # this is informational, not a block: the CLI warns that the application
    # requests an ADDITIONAL tenant so an accidental second application is caught
    # immediately (while it is still only pending). Empty for a first tenant.
    account_existing_tenants: list[str] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    tenant_id_override: str | None = Field(default=None, min_length=1, max_length=64)


class DeclineRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class TenantApplicationResponse(BaseModel):
    application_id: str
    account_id: str
    github_login: str | None
    requested_tenant_id: str
    contact_name: str
    affiliation: str
    research_summary: str
    research_classes: list[str]
    pubkey_hex: str
    status: str
    created_at: datetime
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_reason: str | None
    created_tenant_id: str | None
    # D2 review context (maintainer queue only): tenant_ids already linked to
    # this application's account, so a second-tenant-for-the-same-account
    # approval is a deliberate decision, not a surprise. Populated by the
    # GET /tenant-applications list route; defaults to [] elsewhere.
    account_existing_tenants: list[str] = Field(default_factory=list)


class TenantApplicationListResponse(BaseModel):
    applications: list[TenantApplicationResponse]


class MyApplicationResponse(BaseModel):
    """Applicant-facing view: status + outcome only (no foreign fields)."""

    application_id: str
    status: str
    resolution_reason: str | None
    created_tenant_id: str | None


class MyApplicationListResponse(BaseModel):
    applications: list[MyApplicationResponse]


# ---- self-keyid (proof-of-possession) verification ---------------------------


class _SelfKeyResolver:
    """Resolves ANY keyid to a credential carrying that keyid as pubkey_hex.

    This deliberately skips registry lookup: the applying key is not yet
    registered anywhere, and what the application surface needs is proof that
    the caller POSSESSES the private half of the key it asks the coordinator
    to bind (`verify_request` still checks the Ed25519 signature against the
    keyid bytes). Used by THIS route module only — every other signed surface
    resolves keyids through the tenant/worker registries.
    """

    def resolve(self, pubkey_hex: str) -> Credential:
        return Credential(kind=CredentialClass.ANONYMOUS, pubkey_hex=pubkey_hex)


_SELF_RESOLVER = _SelfKeyResolver()


async def _verify_applying_key(request: Request) -> str:
    """Verify the RFC 9421 signature against its own keyid; return the keyid.

    Raises HTTPException(401) on missing headers or any signature failure,
    using the same error envelope as the standard auth dependency.
    """
    signature_input_header = request.headers.get("Signature-Input")
    signature_header = request.headers.get("Signature")
    if not signature_input_header or not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "signature_required",
                    "message": (
                        "this endpoint requires an RFC 9421 signature by the "
                        "applying key (Signature-Input + Signature headers)"
                    ),
                    "details": {},
                }
            },
        )
    body = await request.body()
    summary = RequestSummary(
        method=request.method,
        path=request.url.path,
        authority=request.url.netloc,
        body=body,
        signature_input_header=signature_input_header,
        signature_header=signature_header,
        content_digest_header=request.headers.get("Content-Digest"),
    )
    try:
        credential = verify_request(summary, _SELF_RESOLVER)
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": e.code, "message": e.message, "details": e.details}},
        ) from e
    assert credential.pubkey_hex is not None
    return credential.pubkey_hex


# ---- helpers ------------------------------------------------------------------


def _generate_account_id() -> str:
    """Coordinator-side account_id, same format as the OAuth-exchange surface."""
    return f"acct-{secrets.token_urlsafe(9)}"


def _require_maintainer(credential: Credential) -> None:
    if not credential.is_maintainer():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")


def _to_response(
    a: TenantApplication, *, account_existing_tenants: list[str] | None = None
) -> TenantApplicationResponse:
    return TenantApplicationResponse(
        application_id=a.application_id,
        account_id=a.account_id,
        github_login=a.github_login,
        requested_tenant_id=a.requested_tenant_id,
        contact_name=a.contact_name,
        affiliation=a.affiliation,
        research_summary=a.research_summary,
        research_classes=a.research_classes,
        pubkey_hex=a.pubkey_hex,
        status=a.status,
        created_at=a.created_at,
        resolved_at=a.resolved_at,
        resolved_by=a.resolved_by,
        resolution_reason=a.resolution_reason,
        created_tenant_id=a.created_tenant_id,
        account_existing_tenants=account_existing_tenants or [],
    )


# ---- router -------------------------------------------------------------------


def build_router(
    credential_dep,
    tenant_application_repository: TenantApplicationRepository,
    account_repository: AccountRepository,
    audit_repository: AuditRepository,
    identity_verifier: IdentityVerifier,
    *,
    tenant_repository: TenantRepository,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    def _publish(event_type: str, data: dict) -> None:
        if event_bus is not None:
            event_bus.publish(event_type, experiment_id=None, data=data)

    @router.post(
        "/tenant-applications",
        response_model=TenantApplicationSubmitResponse,
        status_code=status.HTTP_201_CREATED,
    )
    @limiter.limit("10/hour")
    async def submit_tenant_application(
        request: Request,
        body: TenantApplicationCreate,
    ) -> TenantApplicationSubmitResponse:
        # 1. Proof of possession: the signature must verify against the keyid
        #    it claims. Deliberately NOT the standard credential dependency —
        #    the applying key is unregistered by design.
        pubkey_hex = await _verify_applying_key(request)

        # 2. Verify the identity token (GitHub or ORCID — exactly one, enforced
        #    by the request model). ORCID roots the account on ORCID (researcher
        #    persona); GitHub is the default. Same identity machinery as volunteer
        #    enrollment (token forgery is the IdP's threat model).
        idp = IdentityProvider.ORCID if body.orcid_access_token else IdentityProvider.GITHUB
        token = body.orcid_access_token or body.github_access_token
        assert token is not None  # exactly-one enforced by TenantApplicationCreate
        try:
            claim = identity_verifier.verify(idp, token)
        except UnknownIdentityProviderError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "unsupported_idp",
                        "message": f"identity provider {idp.value!r} not enabled",
                        "details": {},
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

        # The application's github_login is the GitHub handle, or None for an
        # ORCID root (its identity is the account's orcid_id, surfaced at approval
        # as the public contact).
        github_login = claim.display_name if claim.idp is IdentityProvider.GITHUB else None

        # 3. Resolve-or-create the account row (volunteer-enrollment pattern,
        #    including the create race).
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

        # 4. One pending application per account at a time.
        if tenant_application_repository.has_pending_for_account(account.account_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "application_pending",
                        "message": (
                            "this account already has a pending tenant application; "
                            "wait for it to be resolved before applying again"
                        ),
                    }
                },
            )

        application = tenant_application_repository.create(
            account_id=account.account_id,
            github_login=github_login,
            requested_tenant_id=body.requested_tenant_id,
            contact_name=body.contact_name,
            affiliation=body.affiliation,
            # The 0028 column is NOT NULL; '' = summary omitted (classes-only).
            research_summary=body.research_summary or "",
            pubkey_hex=pubkey_hex,
            research_classes=body.research_classes,
        )
        audit_repository.append(
            actor_class=CredentialClass.ANONYMOUS,
            actor_identifier=pubkey_hex,
            action="application.submitted",
            resource_type="tenant_application",
            resource_id=application.application_id,
            payload={
                "account_id": account.account_id,
                "idp": claim.idp.value,
                "github_login": github_login,
                "requested_tenant_id": body.requested_tenant_id,
                "is_new_account": is_new,
                "status": application.status,
            },
        )
        _publish(
            "application.submitted",
            {
                "application_id": application.application_id,
                "account_id": account.account_id,
                "idp": claim.idp.value,
                "github_login": github_login,
                "requested_tenant_id": body.requested_tenant_id,
                "status": application.status,
            },
        )
        existing_tenants = [
            t.tenant_id for t in tenant_repository.list_for_account(account.account_id)
        ]
        return TenantApplicationSubmitResponse(
            application_id=application.application_id,
            status=application.status,
            account_existing_tenants=existing_tenants,
        )

    # NB: /mine is declared before any /{application_id} matcher would be —
    # there is deliberately no public get-by-id route on this surface.

    @router.get(
        "/tenant-applications/mine",
        response_model=MyApplicationListResponse,
        status_code=status.HTTP_200_OK,
    )
    async def my_tenant_applications(request: Request) -> MyApplicationListResponse:
        # Same self-keyid proof of possession as submit: an applicant has no
        # registered credential until approval, so the key IS the identity.
        pubkey_hex = await _verify_applying_key(request)
        applications = tenant_application_repository.list(pubkey_hex=pubkey_hex)
        return MyApplicationListResponse(
            applications=[
                MyApplicationResponse(
                    application_id=a.application_id,
                    status=a.status,
                    resolution_reason=a.resolution_reason,
                    created_tenant_id=a.created_tenant_id,
                )
                for a in applications
            ]
        )

    @router.get(
        "/tenant-applications",
        response_model=TenantApplicationListResponse,
        status_code=status.HTTP_200_OK,
    )
    async def list_tenant_applications(
        status_filter: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantApplicationListResponse:
        _require_maintainer(credential)
        applications = tenant_application_repository.list(status=status_filter)
        # D2 review context: per-application, the tenant_ids already linked to
        # the application's account (excludes nothing; [] when none) — so a
        # second tenant for an account is approved deliberately.
        return TenantApplicationListResponse(
            applications=[
                _to_response(
                    a,
                    account_existing_tenants=[
                        t.tenant_id for t in tenant_repository.list_for_account(a.account_id)
                    ],
                )
                for a in applications
            ]
        )

    def _load_pending(application_id: str) -> TenantApplication:
        existing = tenant_application_repository.get_by_id(application_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="tenant application not found"
            )
        if existing.status != "pending":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "invalid_status_transition",
                        "message": (
                            f"cannot resolve an application in status {existing.status!r} "
                            "(only pending)"
                        ),
                    }
                },
            )
        return existing

    def _audit_and_publish_resolved(
        application: TenantApplication, credential: Credential, payload_extra: dict
    ) -> None:
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="application.resolved",
            resource_type="tenant_application",
            resource_id=application.application_id,
            payload={
                "account_id": application.account_id,
                "new_status": application.status,
                **payload_extra,
            },
        )
        _publish(
            "application.resolved",
            {
                "application_id": application.application_id,
                "status": application.status,
                "resolved_by": credential.maintainer_login,
                "created_tenant_id": application.created_tenant_id,
            },
        )

    @router.post(
        "/tenant-applications/{application_id}/actions/approve",
        response_model=TenantApplicationResponse,
        status_code=status.HTTP_200_OK,
    )
    async def approve_tenant_application(
        application_id: str,
        body: ApproveRequest | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantApplicationResponse:
        _require_maintainer(credential)
        existing = _load_pending(application_id)
        tenant_id = (
            body.tenant_id_override
            if body is not None and body.tenant_id_override
            else existing.requested_tenant_id
        )
        try:
            application = tenant_application_repository.approve(
                application_id,
                tenant_id=tenant_id,
                resolved_by=credential.maintainer_login or "maintainer",
            )
        except DuplicateTenantError:
            # Atomic: the rollback leaves the application pending, so the
            # maintainer can retry with tenant_id_override.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "tenant_id_taken",
                        "message": (
                            f"tenant id {tenant_id!r} is already registered (or the applying "
                            "pubkey is already bound); retry with tenant_id_override"
                        ),
                    }
                },
            ) from None
        except ApplicationNotPendingError:  # pragma: no cover — raced past _load_pending
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="application is not pending"
            ) from None
        _audit_and_publish_resolved(
            application,
            credential,
            {"tenant_id": tenant_id, "tenant_id_override": bool(body and body.tenant_id_override)},
        )
        return _to_response(application)

    @router.post(
        "/tenant-applications/{application_id}/actions/decline",
        response_model=TenantApplicationResponse,
        status_code=status.HTTP_200_OK,
    )
    async def decline_tenant_application(
        application_id: str,
        body: DeclineRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> TenantApplicationResponse:
        _require_maintainer(credential)
        _load_pending(application_id)
        try:
            application = tenant_application_repository.decline(
                application_id,
                resolved_by=credential.maintainer_login or "maintainer",
                reason=body.reason,
            )
        except ApplicationNotPendingError:  # pragma: no cover — raced past _load_pending
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="application is not pending"
            ) from None
        _audit_and_publish_resolved(application, credential, {"reason": body.reason})
        return _to_response(application)

    return router
