"""FastAPI dependency producing the per-request `Credential`.

Wired into routes via `Depends(get_credential)`. The dependency inspects
auth headers in priority order:

  1. `Authorization: Bearer <token>` → maintainer
  2. `Signature-Input` + `Signature` headers → researcher (RFC 9421)
  3. Neither → anonymous

If a header is present but invalid (bad token, expired signature, bad body
digest, etc.), the dependency raises an HTTPException(401) carrying the
stable error code from `auth/errors.py` so the operator console can switch
on it.

Routes that require a particular credential class use a stronger dependency
(e.g., `require_maintainer`, `require_researcher`) that 403s on misclass.
M2 ships only `get_credential` + `require_maintainer` + `require_researcher`;
audience-specific authorization (per-tenant ownership checks etc.) lands with
each resource route.

Accountability cascade (D3): the account is the accountability root, so a
SUSPENDED account's linked tenants stop working. When the resolved researcher
credential's tenant is account-linked and that account is suspended, the
dependency raises 403 `account_suspended` carrying the maintainer's
suspension_reason — the same surfacing rule as the worker-side 423
`worker_quarantined`. `/auth/whoami` stays exempt (read-only), matching the
worker-side philosophy: status surfaces keep answering so the account holder
can see that — and why — they were suspended; work surfaces refuse.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.errors import (
    AuthError,
    InvalidTokenError,
    MalformedAuthorizationError,
)
from auspexai_platform.auth.resolver import CredentialResolver
from auspexai_platform.auth.signature import RequestSummary, verify_request
from auspexai_platform.db.repositories.accounts import AccountRepository

# Paths exempt from the account-suspension cascade. whoami is the researcher's
# status surface — it keeps working read-only for a suspended account so the
# dashboard can show the suspension banner (suspended_at + suspension_reason
# are ACCOUNT_SCOPED fields on the whoami response). Mirrors the worker-side
# philosophy: a quarantined worker still heartbeats and sees its quarantine
# reason; it just gets no work.
_SUSPENSION_EXEMPT_PATHS = frozenset({"/api/v0/auth/whoami"})


def _auth_failure(
    error: AuthError, status_code: int = status.HTTP_401_UNAUTHORIZED
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error": {"code": error.code, "message": error.message, "details": error.details}},
    )


def _enforce_account_not_suspended(
    credential: Credential,
    request_path: str,
    account_repository: AccountRepository | None,
) -> None:
    """D3 accountability cascade: 403 a researcher whose linked account is
    suspended.

    Applies only to researcher credentials whose tenant carries an
    `account_id` (legacy tenants without one are unaffected — there is no
    accountability root to cascade from). Suspension itself is already
    audited at suspend time; this enforcement adds no new audit entries.
    """
    if account_repository is None:
        return
    if not credential.is_researcher() or credential.account_id is None:
        return
    if request_path in _SUSPENSION_EXEMPT_PATHS:
        return
    account = account_repository.get_by_id(credential.account_id)
    if account is None or account.suspended_at is None:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "account_suspended",
                "message": (
                    "this tenant's account is suspended; contact the operator "
                    "or wait for unsuspension"
                ),
                "details": {
                    "suspended_at": account.suspended_at.isoformat(),
                    "suspension_reason": account.suspension_reason,
                },
            }
        },
    )


def enforce_worker_active(
    credential: Credential,
    worker_repository,
    account_repository: AccountRepository | None,
) -> None:
    """Symmetric to `_enforce_account_not_suspended`, for the WORKER write
    paths (result ingestion, vouching).

    A QUARANTINED worker — or a worker whose linked account is SUSPENDED —
    must not have its output ingested. Quarantine is the operator's
    "stop trusting this worker's output" lever; account suspension is the
    accountability-root cascade. Until now quarantine only gated assignment
    DISPATCH (`GET /assignments` → 423), not the write paths, so a worker
    quarantined while already holding an assignment could still POST a result
    into consensus (and trigger receipt issuance + tier auto-promotion). This
    closes that on the ingestion paths.

    PAUSE is deliberately NOT enforced here: a paused worker is under a
    no-fault operational hold, and discarding work it had already completed
    in flight is the open M9 pause-integrity question (partial-result
    collection from paused workers), not a trust decision.
    """
    worker_id = credential.worker_id
    if worker_id is not None and worker_repository is not None:
        worker = worker_repository.get_by_id(worker_id)
        if worker is not None and worker.quarantined_at is not None:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={
                    "error": {
                        "code": "worker_quarantined",
                        "message": (
                            "this worker is quarantined; its results are not "
                            "accepted until unquarantine"
                        ),
                        "details": {
                            "quarantined_at": worker.quarantined_at.isoformat(),
                            "quarantine_reason": worker.quarantine_reason,
                        },
                    }
                },
            )
    if account_repository is not None and credential.account_id is not None:
        account = account_repository.get_by_id(credential.account_id)
        if account is not None and account.suspended_at is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "account_suspended",
                        "message": (
                            "this worker's account is suspended; its results "
                            "are not accepted until unsuspension"
                        ),
                        "details": {
                            "suspended_at": account.suspended_at.isoformat(),
                            "suspension_reason": account.suspension_reason,
                        },
                    }
                },
            )


def make_credential_dependency(
    token_store: TokenStore,
    resolver: CredentialResolver,
    account_repository: AccountRepository | None = None,
):
    """Build the `get_credential` dependency bound to a token store + a
    keyid resolver (tenants + workers). Each `create_app()` call binds its
    own resolver so tests can run in parallel with isolated state.

    `account_repository` arms the account-suspension cascade (D3): signed
    researcher requests from a tenant whose linked account is suspended are
    refused with 403 `account_suspended`. When omitted (minimal test apps),
    the cascade is disarmed."""

    async def get_credential(request: Request) -> Credential:
        auth_header = request.headers.get("Authorization")
        signature_input_header = request.headers.get("Signature-Input")

        if auth_header:
            if not auth_header.startswith("Bearer "):
                raise _auth_failure(
                    MalformedAuthorizationError(
                        "Authorization header must use Bearer scheme",
                    )
                )
            token = auth_header[len("Bearer ") :].strip()
            matched_login = token_store.verify(token)
            if matched_login is None:
                raise _auth_failure(
                    InvalidTokenError("maintainer token is not valid or has expired")
                )
            # AUD-28 (A9 audit): X-Maintainer-Login is a TRUSTED-PROXY attribution
            # header — the operator console holds the login-less SERVICE/root token
            # and names the individual maintainer behind each proxied request so the
            # audit log attributes it to a person, not "the console". Honor it ONLY
            # for that login-less token. A PER-MAINTAINER token (`token issue`) is
            # already bound to its owner; letting its holder set the header would let
            # them rewrite audit actor_identifier to any login — defeating the
            # non-repudiation that per-maintainer tokens exist to provide. So a
            # bound token always attributes to its OWN login, header ignored.
            if matched_login:
                effective_login = matched_login
            else:
                effective_login = request.headers.get("X-Maintainer-Login") or None
            return Credential.maintainer(maintainer_login=effective_login)

        if signature_input_header:
            signature_header = request.headers.get("Signature")
            if signature_header is None:
                raise _auth_failure(
                    AuthError(
                        "Signature-Input header is present but Signature header is missing",
                        details={"code_hint": "send both headers together"},
                    )
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
                credential = verify_request(summary, resolver)
            except AuthError as e:
                raise _auth_failure(e) from e
            _enforce_account_not_suspended(credential, request.url.path, account_repository)
            return credential

        return Credential.anonymous()

    return get_credential


CredentialDep = Annotated[Credential, Depends]


def require_maintainer(credential: Credential) -> Credential:
    """Sub-dependency that 403s if the credential is not a maintainer.

    Use as:
        @router.get(...)
        async def route(credential = Depends(get_credential)):
            require_maintainer(credential)
            ...
    """
    if not credential.is_maintainer():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "maintainer_required",
                    "message": "this endpoint requires a maintainer credential",
                    "details": {"credential_class": credential.kind.value},
                }
            },
        )
    return credential


def require_researcher(credential: Credential) -> Credential:
    """Sub-dependency that 403s if the credential is not a researcher."""
    if not credential.is_researcher():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "researcher_required",
                    "message": "this endpoint requires a researcher credential",
                    "details": {"credential_class": credential.kind.value},
                }
            },
        )
    return credential


def require_worker(credential: Credential) -> Credential:
    """Sub-dependency that 403s if the credential is not a worker."""
    if not credential.is_worker():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "worker_required",
                    "message": "this endpoint requires a worker credential",
                    "details": {"credential_class": credential.kind.value},
                }
            },
        )
    return credential


__all__ = [
    "CredentialClass",
    "make_credential_dependency",
    "require_maintainer",
    "require_researcher",
    "require_worker",
]
