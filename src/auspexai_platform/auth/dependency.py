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
from auspexai_platform.auth.signature import RequestSummary, verify_request
from auspexai_platform.auth.tenant_registry import TenantRegistry


def _auth_failure(
    error: AuthError, status_code: int = status.HTTP_401_UNAUTHORIZED
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error": {"code": error.code, "message": error.message, "details": error.details}},
    )


def make_credential_dependency(
    token_store: TokenStore,
    registry: TenantRegistry,
):
    """Build the `get_credential` dependency bound to a token store + tenant
    registry. Each `create_app()` call binds its own pair so tests can run in
    parallel with isolated state."""

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
            if not token_store.verify(token):
                raise _auth_failure(
                    InvalidTokenError("maintainer token is not valid or has expired")
                )
            return Credential.maintainer()

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
                return verify_request(summary, registry)
            except AuthError as e:
                raise _auth_failure(e) from e

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


__all__ = [
    "CredentialClass",
    "make_credential_dependency",
    "require_maintainer",
    "require_researcher",
]
