"""Authentication errors.

Each error maps to an HTTP 401 with a stable `error.code` per §6.7 of the
design doc. The dependency translates these to FastAPI HTTPExceptions at
request time.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base class for authentication failures.

    Subclasses carry a stable `code` matching the design doc's error model
    (`{"error": {"code": ..., "message": ..., "details": ...}}`).
    """

    code: str = "auth_error"

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, object] = details or {}


class InvalidTokenError(AuthError):
    """The presented maintainer bearer token did not match any active token."""

    code = "invalid_maintainer_token"


class InvalidSignatureError(AuthError):
    """RFC 9421 signature verification failed: bad signature, unknown keyid,
    body digest mismatch, malformed Signature-Input, etc."""

    code = "invalid_signature"


class SignatureExpiredError(AuthError):
    """The `created` timestamp on the signature is outside the accepted window."""

    code = "signature_expired"


class UnsupportedAlgorithmError(AuthError):
    """The `alg` parameter declares an algorithm the coordinator does not accept.
    v0 accepts only `ed25519`."""

    code = "unsupported_signature_algorithm"


class MalformedAuthorizationError(AuthError):
    """The `Authorization` header is present but does not parse as `Bearer <token>`."""

    code = "malformed_authorization_header"
