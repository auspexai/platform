"""Authentication subsystem.

Implements the three Phase 1 credential classes per §5.18 / §10 of the design:

  - Maintainer (operator): static bearer token, file-stored mode 0600.
  - Researcher (tenant): RFC 9421 HTTP Message Signature with Ed25519.
  - Anonymous public: no credential. Coordinator field-filters to `public` only.

The fourth class (T1+ account, OAuth Device Flow) lands in Phase 2-3 as an
additional filter on the same endpoints; the structural hooks exist here from
day one so adding it later is a filter implementation, not a refactor.
"""

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.errors import (
    AuthError,
    InvalidSignatureError,
    InvalidTokenError,
    SignatureExpiredError,
)

__all__ = [
    "AuthError",
    "Credential",
    "CredentialClass",
    "InvalidSignatureError",
    "InvalidTokenError",
    "SignatureExpiredError",
]
