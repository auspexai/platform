"""IdentityVerifier protocol + dispatch verifier that routes per IdP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from auspexai_platform.db.models import IdentityProvider


class InvalidAccessTokenError(Exception):
    """Raised when an access token is malformed, expired, or rejected by the IdP."""


class UnknownIdentityProviderError(Exception):
    """Raised when an IdP is requested for which no verifier is registered."""


@dataclass(frozen=True)
class IdentityClaim:
    """The verified identity behind an access token."""

    idp: IdentityProvider
    idp_sub: str
    display_name: str | None = None
    email: str | None = None


class IdentityVerifier(Protocol):
    """Protocol for IdP-specific token verification.

    Implementations call the IdP's user-info endpoint with the access token,
    parse the response, and return an `IdentityClaim`. Failures (network
    error, IdP rejection, missing fields) raise `InvalidAccessTokenError`.
    """

    def verify(
        self, idp: IdentityProvider, access_token: str
    ) -> IdentityClaim:  # pragma: no cover — protocol
        ...


class DispatchingVerifier:
    """Routes verification requests to per-IdP verifiers.

    The coordinator builds one of these at startup with the IdPs it accepts.
    Phase 1: GitHub only.
    """

    def __init__(self, verifiers: dict[IdentityProvider, IdentityVerifier]):
        self._verifiers = dict(verifiers)

    def verify(self, idp: IdentityProvider, access_token: str) -> IdentityClaim:
        verifier = self._verifiers.get(idp)
        if verifier is None:
            raise UnknownIdentityProviderError(idp.value)
        return verifier.verify(idp, access_token)


def build_default_verifier() -> DispatchingVerifier:
    """Build the production verifier — GitHub (account root) + ORCID (D8, linked)."""
    from auspexai_platform.oauth.github import GitHubVerifier
    from auspexai_platform.oauth.orcid import OrcidVerifier

    return DispatchingVerifier(
        {
            IdentityProvider.GITHUB: GitHubVerifier(),
            IdentityProvider.ORCID: OrcidVerifier(),
        }
    )
