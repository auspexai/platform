"""OAuth identity-verification helpers.

The coordinator delegates the OAuth 2.0 Device Authorization Flow (RFC 8628)
itself to the calling client (worker, researcher dashboard) per the
public-client model — the GitHub OAuth App's Client ID ships in caller
source code, not coordinator config. The coordinator's role is to **verify**
the access token that completes the flow and resolve it to a stable IdP
subject identifier (e.g., GitHub numeric user id).

`IdentityVerifier` is the abstract protocol; per-IdP implementations live in
`oauth/<idp>.py`. The `DispatchingVerifier` routes a request to the right
per-IdP verifier. Tests inject a `FakeIdentityVerifier`.
"""

from auspexai_platform.oauth.identity import (
    DispatchingVerifier,
    IdentityClaim,
    IdentityVerifier,
    InvalidAccessTokenError,
    UnknownIdentityProviderError,
    build_default_verifier,
)

__all__ = [
    "DispatchingVerifier",
    "IdentityClaim",
    "IdentityVerifier",
    "InvalidAccessTokenError",
    "UnknownIdentityProviderError",
    "build_default_verifier",
]
