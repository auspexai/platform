"""ORCID identity verification (D8 — the citation-grade researcher identity).

Calls ORCID's OpenID Connect `userinfo` endpoint with the supplied access token
and reads the `sub` claim — the researcher's ORCID iD (e.g.
"0000-0002-1825-0097"), which is stable and the identifier we persist as the
account's linked ORCID. The `name` (or given/family name) goes into
`display_name`.

ORCID supports OIDC, so this mirrors the GitHub verifier exactly: present the
bearer token to the IdP's user-info endpoint, trust the IdP's answer. The
endpoint is configurable (`AUSPEXAI_ORCID_USERINFO`) so the sandbox
(`https://sandbox.orcid.org/oauth/userinfo`) can be used in dev without code
changes; it defaults to production.

ORCID is supported as a *linked* identity (account-linking, not a root IdP — see
`IdentityProvider`), so a successful verify feeds the link endpoint, which stores
the ORCID iD and marks the account identity-verified (method=ORCID).
"""

from __future__ import annotations

import os

import httpx

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.identity import IdentityClaim, InvalidAccessTokenError

ORCID_USERINFO_PROD = "https://orcid.org/oauth/userinfo"
ORCID_API_TIMEOUT_SECONDS = 10.0


def _orcid_userinfo_endpoint() -> str:
    return os.environ.get("AUSPEXAI_ORCID_USERINFO", ORCID_USERINFO_PROD)


class OrcidVerifier:
    """Verifier for IdentityProvider.ORCID (via ORCID OIDC userinfo)."""

    def __init__(self, userinfo_endpoint: str | None = None, client: httpx.Client | None = None):
        self._endpoint = userinfo_endpoint or _orcid_userinfo_endpoint()
        self._client = client or httpx.Client(timeout=ORCID_API_TIMEOUT_SECONDS)

    def verify(self, idp: IdentityProvider, access_token: str) -> IdentityClaim:
        if idp is not IdentityProvider.ORCID:
            raise InvalidAccessTokenError(f"OrcidVerifier cannot verify idp={idp.value}")
        try:
            response = self._client.get(
                self._endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as e:
            raise InvalidAccessTokenError(f"orcid user-info call failed: {e}") from e

        if response.status_code == 401:
            raise InvalidAccessTokenError("orcid rejected access token (401)")
        if response.status_code != 200:
            raise InvalidAccessTokenError(f"orcid returned status {response.status_code}")

        body = response.json()
        sub = body.get("sub")
        if not isinstance(sub, str) or not sub:
            raise InvalidAccessTokenError("orcid response missing string 'sub' (the ORCID iD)")
        # Prefer the OIDC `name`; fall back to assembling given + family name.
        name = body.get("name") or (
            " ".join(p for p in (body.get("given_name"), body.get("family_name")) if p) or None
        )
        return IdentityClaim(idp=IdentityProvider.ORCID, idp_sub=sub, display_name=name)
