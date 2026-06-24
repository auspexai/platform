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
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.identity import IdentityClaim, InvalidAccessTokenError

ORCID_BASE_PROD = "https://orcid.org"
ORCID_USERINFO_PROD = f"{ORCID_BASE_PROD}/oauth/userinfo"
ORCID_API_TIMEOUT_SECONDS = 10.0


def _orcid_userinfo_endpoint() -> str:
    return os.environ.get("AUSPEXAI_ORCID_USERINFO", ORCID_USERINFO_PROD)


def _orcid_base() -> str:
    return os.environ.get("AUSPEXAI_ORCID_BASE", ORCID_BASE_PROD).rstrip("/")


@dataclass(frozen=True)
class OrcidLink:
    """The verified ORCID iD + name from a completed OAuth exchange."""

    orcid_id: str
    name: str | None = None


class OrcidOAuthClient:
    """Server-side ORCID OAuth (authorization-code flow).

    The coordinator holds the client secret and performs the code→token
    exchange; ORCID's token response carries the authenticated `orcid` iD and
    `name` directly, so no extra userinfo call is needed. Config is read from the
    environment (the secret never touches the repo): `AUSPEXAI_ORCID_CLIENT_ID`,
    `AUSPEXAI_ORCID_CLIENT_SECRET`, `AUSPEXAI_ORCID_REDIRECT_URI`,
    `AUSPEXAI_ORCID_BASE` (defaults to production). `is_configured` is False until
    the id/secret/redirect are present, so the link endpoint can 503 cleanly.
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        base: str | None = None,
        client: httpx.Client | None = None,
    ):
        self.client_id = client_id or os.environ.get("AUSPEXAI_ORCID_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("AUSPEXAI_ORCID_CLIENT_SECRET")
        self.redirect_uri = redirect_uri or os.environ.get("AUSPEXAI_ORCID_REDIRECT_URI")
        self.base = (base or _orcid_base()).rstrip("/")
        self._client = client or httpx.Client(timeout=ORCID_API_TIMEOUT_SECONDS)

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)

    def authorize_url(self, state: str) -> str:
        """The ORCID authorize URL the researcher's browser is sent to. Carries
        the PUBLIC client id + the CSRF `state`; scope `/authenticate` only
        (verify the iD — no record access)."""
        q = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "scope": "/authenticate",
                "redirect_uri": self.redirect_uri,
                "state": state,
            }
        )
        return f"{self.base}/oauth/authorize?{q}"

    def exchange_code(self, code: str) -> OrcidLink:
        """Exchange an authorization code for the researcher's ORCID iD. ORCID's
        token response includes `orcid` + `name` directly. Raises
        InvalidAccessTokenError on any failure."""
        try:
            resp = self._client.post(
                f"{self.base}/oauth/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as e:
            raise InvalidAccessTokenError(f"orcid token exchange failed: {e}") from e
        if resp.status_code != 200:
            raise InvalidAccessTokenError(f"orcid token endpoint returned {resp.status_code}")
        body = resp.json()
        orcid = body.get("orcid")
        if not isinstance(orcid, str) or not orcid:
            raise InvalidAccessTokenError("orcid token response missing 'orcid'")
        return OrcidLink(orcid_id=orcid, name=body.get("name"))


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
