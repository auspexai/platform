"""GitHub identity verification.

Calls `GET https://api.github.com/user` with the supplied access token,
extracts the stable numeric user ID + login. GitHub returns 401 on
invalid/expired tokens; we surface those as `InvalidAccessTokenError`.

The `id` field on GitHub's user response is the stable numeric user ID —
immutable even if the user changes their `login` (handle). We persist
`id` as the account's `idp_sub` for that reason; `login` goes into
`display_name`.

The GitHub OAuth App's Client ID does not appear here — token verification
doesn't need it. The Client ID is used only by the *caller* to initiate the
device flow with GitHub.
"""

from __future__ import annotations

import httpx

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.identity import IdentityClaim, InvalidAccessTokenError

GITHUB_USER_ENDPOINT = "https://api.github.com/user"
GITHUB_API_TIMEOUT_SECONDS = 10.0


class GitHubVerifier:
    """Verifier for IdentityProvider.GITHUB."""

    def __init__(self, client: httpx.Client | None = None):
        self._client = client or httpx.Client(timeout=GITHUB_API_TIMEOUT_SECONDS)

    def verify(self, idp: IdentityProvider, access_token: str) -> IdentityClaim:
        if idp is not IdentityProvider.GITHUB:
            raise InvalidAccessTokenError(f"GitHubVerifier cannot verify idp={idp.value}")
        try:
            response = self._client.get(
                GITHUB_USER_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        except httpx.HTTPError as e:
            raise InvalidAccessTokenError(f"github user-info call failed: {e}") from e

        if response.status_code == 401:
            raise InvalidAccessTokenError("github rejected access token (401)")
        if response.status_code != 200:
            raise InvalidAccessTokenError(f"github returned status {response.status_code}")

        body = response.json()
        user_id = body.get("id")
        if not isinstance(user_id, int):
            raise InvalidAccessTokenError("github response missing numeric 'id'")
        return IdentityClaim(
            idp=IdentityProvider.GITHUB,
            idp_sub=str(user_id),
            display_name=body.get("login"),
            email=body.get("email"),
        )
