"""GitHubVerifier tests — exercise the GET /user call via httpx MockTransport."""

from __future__ import annotations

import httpx
import pytest

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.github import GITHUB_USER_ENDPOINT, GitHubVerifier
from auspexai_platform.oauth.identity import InvalidAccessTokenError


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_verify_returns_claim_for_valid_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(GITHUB_USER_ENDPOINT)
        assert request.headers["Authorization"] == "Bearer gho_valid_token"
        assert request.headers["Accept"] == "application/vnd.github+json"
        return httpx.Response(
            200,
            json={
                "id": 246774008,
                "login": "jasongagne-git",
                "email": "jason@example.org",
            },
        )

    verifier = GitHubVerifier(client=_client(handler))
    claim = verifier.verify(IdentityProvider.GITHUB, "gho_valid_token")
    assert claim.idp is IdentityProvider.GITHUB
    assert claim.idp_sub == "246774008"
    assert claim.display_name == "jasongagne-git"
    assert claim.email == "jason@example.org"


def test_verify_rejects_non_github_idp_argument() -> None:
    # GitHubVerifier should refuse other IdPs even if it's somehow invoked
    # with them — the DispatchingVerifier shouldn't route them here, but
    # belt-and-braces.
    verifier = GitHubVerifier(client=_client(lambda r: httpx.Response(200)))

    # Construct a fake IdP value to trigger the branch (use cast since the
    # enum only has one member in Phase 1).
    class _Other:
        value = "other"

    with pytest.raises(InvalidAccessTokenError, match="cannot verify"):
        verifier.verify(_Other(), "gho_anything")  # type: ignore[arg-type]


def test_verify_raises_on_401() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    verifier = GitHubVerifier(client=_client(handler))
    with pytest.raises(InvalidAccessTokenError, match="401"):
        verifier.verify(IdentityProvider.GITHUB, "gho_bad")


def test_verify_raises_on_unexpected_status() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    verifier = GitHubVerifier(client=_client(handler))
    with pytest.raises(InvalidAccessTokenError, match="503"):
        verifier.verify(IdentityProvider.GITHUB, "gho_x")


def test_verify_raises_on_missing_id_field() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "someone"})

    verifier = GitHubVerifier(client=_client(handler))
    with pytest.raises(InvalidAccessTokenError, match="missing numeric"):
        verifier.verify(IdentityProvider.GITHUB, "gho_x")


def test_verify_raises_on_transport_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated")

    verifier = GitHubVerifier(client=_client(handler))
    with pytest.raises(InvalidAccessTokenError, match="user-info call failed"):
        verifier.verify(IdentityProvider.GITHUB, "gho_x")
