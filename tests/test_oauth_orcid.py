"""OrcidVerifier tests — exercise the OIDC userinfo call via httpx MockTransport."""

from __future__ import annotations

import httpx
import pytest

from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.identity import InvalidAccessTokenError
from auspexai_platform.oauth.orcid import ORCID_USERINFO_PROD, OrcidVerifier


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_verify_returns_claim_for_valid_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(ORCID_USERINFO_PROD)
        assert request.headers["Authorization"] == "Bearer orcid_valid"
        return httpx.Response(
            200,
            json={
                "sub": "0000-0002-1825-0097",
                "given_name": "Josiah",
                "family_name": "Carberry",
            },
        )

    verifier = OrcidVerifier(client=_client(handler))
    claim = verifier.verify(IdentityProvider.ORCID, "orcid_valid")
    assert claim.idp is IdentityProvider.ORCID
    assert claim.idp_sub == "0000-0002-1825-0097"
    assert claim.display_name == "Josiah Carberry"


def test_verify_prefers_name_over_given_family() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"sub": "0000-0001-2345-6789", "name": "Ada L."})

    verifier = OrcidVerifier(client=_client(handler))
    claim = verifier.verify(IdentityProvider.ORCID, "t")
    assert claim.display_name == "Ada L."


def test_configurable_sandbox_endpoint() -> None:
    sandbox = "https://sandbox.orcid.org/oauth/userinfo"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(sandbox)
        return httpx.Response(200, json={"sub": "0000-0002-1825-0097"})

    verifier = OrcidVerifier(userinfo_endpoint=sandbox, client=_client(handler))
    assert verifier.verify(IdentityProvider.ORCID, "t").idp_sub == "0000-0002-1825-0097"


def test_verify_rejects_non_orcid_idp() -> None:
    verifier = OrcidVerifier(client=_client(lambda r: httpx.Response(200)))
    with pytest.raises(InvalidAccessTokenError, match="cannot verify"):
        verifier.verify(IdentityProvider.GITHUB, "x")


def test_verify_raises_on_401() -> None:
    verifier = OrcidVerifier(client=_client(lambda r: httpx.Response(401)))
    with pytest.raises(InvalidAccessTokenError, match="401"):
        verifier.verify(IdentityProvider.ORCID, "bad")


def test_verify_raises_on_unexpected_status() -> None:
    verifier = OrcidVerifier(client=_client(lambda r: httpx.Response(503)))
    with pytest.raises(InvalidAccessTokenError, match="503"):
        verifier.verify(IdentityProvider.ORCID, "x")


def test_verify_raises_on_missing_sub() -> None:
    verifier = OrcidVerifier(client=_client(lambda r: httpx.Response(200, json={"name": "x"})))
    with pytest.raises(InvalidAccessTokenError, match="missing string 'sub'"):
        verifier.verify(IdentityProvider.ORCID, "x")


def test_verify_raises_on_transport_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated")

    verifier = OrcidVerifier(client=_client(handler))
    with pytest.raises(InvalidAccessTokenError, match="user-info call failed"):
        verifier.verify(IdentityProvider.ORCID, "x")
