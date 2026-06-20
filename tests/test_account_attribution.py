"""D-inc4: public-citation opt-in endpoints — GET/PUT /accounts/{id}/attribution.

Account-self (via the bound worker's credential) or maintainer; default OFF, since
auth-consent (the GitHub linkage) is not attribution-consent. The maintainer path
exercises the endpoint logic + persistence; the account-self authz reuses the same
`_require_account_self_or_maintainer` helper covered by the M7e account tests.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.db.models import IdentityProvider


def test_attribution_default_off_then_opt_in_and_out(
    client: TestClient, maintainer_token: str, account_repository
) -> None:
    account_repository.create(account_id="acct-ada", idp=IdentityProvider.GITHUB, idp_sub="gh-ada")
    h = {"Authorization": f"Bearer {maintainer_token}"}

    # Default: not opted in.
    r = client.get("/api/v0/accounts/acct-ada/attribution", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["public_attribution"] is False
    assert r.json()["attribution_name"] is None

    # Opt in with a chosen name.
    r = client.put(
        "/api/v0/accounts/acct-ada/attribution",
        headers=h,
        json={"public_attribution": True, "attribution_name": "Ada Lovelace"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["public_attribution"] is True
    assert body["attribution_name"] == "Ada Lovelace"

    # Persists across a fresh GET.
    assert (
        client.get("/api/v0/accounts/acct-ada/attribution", headers=h).json()["public_attribution"]
        is True
    )

    # Reversible while live — opt back out.
    r = client.put(
        "/api/v0/accounts/acct-ada/attribution",
        headers=h,
        json={"public_attribution": False},
    )
    assert r.json()["public_attribution"] is False


def test_attribution_blank_name_normalizes_to_null(
    client: TestClient, maintainer_token: str, account_repository
) -> None:
    account_repository.create(
        account_id="acct-blank", idp=IdentityProvider.GITHUB, idp_sub="gh-blank"
    )
    h = {"Authorization": f"Bearer {maintainer_token}"}
    r = client.put(
        "/api/v0/accounts/acct-blank/attribution",
        headers=h,
        json={"public_attribution": True, "attribution_name": "   "},
    )
    assert r.status_code == 200, r.text
    assert r.json()["attribution_name"] is None


def test_attribution_unknown_account_404(client: TestClient, maintainer_token: str) -> None:
    r = client.put(
        "/api/v0/accounts/acct-nope/attribution",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={"public_attribution": True},
    )
    assert r.status_code == 404


def test_attribution_anonymous_forbidden(client: TestClient) -> None:
    r = client.put(
        "/api/v0/accounts/acct-ada/attribution",
        json={"public_attribution": True},
    )
    assert r.status_code in (401, 403)
