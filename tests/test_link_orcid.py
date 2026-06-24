"""ORCID account-linking (D8) — POST /accounts/{id}/actions/link-orcid + repo.

Linking stores the ORCID iD AND marks the account identity-verified
(method=ORCID) — the flag the R2→R3 vetting gate reads.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.db.models import IdentityProvider, IdentityVerificationMethod
from auspexai_platform.db.repositories import AccountRepository
from auspexai_platform.oauth.identity import IdentityClaim

from .conftest import FakeIdentityVerifier

ORCID = "0000-0002-1825-0097"


def _mh(maintainer_token) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


def test_maintainer_links_orcid_and_marks_identity_verified(
    client: TestClient,
    identity_verifier: FakeIdentityVerifier,
    account_repository: AccountRepository,
    maintainer_token,
) -> None:
    account_repository.create(account_id="acct-o", idp=IdentityProvider.GITHUB, idp_sub="gh-o")
    identity_verifier.register(
        "orcid_tok",
        IdentityClaim(idp=IdentityProvider.ORCID, idp_sub=ORCID, display_name="Josiah Carberry"),
    )
    r = client.post(
        "/api/v0/accounts/acct-o/actions/link-orcid",
        json={"access_token": "orcid_tok"},
        headers=_mh(maintainer_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["orcid_id"] == ORCID
    assert body["identity_verification_method"] == "orcid"
    assert body["identity_verified_at"]
    # Persisted: the iD + identity verified via ORCID (satisfies the R3 gate).
    acct = account_repository.get_by_id("acct-o")
    assert acct.orcid_id == ORCID
    assert acct.identity_verified_at is not None
    assert acct.identity_verification_method is IdentityVerificationMethod.ORCID


def test_link_orcid_rejects_invalid_token(
    client: TestClient,
    account_repository: AccountRepository,
    maintainer_token,
) -> None:
    account_repository.create(account_id="acct-bad", idp=IdentityProvider.GITHUB, idp_sub="gh-bad")
    # No token registered → the fake verifier raises → 401 (IdP rejected it).
    r = client.post(
        "/api/v0/accounts/acct-bad/actions/link-orcid",
        json={"access_token": "nope"},
        headers=_mh(maintainer_token),
    )
    assert r.status_code == 401, r.text


def test_link_orcid_404_for_unknown_account(client: TestClient, maintainer_token) -> None:
    r = client.post(
        "/api/v0/accounts/acct-missing/actions/link-orcid",
        json={"access_token": "x"},
        headers=_mh(maintainer_token),
    )
    assert r.status_code == 404


def test_repo_link_orcid_then_revoke_clears_it(account_repository: AccountRepository) -> None:
    account_repository.create(account_id="acct-rv", idp=IdentityProvider.GITHUB, idp_sub="gh-rv")
    linked = account_repository.link_orcid("acct-rv", orcid_id=ORCID, display_name="x")
    assert linked.orcid_id == ORCID
    assert linked.identity_verification_method is IdentityVerificationMethod.ORCID
    assert linked.identity_verified_at is not None
    # Revoking identity also clears the linked ORCID (consistency).
    account_repository.revoke_identity("acct-rv")
    acct = account_repository.get_by_id("acct-rv")
    assert acct.orcid_id is None
    assert acct.identity_verified_at is None
