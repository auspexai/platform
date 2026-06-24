"""ORCID account-linking (D8) — POST /accounts/{id}/actions/link-orcid + repo.

Linking stores the ORCID iD AND marks the account identity-verified
(method=ORCID) — the flag the R2→R3 vetting gate reads.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.auth.credential import CredentialClass
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


# ---- single-use state repo + the live OAuth flow endpoints -------------------


def test_state_create_consume_single_use(account_repository: AccountRepository) -> None:
    account_repository.create(account_id="acct-s", idp=IdentityProvider.GITHUB, idp_sub="gh-s")
    account_repository.create_orcid_state("st-1", "acct-s")
    assert account_repository.consume_orcid_state("st-1") == "acct-s"
    # single-use: a second consume finds nothing.
    assert account_repository.consume_orcid_state("st-1") is None


def test_state_expiry_and_unknown(account_repository: AccountRepository) -> None:
    account_repository.create(account_id="acct-e", idp=IdentityProvider.GITHUB, idp_sub="gh-e")
    account_repository.create_orcid_state("st-2", "acct-e")
    # max_age 0 → already expired (and still consumed/deleted).
    assert account_repository.consume_orcid_state("st-2", max_age_seconds=0) is None
    assert account_repository.consume_orcid_state("never-made") is None


def test_callback_links_and_redirects(
    client, account_repository, audit_repository, monkeypatch
) -> None:
    from auspexai_platform.oauth.orcid import OrcidLink, OrcidOAuthClient

    account_repository.create(account_id="acct-cb", idp=IdentityProvider.GITHUB, idp_sub="gh-cb")
    account_repository.create_orcid_state("st-cb", "acct-cb")
    monkeypatch.setattr(
        OrcidOAuthClient,
        "exchange_code",
        lambda self, code: OrcidLink(orcid_id=ORCID, name="JC"),
    )
    r = client.get("/api/v0/accounts/orcid/callback?code=abc&state=st-cb", follow_redirects=False)
    assert r.status_code == 302
    assert "orcid=linked" in r.headers["location"]
    acct = account_repository.get_by_id("acct-cb")
    assert acct.orcid_id == ORCID
    assert acct.identity_verification_method is IdentityVerificationMethod.ORCID
    # The unauthenticated OAuth callback attributes the link to the ACCOUNT owner
    # (proven by the single-use state), NOT anonymous — audit legibility.
    link_audit = next(e for e in audit_repository.latest() if e.action == "account.link_orcid")
    assert link_audit.actor_class == CredentialClass.RESEARCHER
    assert link_audit.actor_identifier == (acct.display_name or "acct-cb")


def test_callback_unknown_state_is_expired(client) -> None:
    r = client.get("/api/v0/accounts/orcid/callback?code=abc&state=nope", follow_redirects=False)
    assert r.status_code == 302
    assert "orcid=expired" in r.headers["location"]


def test_callback_error_param_redirects_error(client) -> None:
    r = client.get("/api/v0/accounts/orcid/callback?error=access_denied", follow_redirects=False)
    assert r.status_code == 302
    assert "orcid=error" in r.headers["location"]


def test_start_requires_an_account(client, maintainer_token) -> None:
    # A maintainer token has no account_id → can't self-link.
    r = client.post("/api/v0/accounts/orcid/start", headers=_mh(maintainer_token))
    assert r.status_code == 403
