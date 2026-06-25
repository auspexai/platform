"""Tier-1 connected-researcher onboarding — POST /accounts/bind + the resolver.

Connecting binds the dashboard key DIRECTLY to an account (no tenant, no
approval — like a worker connecting GitHub). The bound key then resolves to a
CredentialClass.ACCOUNT. Covers the bind (find-or-create + key bind), whoami for
a tenant-less account, the proof-of-possession + invalid-token negatives, and
the rebind (latest connect wins).
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.oauth.identity import IdentityClaim

BIND_PATH = "/api/v0/accounts/bind"
WHOAMI_PATH = "/api/v0/auth/whoami"

_ORCID_TOKEN = "orcid_connect_token"
_ORCID_CLAIM = IdentityClaim(
    idp=IdentityProvider.ORCID,
    idp_sub="0000-0002-1825-0097",
    display_name="Josiah Carberry",
)


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _signed_post(client, *, privkey, pubkey_hex, path, body):
    raw = json.dumps(body).encode("utf-8")
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, headers=headers, content=raw)


def _signed_get(client, *, privkey, pubkey_hex, path):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


def test_bind_creates_account_and_key_resolves_as_account(
    client: TestClient, identity_verifier, account_repository
) -> None:
    priv, pub = _keypair()
    identity_verifier.register(_ORCID_TOKEN, _ORCID_CLAIM)
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=BIND_PATH,
        body={"idp": "orcid", "access_token": _ORCID_TOKEN},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_new_account"] is True
    assert body["idp"] == "orcid"
    assert body["display_name"] == "Josiah Carberry"

    account = account_repository.get_by_idp_subject(IdentityProvider.ORCID, _ORCID_CLAIM.idp_sub)
    assert account is not None
    assert account_repository.get_account_id_for_key(pub) == account.account_id

    # The bound key now resolves as a tenant-less ACCOUNT credential.
    w = _signed_get(client, privkey=priv, pubkey_hex=pub, path=WHOAMI_PATH)
    assert w.status_code == 200, w.text
    who = w.json()
    assert who["credential_class"] == "account"
    assert who.get("tenant_id") is None
    assert who.get("orcid_id")  # ORCID surfaced (rooted + identity-verified)


def test_bind_requires_signature(client: TestClient, identity_verifier) -> None:
    identity_verifier.register(_ORCID_TOKEN, _ORCID_CLAIM)
    r = client.post(BIND_PATH, json={"idp": "orcid", "access_token": _ORCID_TOKEN})
    assert r.status_code == 401
    assert "signature_required" in r.text


def test_bind_invalid_token_401(client: TestClient) -> None:
    priv, pub = _keypair()
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=BIND_PATH,
        body={"idp": "orcid", "access_token": "nope"},
    )
    assert r.status_code == 401
    assert "invalid_access_token" in r.text


def test_rebind_latest_connect_wins(
    client: TestClient, identity_verifier, account_repository
) -> None:
    # Same key connects ORCID, then GitHub → rebinds to the GitHub account.
    priv, pub = _keypair()
    gh_claim = IdentityClaim(idp=IdentityProvider.GITHUB, idp_sub="42", display_name="octo")
    identity_verifier.register(_ORCID_TOKEN, _ORCID_CLAIM)
    identity_verifier.register("gh_tok", gh_claim)
    _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=BIND_PATH,
        body={"idp": "orcid", "access_token": _ORCID_TOKEN},
    )
    orcid_acct = account_repository.get_by_idp_subject(IdentityProvider.ORCID, _ORCID_CLAIM.idp_sub)
    assert account_repository.get_account_id_for_key(pub) == orcid_acct.account_id
    _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=BIND_PATH,
        body={"idp": "github", "access_token": "gh_tok"},
    )
    gh_acct = account_repository.get_by_idp_subject(IdentityProvider.GITHUB, "42")
    assert account_repository.get_account_id_for_key(pub) == gh_acct.account_id
