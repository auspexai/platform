"""Tier-1 (increment C): a connected ACCOUNT runs a public tenant's certified
starter — the certification record IS the public-access grant.

An account (no tenant) may submit a manifest that matches an ACTIVE certified
profile, under the certifying tenant. It then lists + views ONLY its OWN run;
another account sees nothing (no leak). Non-certified / suspended are rejected.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories.certified_profiles import CertifiedProfileRepository
from auspexai_platform.db.repositories.tenants import TenantRepository
from auspexai_platform.oauth.identity import IdentityClaim

EXP_PATH = "/api/v0/experiments"
BIND_PATH = "/api/v0/accounts/bind"
PKG = "a" * 64


def _starter_manifest(**over):
    m = {
        "tenant_id": "vigiles-lab",
        "experiment_id": "vigiles-run",
        "research_class": "behavioral_drift",
        "sensitive_content_flags": [],
        "models": [{"id": "gemma-3-1b-it-q4"}],
        "replication_factor": 2,
        "expected_duration_hours": 1.0,
        "executor": {"package_sha256": PKG},
        "reducer": {"kind": "builtin_hash_agreement"},
    }
    m.update(over)
    return m


def _certify(db) -> None:
    # The public starter tenant must exist (manifest FK; the run is under it). The
    # account is NOT its maintainer ('bb'*32) — it runs as an ACCOUNT, not owner.
    TenantRepository(db).register(tenant_id="vigiles-lab", maintainer_pubkey="bb" * 32)
    CertifiedProfileRepository(db).insert(
        package_sha256=PKG,
        snapshot_version="vigiles-tenant@v0.1.0",
        tenant_id="vigiles-lab",
        profile_name="starter",
        research_class="behavioral_drift",
        sensitive_content_flags=[],
        model_ids=["gemma-3-1b-it-q4"],
        replication_floor=2,
        max_units_ceiling=None,
        duration_hours_ceiling=1.0,
        cose_signed_blob=b"\x01\x02",
        signing_key_pubkey_hex="ff" * 32,
        certified_by="maintainer:test",
    )


def _connect(client, identity_verifier, *, idp_sub, token):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    identity_verifier.register(
        token,
        IdentityClaim(idp=IdentityProvider.ORCID, idp_sub=idp_sub, display_name="Researcher"),
    )
    raw = json.dumps({"idp": "orcid", "access_token": token}).encode()
    headers = sign_request(
        privkey=priv,
        pubkey_hex=pub,
        method="POST",
        path=BIND_PATH,
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    r = client.post(BIND_PATH, headers=headers, content=raw)
    assert r.status_code == 200, r.text
    return priv, pub, r.json()["account_id"]


def _submit(client, privkey, pubkey_hex, manifest):
    raw = json.dumps({"manifest": manifest, "signature": {"sig": "x"}}).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=EXP_PATH,
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    return client.post(EXP_PATH, headers=headers, content=raw)


def _get(client, privkey, pubkey_hex, path):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


def test_account_runs_certified_starter_and_sees_only_its_own(
    client: TestClient, db, identity_verifier, account_repository
) -> None:
    _certify(db)
    a_priv, a_pub, _ = _connect(client, identity_verifier, idp_sub="0000-0001", token="tok-a")
    b_priv, b_pub, _ = _connect(client, identity_verifier, idp_sub="0000-0002", token="tok-b")

    # A runs the certified starter under the public tenant — no tenant of its own.
    r = _submit(client, a_priv, a_pub, _starter_manifest())
    assert r.status_code == 201, r.text
    exp_id = r.json()["experiment_id"]

    # A lists + views ITS OWN run, and sees the (tenant-scoped) status field.
    lst = _get(client, a_priv, a_pub, EXP_PATH).json()["experiments"]
    assert [e["experiment_id"] for e in lst] == [exp_id]
    detail = _get(client, a_priv, a_pub, f"{EXP_PATH}/{exp_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "submitted"  # tenant-scoped field, visible to the runner

    # B sees NOTHING — not in B's list, 404 on B's detail fetch (no existence leak).
    assert _get(client, b_priv, b_pub, EXP_PATH).json()["experiments"] == []
    assert _get(client, b_priv, b_pub, f"{EXP_PATH}/{exp_id}").status_code == 404


def test_account_non_certified_manifest_forbidden(
    client: TestClient, db, identity_verifier
) -> None:
    # No cert registered → certified_match is None → the account path is forbidden.
    a_priv, a_pub, _ = _connect(client, identity_verifier, idp_sub="0000-0003", token="tok-c")
    r = _submit(client, a_priv, a_pub, _starter_manifest())
    assert r.status_code == 403
    assert "not_a_public_certified_starter" in r.text


def test_suspended_account_forbidden(
    client: TestClient, db, identity_verifier, account_repository
) -> None:
    _certify(db)
    a_priv, a_pub, a_acct = _connect(client, identity_verifier, idp_sub="0000-0004", token="tok-d")
    account_repository.suspend(a_acct, reason="abuse")
    r = _submit(client, a_priv, a_pub, _starter_manifest())
    assert r.status_code == 403
    assert "account_not_runnable" in r.text
