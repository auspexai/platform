"""Researcher onboarding Option D — tenant-application pipeline.

Submission is RFC-9421 signed and verified against ITS OWN keyid (proof of
possession for a deliberately UNREGISTERED applying key) plus a GitHub access
token verified through the volunteer identity machinery. Covers the
proof-of-possession negatives, the one-pending-per-account 409, the
maintainer-only queue + actions, the atomic approve (tenant created with the
applying key bound + account linked — verified end-to-end via whoami), the
mandatory decline reason, /mine key-scoping, and the submit rate limit.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import TenantApplicationRepository
from auspexai_platform.events import GLOBAL
from auspexai_platform.oauth.identity import IdentityClaim

APPLY_PATH = "/api/v0/tenant-applications"

_GH_TOKEN = "gho_applicant_token"
_GH_CLAIM = IdentityClaim(
    idp=IdentityProvider.GITHUB,
    idp_sub="987654",
    display_name="vigiles-dev",
    email="vigiles@example.org",
)


def _apply_body(**overrides) -> dict:
    body = {
        "github_access_token": _GH_TOKEN,
        "requested_tenant_id": "vigiles",
        "contact_name": "Vigiles Dev",
        "affiliation": "Independent — drift-probe research",
        "research_summary": "Deterministic local-inference drift probes over volunteer compute.",
    }
    body.update(overrides)
    return body


def _signed_post(
    client: TestClient,
    *,
    privkey,
    pubkey_hex: str,
    path: str,
    body: dict,
    extra_headers: dict | None = None,
):
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
    if extra_headers:
        headers.update(extra_headers)
    return client.post(path, headers=headers, content=raw)


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


def _mtnr(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


@pytest.fixture
def applicant_keypair() -> tuple[Ed25519PrivateKey, str]:
    """(privkey, pubkey_hex) — the UNREGISTERED applying key."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


@pytest.fixture
def application_repository(db) -> TenantApplicationRepository:
    return TenantApplicationRepository(db)


@pytest.fixture
def applied(client, identity_verifier, applicant_keypair) -> dict:
    """A submitted (pending) application. Returns the 201 response body
    augmented with the applying keypair."""
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=_apply_body())
    assert r.status_code == 201, r.text
    return {**r.json(), "privkey": priv, "pubkey_hex": pub}


# ---- POST /tenant-applications (submit) --------------------------------------


def test_submit_creates_pending_application_account_audit_event(
    client: TestClient,
    identity_verifier,
    applicant_keypair,
    account_repository,
    application_repository,
    audit_repository,
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=_apply_body())
        ev = q.get_nowait()
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["application_id"].startswith("tapp-")
    assert created["status"] == "pending"

    # Account resolved-or-created from the verified GitHub identity.
    account = account_repository.get_by_idp_subject(IdentityProvider.GITHUB, _GH_CLAIM.idp_sub)
    assert account is not None

    # Row carries the verified keyid + GitHub login and links the account.
    row = application_repository.get_by_id(created["application_id"])
    assert row is not None
    assert row.pubkey_hex == pub
    assert row.github_login == "vigiles-dev"
    assert row.account_id == account.account_id
    assert row.requested_tenant_id == "vigiles"

    assert ev.type == "application.submitted"
    assert ev.data["application_id"] == created["application_id"]
    assert ev.data["requested_tenant_id"] == "vigiles"
    entries = [e for e in audit_repository.latest() if e.action == "application.submitted"]
    assert entries and entries[0].resource_id == created["application_id"]
    assert entries[0].payload["account_id"] == account.account_id


def test_submit_proof_of_possession_rejects_wrong_key(
    client: TestClient, identity_verifier, applicant_keypair
) -> None:
    """Signing with key A while claiming keyid B must 401 — the applying key
    must PROVE possession of the private half of the keyid it asks to bind."""
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    signer_priv = Ed25519PrivateKey.generate()  # key A signs...
    _, claimed_pub = applicant_keypair  # ...but keyid claims key B
    r = _signed_post(
        client, privkey=signer_priv, pubkey_hex=claimed_pub, path=APPLY_PATH, body=_apply_body()
    )
    assert r.status_code == 401
    assert "verification failed" in r.text


def test_submit_unsigned_is_401(client: TestClient, identity_verifier) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    r = client.post(APPLY_PATH, json=_apply_body())
    assert r.status_code == 401
    assert "signature_required" in r.text


def test_submit_invalid_github_token_is_401(client: TestClient, applicant_keypair) -> None:
    # Nothing registered with the fake verifier → IdP rejects the token.
    priv, pub = applicant_keypair
    r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=_apply_body())
    assert r.status_code == 401
    assert "invalid_access_token" in r.text


def test_submit_second_pending_for_same_account_409(
    client: TestClient, identity_verifier, applied
) -> None:
    """One pending application per account — even from a fresh applying key."""
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    r = _signed_post(
        client,
        privkey=other_priv,
        pubkey_hex=other_pub,
        path=APPLY_PATH,
        body=_apply_body(requested_tenant_id="vigiles-2"),
    )
    assert r.status_code == 409
    assert "application_pending" in r.text


def test_submit_again_after_decline_is_allowed(
    client: TestClient, applied, maintainer_token
) -> None:
    r = client.post(
        f"{APPLY_PATH}/{applied['application_id']}/actions/decline",
        json={"reason": "summary too thin; resubmit with detail"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200
    r = _signed_post(
        client,
        privkey=applied["privkey"],
        pubkey_hex=applied["pubkey_hex"],
        path=APPLY_PATH,
        body=_apply_body(),
    )
    assert r.status_code == 201, r.text


def test_submit_validates_field_lengths(
    client: TestClient, identity_verifier, applicant_keypair
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=APPLY_PATH,
        body=_apply_body(research_summary="x" * 4001),
    )
    assert r.status_code == 422
    r = _signed_post(
        client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=_apply_body(contact_name="")
    )
    assert r.status_code == 422


# ---- research classes (migration 0029) ----------------------------------------


def test_submit_with_research_classes_stores_and_returns_them(
    client: TestClient,
    identity_verifier,
    applicant_keypair,
    application_repository,
    maintainer_token,
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=APPLY_PATH,
        body=_apply_body(research_classes=["behavioral_drift", "eval_sweeps"]),
    )
    assert r.status_code == 201, r.text

    # Stored on the row (alongside the summary)...
    row = application_repository.get_by_id(r.json()["application_id"])
    assert row.research_classes == ["behavioral_drift", "eval_sweeps"]
    assert row.research_summary  # summary still stored when both are given

    # ...and surfaced on the maintainer queue.
    apps = client.get(APPLY_PATH, headers=_mtnr(maintainer_token)).json()["applications"]
    assert apps[0]["research_classes"] == ["behavioral_drift", "eval_sweeps"]


def test_submit_unknown_research_class_422(
    client: TestClient, identity_verifier, applicant_keypair
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=APPLY_PATH,
        body=_apply_body(research_classes=["behavioral_drift", "weight_exfiltration"]),
    )
    assert r.status_code == 422
    assert "weight_exfiltration" in r.text  # the message names the offender


def test_submit_neither_classes_nor_summary_422(
    client: TestClient, identity_verifier, applicant_keypair
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    # Summary key absent entirely, no classes.
    body = _apply_body()
    del body["research_summary"]
    r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=body)
    assert r.status_code == 422
    assert "at least one of" in r.text
    # Empty-string summary + empty class list is equally rejected.
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=APPLY_PATH,
        body=_apply_body(research_summary="", research_classes=[]),
    )
    assert r.status_code == 422


def test_submit_classes_only_ok(
    client: TestClient,
    identity_verifier,
    applicant_keypair,
    application_repository,
    maintainer_token,
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    body = _apply_body(research_classes=["quantization_effects", "other"])
    del body["research_summary"]
    r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=body)
    assert r.status_code == 201, r.text
    row = application_repository.get_by_id(r.json()["application_id"])
    assert row.research_classes == ["quantization_effects", "other"]
    assert row.research_summary == ""  # 0028 NOT NULL column: '' = omitted

    apps = client.get(APPLY_PATH, headers=_mtnr(maintainer_token)).json()["applications"]
    assert apps[0]["research_classes"] == ["quantization_effects", "other"]
    assert apps[0]["research_summary"] == ""


def test_submit_summary_only_backward_compat(
    client: TestClient, identity_verifier, applicant_keypair, maintainer_token
) -> None:
    """The pre-0029 body shape (no research_classes key) still 201s and the
    maintainer view surfaces research_classes as []."""
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(client, privkey=priv, pubkey_hex=pub, path=APPLY_PATH, body=_apply_body())
    assert r.status_code == 201, r.text
    apps = client.get(APPLY_PATH, headers=_mtnr(maintainer_token)).json()["applications"]
    assert apps[0]["research_classes"] == []


def test_submit_research_classes_deduped(
    client: TestClient, identity_verifier, applicant_keypair, application_repository
) -> None:
    identity_verifier.register(_GH_TOKEN, _GH_CLAIM)
    priv, pub = applicant_keypair
    r = _signed_post(
        client,
        privkey=priv,
        pubkey_hex=pub,
        path=APPLY_PATH,
        body=_apply_body(research_classes=["other", "behavioral_drift", "other"]),
    )
    assert r.status_code == 201, r.text
    row = application_repository.get_by_id(r.json()["application_id"])
    assert row.research_classes == ["other", "behavioral_drift"]  # order-preserving dedupe


def test_submit_rate_limited_per_ip(client: TestClient) -> None:
    """10/hour per IP on the submit route. Unsigned requests 401 inside the
    handler but still consume the bucket, so the 11th earns 429."""
    ip = {"CF-Connecting-IP": "203.0.113.77"}
    for i in range(10):
        r = client.post(APPLY_PATH, json=_apply_body(), headers=ip)
        assert r.status_code != 429, f"submit {i + 1}/10 hit rate limit unexpectedly"
    r = client.post(APPLY_PATH, json=_apply_body(), headers=ip)
    assert r.status_code == 429


# ---- GET /tenant-applications (maintainer queue) ------------------------------


def test_list_is_maintainer_only(
    client: TestClient, applied, registered_tenant, maintainer_token
) -> None:
    r = client.get(APPLY_PATH, headers=_mtnr(maintainer_token))
    assert r.status_code == 200
    apps = r.json()["applications"]
    assert [a["application_id"] for a in apps] == [applied["application_id"]]
    # Maintainer view carries ALL fields.
    assert apps[0]["github_login"] == "vigiles-dev"
    assert apps[0]["pubkey_hex"] == applied["pubkey_hex"]
    assert apps[0]["affiliation"] == "Independent — drift-probe research"
    assert apps[0]["contact_name"] == "Vigiles Dev"
    assert apps[0]["account_id"]
    assert apps[0]["research_summary"]

    # Registered researcher → 403 (not their surface); anonymous → 403.
    privkey, binding = registered_tenant
    r = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=APPLY_PATH)
    assert r.status_code == 403
    r = client.get(APPLY_PATH)
    assert r.status_code == 403


def test_list_status_filter(client: TestClient, applied, maintainer_token) -> None:
    r = client.get(f"{APPLY_PATH}?status_filter=pending", headers=_mtnr(maintainer_token))
    assert [a["application_id"] for a in r.json()["applications"]] == [applied["application_id"]]
    r = client.get(f"{APPLY_PATH}?status_filter=approved", headers=_mtnr(maintainer_token))
    assert r.json()["applications"] == []


# ---- GET /tenant-applications/mine --------------------------------------------


def test_mine_is_scoped_to_the_signing_key(client: TestClient, applied) -> None:
    r = _signed_get(
        client,
        privkey=applied["privkey"],
        pubkey_hex=applied["pubkey_hex"],
        path=f"{APPLY_PATH}/mine",
    )
    assert r.status_code == 200
    mine = r.json()["applications"]
    assert len(mine) == 1
    assert mine[0] == {
        "application_id": applied["application_id"],
        "status": "pending",
        "resolution_reason": None,
        "created_tenant_id": None,
    }

    # NEGATIVE: a different (also unregistered) key sees nothing.
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    r = _signed_get(client, privkey=other_priv, pubkey_hex=other_pub, path=f"{APPLY_PATH}/mine")
    assert r.status_code == 200
    assert r.json()["applications"] == []


def test_mine_unsigned_is_401(client: TestClient) -> None:
    assert client.get(f"{APPLY_PATH}/mine").status_code == 401


def test_mine_surfaces_resolution(client: TestClient, applied, maintainer_token) -> None:
    client.post(
        f"{APPLY_PATH}/{applied['application_id']}/actions/approve",
        json={},
        headers=_mtnr(maintainer_token),
    )
    r = _signed_get(
        client,
        privkey=applied["privkey"],
        pubkey_hex=applied["pubkey_hex"],
        path=f"{APPLY_PATH}/mine",
    )
    mine = r.json()["applications"][0]
    assert mine["status"] == "approved"
    assert mine["created_tenant_id"] == "vigiles"


# ---- approve -------------------------------------------------------------------


def test_approve_creates_tenant_binds_key_and_links_account(
    client: TestClient,
    applied,
    maintainer_token,
    tenant_repository,
    account_repository,
    audit_repository,
) -> None:
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"{APPLY_PATH}/{applied['application_id']}/actions/approve",
            json={},
            headers=_mtnr(maintainer_token),
        )
        ev = q.get_nowait()
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["created_tenant_id"] == "vigiles"
    assert body["resolved_by"]
    assert body["resolved_at"]

    # The tenants row: applying pubkey bound as maintainer_pubkey, account linked.
    account = account_repository.get_by_idp_subject(IdentityProvider.GITHUB, _GH_CLAIM.idp_sub)
    tenant = tenant_repository.get_by_id("vigiles")
    assert tenant is not None
    assert tenant.maintainer_pubkey == applied["pubkey_hex"]
    assert tenant.account_id == account.account_id
    # The application's metadata is carried into the tenant record (operators
    # were seeing placeholder rows — researcher-#0 finding, 2026-06-12).
    assert tenant.display_name == "Vigiles Dev (Independent — drift-probe research)"
    assert tenant.contact_public == "github:vigiles-dev"
    assert "drift probes" in (tenant.description or "")

    # End-to-end: the applying key now resolves as a live researcher credential.
    r = _signed_get(
        client,
        privkey=applied["privkey"],
        pubkey_hex=applied["pubkey_hex"],
        path="/api/v0/auth/whoami",
    )
    assert r.status_code == 200
    assert r.json()["credential_class"] == "researcher"
    assert r.json()["tenant_id"] == "vigiles"

    assert ev.type == "application.resolved"
    assert ev.data["status"] == "approved"
    assert ev.data["created_tenant_id"] == "vigiles"
    entries = [e for e in audit_repository.latest() if e.action == "application.resolved"]
    assert entries and entries[0].payload["new_status"] == "approved"
    assert entries[0].payload["tenant_id"] == "vigiles"


def test_approve_with_tenant_id_override(
    client: TestClient, applied, maintainer_token, tenant_repository
) -> None:
    r = client.post(
        f"{APPLY_PATH}/{applied['application_id']}/actions/approve",
        json={"tenant_id_override": "vigiles-probe"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_tenant_id"] == "vigiles-probe"
    assert tenant_repository.get_by_id("vigiles-probe") is not None
    assert tenant_repository.get_by_id("vigiles") is None


def test_approve_taken_tenant_id_409_keeps_pending_then_override_succeeds(
    client: TestClient, applied, maintainer_token, tenant_registry, application_repository
) -> None:
    # Squat the requested id with an unrelated tenant.
    squatter = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="vigiles", pubkey_hex=squatter)

    r = client.post(
        f"{APPLY_PATH}/{applied['application_id']}/actions/approve",
        json={},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 409
    assert "tenant_id_taken" in r.text
    # Atomic rollback: the application is still pending and retryable.
    row = application_repository.get_by_id(applied["application_id"])
    assert row.status == "pending"
    assert row.created_tenant_id is None

    r = client.post(
        f"{APPLY_PATH}/{applied['application_id']}/actions/approve",
        json={"tenant_id_override": "vigiles-2"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_tenant_id"] == "vigiles-2"


def test_actions_are_maintainer_only(client: TestClient, applied, registered_tenant) -> None:
    privkey, binding = registered_tenant
    for action, body in (("approve", {}), ("decline", {"reason": "nope"})):
        path = f"{APPLY_PATH}/{applied['application_id']}/actions/{action}"
        # Registered researcher → 403.
        r = _signed_post(
            client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path, body=body
        )
        assert r.status_code == 403, f"{action}: {r.text}"
        # Anonymous → 403.
        r = client.post(path, json=body)
        assert r.status_code == 403, f"{action}: {r.text}"


# ---- decline -------------------------------------------------------------------


def test_decline_requires_reason_and_records_it(
    client: TestClient, applied, maintainer_token, audit_repository
) -> None:
    path = f"{APPLY_PATH}/{applied['application_id']}/actions/decline"
    assert (
        client.post(path, json={"reason": ""}, headers=_mtnr(maintainer_token)).status_code == 422
    )
    assert client.post(path, json={}, headers=_mtnr(maintainer_token)).status_code == 422

    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            path, json={"reason": "affiliation unverifiable"}, headers=_mtnr(maintainer_token)
        )
        ev = q.get_nowait()
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "declined"
    assert body["resolution_reason"] == "affiliation unverifiable"
    assert body["created_tenant_id"] is None
    assert ev.type == "application.resolved"
    assert ev.data["status"] == "declined"
    entries = [e for e in audit_repository.latest() if e.action == "application.resolved"]
    assert entries and entries[0].payload["reason"] == "affiliation unverifiable"


def test_resolve_twice_conflicts_and_unknown_id_404s(
    client: TestClient, applied, maintainer_token
) -> None:
    rid = applied["application_id"]
    r = client.post(
        f"{APPLY_PATH}/{rid}/actions/decline",
        json={"reason": "first resolution"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 200
    # Both actions 409 on a non-pending application.
    r = client.post(
        f"{APPLY_PATH}/{rid}/actions/decline",
        json={"reason": "again"},
        headers=_mtnr(maintainer_token),
    )
    assert r.status_code == 409
    r = client.post(f"{APPLY_PATH}/{rid}/actions/approve", json={}, headers=_mtnr(maintainer_token))
    assert r.status_code == 409
    r = client.post(
        f"{APPLY_PATH}/tapp-missing0/actions/approve", json={}, headers=_mtnr(maintainer_token)
    )
    assert r.status_code == 404
