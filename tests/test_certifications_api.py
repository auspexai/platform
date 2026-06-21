"""/api/v0/certifications — public reads + maintainer revoke (RFC 0001 / Ethics §6.7)."""

from __future__ import annotations

import base64

from auspexai_platform.db.repositories import CertifiedProfileRepository


def _hdr(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def _seed(db) -> None:
    CertifiedProfileRepository(db).insert(
        package_sha256="a" * 64,
        snapshot_version="vigiles-tenant@v0.1.0",
        tenant_id="vigiles-lab",
        profile_name="starter",
        research_class="behavioral_drift",
        sensitive_content_flags=[],
        model_ids=["gemma-3-1b-it-q4"],
        replication_floor=2,
        max_units_ceiling=None,
        duration_hours_ceiling=1.0,
        cose_signed_blob=b"\x01\x02\x03",
        signing_key_pubkey_hex="ff" * 32,
        certified_by="maintainer:test",
    )


def test_list_is_public_and_carries_blob_and_logindex(client, db):
    # Anonymous-public — no Authorization header. The whole point: verify without us.
    _seed(db)
    r = client.get("/api/v0/certifications")
    assert r.status_code == 200
    certs = r.json()["certifications"]
    assert len(certs) == 1
    c = certs[0]
    assert c["profile_name"] == "starter" and c["status"] == "certified"
    # the blob is now exposed (b64) so a third party can verify it independently
    assert base64.b64decode(c["cose_signed_blob_b64"]) == b"\x01\x02\x03"
    assert "rekor_log_index" in c and "signing_key_pubkey_hex" in c


def test_get_one_is_public(client, db):
    _seed(db)
    r = client.get("/api/v0/certifications/" + "a" * 64)
    assert r.status_code == 200
    assert r.json()["package_sha256"] == "a" * 64


def test_get_one_missing_is_404(client):
    assert client.get("/api/v0/certifications/" + "b" * 64).status_code == 404


def test_revoke_requires_maintainer(client, db):
    _seed(db)
    # no auth → revoke is rejected (reads are public, writes are not)
    r = client.post("/api/v0/certifications/" + "a" * 64 + "/revoke", json={"reason": "x"})
    assert r.status_code in (401, 403)


def test_revoke_certification(client, maintainer_token, db):
    _seed(db)
    r = client.post(
        "/api/v0/certifications/" + "a" * 64 + "/revoke",
        headers=_hdr(maintainer_token),
        json={"reason": "superseded by v0.2.0"},
    )
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    listed = client.get("/api/v0/certifications").json()
    assert listed["certifications"][0]["status"] == "revoked"


def test_revoke_missing_is_404(client, maintainer_token):
    r = client.post(
        "/api/v0/certifications/" + "b" * 64 + "/revoke",
        headers=_hdr(maintainer_token),
        json={"reason": "x"},
    )
    assert r.status_code == 404
