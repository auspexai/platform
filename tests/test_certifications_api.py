"""/api/v0/certifications — list + revoke (RFC 0001 / Ethics §6.7)."""

from __future__ import annotations

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
        cose_signed_blob=b"\x01\x02",
        signing_key_pubkey_hex="ff" * 32,
        certified_by="maintainer:test",
    )


def test_list_certifications(client, maintainer_token, db):
    _seed(db)
    r = client.get("/api/v0/certifications", headers=_hdr(maintainer_token))
    assert r.status_code == 200
    certs = r.json()["certifications"]
    assert len(certs) == 1
    c = certs[0]
    assert c["profile_name"] == "starter"
    assert c["status"] == "certified"
    assert c["replication_floor"] == 2
    assert c["advisor"] is None
    assert "cose_signed_blob" not in c  # binary omitted from the payload


def test_revoke_certification(client, maintainer_token, db):
    _seed(db)
    r = client.post(
        "/api/v0/certifications/" + "a" * 64 + "/revoke",
        headers=_hdr(maintainer_token),
        json={"reason": "superseded by v0.2.0"},
    )
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # idempotent surface: it now lists as revoked
    listed = client.get("/api/v0/certifications", headers=_hdr(maintainer_token)).json()
    assert listed["certifications"][0]["status"] == "revoked"


def test_revoke_missing_is_404(client, maintainer_token):
    r = client.post(
        "/api/v0/certifications/" + "b" * 64 + "/revoke",
        headers=_hdr(maintainer_token),
        json={"reason": "x"},
    )
    assert r.status_code == 404


def test_certifications_requires_maintainer(client):
    assert client.get("/api/v0/certifications").status_code in (401, 403)
