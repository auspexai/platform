"""Certifications routes — /api/v0/certifications (RFC 0001 / Research Ethics §6.7).

The PUBLIC registry of promotion-gate certifications — the "publish" half of
§6.7.4 (sign + publish + contest). Reads are anonymous-public so anyone can
independently verify a certification WITHOUT trusting (or even contacting) a
maintainer: the payload carries the COSE blob + its Rekor logIndex, and the trust
chain closes against PUBLIC sources — public Rekor (the blob's hash + timestamp)
and the published AUTHORIZED_SIGNERS roster (the signing key). We only hand over
data; the verdict comes from sources we don't control.

  GET  /api/v0/certifications                          — list (anonymous-public)
  GET  /api/v0/certifications/{package_sha256}         — one cert (anonymous-public)
  POST /api/v0/certifications/{package_sha256}/revoke  — revoke (maintainer only)

ISSUING stays a CLI/host act (`auspexai-coordinator certification issue`) — it
needs the coordinator signing key + a built manifest. Revocation is a maintainer
state change (§6.7.6), audited (`certification.revoke`).
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.certification import is_newer_build
from auspexai_platform.db.repositories import AuditRepository, CertifiedProfileRepository


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _payload(rec) -> dict[str, Any]:
    """Certification → public JSON. Includes the COSE blob (b64) + Rekor logIndex
    so a third party has everything needed to verify against public Rekor + the
    signer roster. Nothing here is sensitive — it IS the published certificate."""
    return {
        "package_sha256": rec.package_sha256,
        "snapshot_version": rec.snapshot_version,
        "tenant_id": rec.tenant_id,
        "profile_name": rec.profile_name,
        "status": rec.status,
        "research_class": rec.research_class,
        "sensitive_content_flags": rec.sensitive_content_flags,
        "model_ids": rec.model_ids,
        "replication_floor": rec.replication_floor,
        "max_units_ceiling": rec.max_units_ceiling,
        "duration_hours_ceiling": rec.duration_hours_ceiling,
        "certified_by": rec.certified_by,
        "advisor": rec.advisor,
        "signing_key_pubkey_hex": rec.signing_key_pubkey_hex,
        "rekor_log_index": rec.rekor_log_index,
        "cose_signed_blob_b64": base64.b64encode(rec.cose_signed_blob).decode("ascii"),
        "certified_at": rec.certified_at.isoformat() if rec.certified_at else None,
        "revoked_at": rec.revoked_at.isoformat() if rec.revoked_at else None,
        "revoked_reason": rec.revoked_reason,
    }


def build_router(
    credential_dep,
    certified_profile_repository: CertifiedProfileRepository,
    audit_repository: AuditRepository,
    manifest_repository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/certifications")
    async def list_certifications() -> dict[str, Any]:
        # Anonymous-public: this list IS the published registry (§6.7.4 publish).
        return {"certifications": [_payload(r) for r in certified_profile_repository.list_all()]}

    # Defined BEFORE /certifications/{package_sha256} so "staleness" isn't matched
    # as a package digest.
    @router.get("/certifications/staleness")
    async def certification_staleness(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        """Maintainer-only: per active certification, whether a NEWER BUILD of its
        profile has been submitted (same locked fields, different package digest —
        it reverted to review by the content-addressed gate; surface it so the
        Maintainer can re-certify). NOT on the public registry — it reflects
        submission activity. Keyed by the certified `package_sha256`."""
        require_maintainer(credential)
        active = [c for c in certified_profile_repository.list_all() if c.status == "certified"]
        by_tenant: dict[str, list[Any]] = {}
        for c in active:
            by_tenant.setdefault(c.tenant_id, []).append(c)
        stale: dict[str, Any] = {}
        for tenant_id, tcerts in by_tenant.items():
            manifests = manifest_repository.list_for_tenant(tenant_id)  # ascending by uploaded_at
            for cert in tcerts:
                newer = None
                for m in manifests:
                    if is_newer_build(m.manifest_json, cert):
                        newer = m  # keep the latest match (list is ascending)
                if newer is not None:
                    pkg = (newer.manifest_json.get("executor") or {}).get("package_sha256", "")
                    stale[cert.package_sha256] = {
                        "newer_build_seen": True,
                        "newer_package_sha256": pkg,
                        "seen_at": newer.uploaded_at.isoformat(),
                    }
        return {"stale": stale}

    @router.get("/certifications/{package_sha256}")
    async def get_certification(package_sha256: str) -> dict[str, Any]:
        # Anonymous-public: fetch one cert by its content-addressed package digest,
        # so a verifier can pull exactly the blob + logIndex they need.
        rec = certified_profile_repository.get_by_package(package_sha256)
        if rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="no such certification"
            )
        return _payload(rec)

    @router.post("/certifications/{package_sha256}/revoke", status_code=status.HTTP_200_OK)
    async def revoke_certification(
        package_sha256: str,
        body: RevokeRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        rec = certified_profile_repository.get_by_package(package_sha256)
        if rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="no such certification"
            )
        actor = credential.maintainer_login or "maintainer"
        certified_profile_repository.revoke(package_sha256, reason=body.reason)
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=actor,
            actor_tenant_id=None,
            action="certification.revoke",
            resource_type="certified_profile",
            resource_id=package_sha256,
            payload={
                "tenant_id": rec.tenant_id,
                "profile_name": rec.profile_name,
                "snapshot_version": rec.snapshot_version,
                "reason": body.reason,
            },
        )
        return _payload(certified_profile_repository.get_by_package(package_sha256))

    return router
