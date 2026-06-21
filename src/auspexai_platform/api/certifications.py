"""Certifications routes — /api/v0/certifications (RFC 0001 / Research Ethics §6.7).

Read + revoke surface for the promotion-gate certification registry, so the
operator console can show what's certified and remove a standing approval. Both
maintainer-only.

  GET  /api/v0/certifications                          — list certifications
  POST /api/v0/certifications/{package_sha256}/revoke  — revoke (reason required)

ISSUING a certification stays a CLI/host operation (`auspexai-coordinator
certification issue`) — it needs the coordinator signing key + a built starter
manifest, and is a deliberate, signed maintainer act. Revocation is a plain
state change (§6.7.6), so it is exposed here for the console. Audited
(`certification.revoke`), same posture as every other trust action.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import AuditRepository, CertifiedProfileRepository


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _payload(rec) -> dict[str, Any]:
    """Certification → JSON for the console. Omits the raw COSE blob (binary); the
    signing pubkey + Rekor index are the verification handles."""
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
        "certified_at": rec.certified_at.isoformat() if rec.certified_at else None,
        "revoked_at": rec.revoked_at.isoformat() if rec.revoked_at else None,
        "revoked_reason": rec.revoked_reason,
    }


def build_router(
    credential_dep,
    certified_profile_repository: CertifiedProfileRepository,
    audit_repository: AuditRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/certifications")
    async def list_certifications(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        return {"certifications": [_payload(r) for r in certified_profile_repository.list_all()]}

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
