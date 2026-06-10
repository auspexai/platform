"""Release registry + fleet announcement (§9 #46).

A maintainer records a published (GitHub) release to ANNOUNCE it: the
worker-heartbeat response relays the latest release for the worker's channel
and the volunteer elects to upgrade — never automatic (trust chain: the
maintainer gates what is OFFERED to the fleet, the volunteer gates what is
INSTALLED on their machine).

  POST /api/v0/releases            — maintainer records+announces a release;
                                     `fulfils_request_ids` links approved
                                     software requests, flipping them to
                                     `released` (validate-first, atomic-ish:
                                     no writes on any invalid id).
  GET  /api/v0/releases[?channel=] — maintainer or researcher (release info
                                     is public on GitHub anyway).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.repositories import (
    AuditRepository,
    ReleaseRepository,
    SoftwareRequestRepository,
)
from auspexai_platform.db.repositories.releases import Release, ReleaseExistsError
from auspexai_platform.events import EventBus


class ReleaseCreate(BaseModel):
    version: str = Field(min_length=1, max_length=64, description="bare version, no leading 'v'")
    channel: str = Field(default="worker", min_length=1, max_length=64)
    headline: str = Field(min_length=1, max_length=500)
    notes: str | None = Field(default=None, max_length=8000)
    release_url: str | None = Field(default=None, max_length=512)
    fulfils_request_ids: list[str] = Field(default_factory=list)


class ReleaseResponse(BaseModel):
    version: str
    channel: str
    headline: str
    notes: str | None = None
    release_url: str | None = None
    published_at: datetime
    announced_by: str
    fulfilled_request_ids: list[str] = Field(default_factory=list)


class ReleaseListResponse(BaseModel):
    releases: list[ReleaseResponse]


def _to_response(r: Release, *, fulfilled: list[str] | None = None) -> ReleaseResponse:
    return ReleaseResponse(
        version=r.version,
        channel=r.channel,
        headline=r.headline,
        notes=r.notes,
        release_url=r.release_url,
        published_at=r.published_at,
        announced_by=r.announced_by,
        fulfilled_request_ids=fulfilled or [],
    )


def build_router(
    credential_dep,
    release_repository: ReleaseRepository,
    software_request_repository: SoftwareRequestRepository,
    audit_repository: AuditRepository,
    *,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/releases",
        response_model=ReleaseResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def record_release(
        body: ReleaseCreate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ReleaseResponse:
        if not credential.is_maintainer():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")
        # Validate-first: every fulfilled request must exist and be `approved`
        # BEFORE any write — a bad id fails the whole call, no partial state.
        for request_id in body.fulfils_request_ids:
            req = software_request_repository.get_by_id(request_id)
            if req is None or req.status != "approved":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": {
                            "code": "request_not_approved",
                            "message": (
                                f"software request {request_id!r} "
                                + ("not found" if req is None else f"is {req.status!r}")
                                + " — only approved requests can be fulfilled by a release"
                            ),
                        }
                    },
                )
        try:
            release = release_repository.create(
                version=body.version,
                channel=body.channel,
                headline=body.headline,
                notes=body.notes,
                release_url=body.release_url,
                announced_by=credential.maintainer_login or "maintainer",
            )
        except ReleaseExistsError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "release_exists",
                        "message": f"release {body.channel}/{body.version} is already recorded",
                    }
                },
            ) from e
        for request_id in body.fulfils_request_ids:
            software_request_repository.mark_released(request_id, release_version=body.version)
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="release.publish",
            resource_type="release",
            resource_id=f"{body.channel}/{body.version}",
            payload={
                "version": body.version,
                "channel": body.channel,
                "headline": body.headline,
                "fulfils_request_ids": body.fulfils_request_ids,
            },
        )
        if event_bus is not None:
            event_bus.publish(
                "release.published",
                experiment_id=None,
                data={
                    "version": body.version,
                    "channel": body.channel,
                    "headline": body.headline,
                    "fulfils_request_ids": body.fulfils_request_ids,
                },
            )
        return _to_response(release, fulfilled=body.fulfils_request_ids)

    @router.get(
        "/releases",
        response_model=ReleaseListResponse,
        status_code=status.HTTP_200_OK,
    )
    async def list_releases(
        channel: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ReleaseListResponse:
        if not (credential.is_researcher() or credential.is_maintainer()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="researcher or maintainer credential required",
            )
        return ReleaseListResponse(
            releases=[_to_response(r) for r in release_repository.list(channel=channel)]
        )

    return router
