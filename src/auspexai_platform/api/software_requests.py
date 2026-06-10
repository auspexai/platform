"""Software-requirements pipeline — the code-plane demand board (§9 #46).

The software analog of model_requests.py: a researcher signals that an
experiment needs a worker-baseline capability the network doesn't provide
(e.g. an inference backend). Code-plane requests always enter the maintainer
review queue (no "available" auto-status), and carry an ASSESSMENT stage —
dependencies / security / alternatives — reviewable before approve/decline:

  POST /api/v0/software-requests                  — researcher submits (pending).
  GET  /api/v0/software-requests[?status=]        — maintainer: all; researcher:
                                                    own tenant's (the "my
                                                    requests" surface).
  GET  /api/v0/software-requests/{id}             — maintainer or owning tenant.
  POST .../actions/assess                         — maintainer attaches the
                                                    assessment (draft=true marks
                                                    an unratified auto-draft;
                                                    ratify = re-attach draft=false).
  POST .../actions/approve|decline                — maintainer resolves with a
                                                    mandatory, audited reason.
                                                    Approving without a ratified
                                                    assessment proceeds but is
                                                    recorded as a gate override
                                                    (warn-but-allow, mirroring
                                                    the accounts promotion gates).

Status `released` is set by POST /releases (releases.py) when a recorded
release names this request in fulfils_request_ids — not by an endpoint here.
"""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.repositories import AuditRepository, SoftwareRequestRepository
from auspexai_platform.db.repositories.software_requests import SoftwareRequest
from auspexai_platform.events import EventBus


class SoftwareRequestCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    reason: str = Field(min_length=1, max_length=2000)


class Assessment(BaseModel):
    """The pre-approval review artifact: what it pulls in, what it exposes,
    and what else could meet the need."""

    dependencies: str = Field(min_length=1, max_length=8000)
    security: str = Field(min_length=1, max_length=8000)
    alternatives: str = Field(min_length=1, max_length=8000)
    summary: str | None = Field(default=None, max_length=2000)


class AssessRequest(BaseModel):
    assessment: Assessment
    draft: bool = Field(
        default=False,
        description=(
            "True marks an unratified auto-draft (e.g. from the assessment "
            "agent); a maintainer ratifies by re-attaching with draft=false."
        ),
    )


class ResolveRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class SoftwareRequestResponse(BaseModel):
    request_id: str
    tenant_id: str
    title: str
    description: str
    reason: str
    status: str
    created_at: datetime
    assessment: Assessment | None = None
    assessment_draft: bool = False
    assessed_at: datetime | None = None
    assessed_by: str | None = None
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None
    release_version: str | None = None
    released_at: datetime | None = None


class SoftwareRequestResolveResponse(SoftwareRequestResponse):
    """Approve/decline response — adds the warn-but-allow gate fields
    (mirrors the accounts promotion-gate pattern)."""

    gate_override: bool = False
    gate_warnings: list[str] = Field(default_factory=list)


class SoftwareRequestListResponse(BaseModel):
    requests: list[SoftwareRequestResponse]


_RESOLVABLE_STATUSES = ("pending", "assessed")


def _require_maintainer(credential: Credential) -> None:
    if not credential.is_maintainer():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maintainer required")


def _forbid_queue_access() -> HTTPException:
    # Module-level so routes whose `status` query param shadows the fastapi
    # `status` module can still raise the canonical 403.
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="researcher or maintainer credential required",
    )


def _to_response(
    r: SoftwareRequest, *, cls: type[SoftwareRequestResponse] = SoftwareRequestResponse
) -> SoftwareRequestResponse:
    assessment = None
    if r.assessment_json:
        assessment = Assessment.model_validate(json.loads(r.assessment_json))
    return cls(
        request_id=r.request_id,
        tenant_id=r.tenant_id,
        title=r.title,
        description=r.description,
        reason=r.reason,
        status=r.status,
        created_at=r.created_at,
        assessment=assessment,
        assessment_draft=r.assessment_draft,
        assessed_at=r.assessed_at,
        assessed_by=r.assessed_by,
        resolved_at=r.resolved_at,
        resolved_by=r.resolved_by,
        resolution_reason=r.resolution_reason,
        release_version=r.release_version,
        released_at=r.released_at,
    )


def build_router(
    credential_dep,
    software_request_repository: SoftwareRequestRepository,
    audit_repository: AuditRepository,
    *,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    def _publish(event_type: str, data: dict) -> None:
        if event_bus is not None:
            event_bus.publish(event_type, experiment_id=None, data=data)

    @router.post(
        "/software-requests",
        response_model=SoftwareRequestResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_software_request(
        body: SoftwareRequestCreate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestResponse:
        if not credential.is_researcher() or not credential.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_required",
                        "message": (
                            "a researcher credential is required to request a software capability"
                        ),
                    }
                },
            )
        req = software_request_repository.create(
            tenant_id=credential.tenant_id,
            title=body.title,
            description=body.description,
            reason=body.reason,
        )
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="software_request.create",
            resource_type="software_request",
            resource_id=req.request_id,
            payload={"title": body.title, "status": req.status},
        )
        _publish(
            "requirement.submitted",
            {
                "request_id": req.request_id,
                "kind": "software",
                "tenant_id": req.tenant_id,
                "title": req.title,
                "status": req.status,
            },
        )
        return _to_response(req)

    @router.get(
        "/software-requests",
        response_model=SoftwareRequestListResponse,
        status_code=status.HTTP_200_OK,
    )
    async def list_software_requests(
        status: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestListResponse:
        # Dual-audience: maintainers see the whole queue; a researcher gets a
        # tenant-forced view of their own requests (the "my requests" surface).
        if credential.is_maintainer():
            reqs = software_request_repository.list(status=status)
        elif credential.is_researcher() and credential.tenant_id:
            reqs = software_request_repository.list(status=status, tenant_id=credential.tenant_id)
        else:
            raise _forbid_queue_access()
        return SoftwareRequestListResponse(requests=[_to_response(r) for r in reqs])

    @router.get(
        "/software-requests/{request_id}",
        response_model=SoftwareRequestResponse,
        status_code=status.HTTP_200_OK,
    )
    async def get_software_request(
        request_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestResponse:
        req = software_request_repository.get_by_id(request_id)
        # Tenant-private: a foreign tenant gets the same 404 as a missing id.
        visible = req is not None and (
            credential.is_maintainer()
            or (credential.is_researcher() and credential.tenant_id == req.tenant_id)
        )
        if not visible:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="software request not found"
            )
        assert req is not None
        return _to_response(req)

    @router.post(
        "/software-requests/{request_id}/actions/assess",
        response_model=SoftwareRequestResponse,
        status_code=status.HTTP_200_OK,
    )
    async def assess_software_request(
        request_id: str,
        body: AssessRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestResponse:
        _require_maintainer(credential)
        existing = software_request_repository.get_by_id(request_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="software request not found"
            )
        if existing.status not in _RESOLVABLE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "invalid_status_transition",
                        "message": (
                            f"cannot assess a request in status {existing.status!r} "
                            "(only pending/assessed)"
                        ),
                    }
                },
            )
        re_assessment = existing.assessment_json is not None
        assessed_by = credential.maintainer_login or "maintainer"
        req = software_request_repository.attach_assessment(
            request_id,
            assessment_json=json.dumps(body.assessment.model_dump()),
            assessed_by=assessed_by,
            draft=body.draft,
        )
        assert req is not None
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action="software_request.assess",
            resource_type="software_request",
            resource_id=request_id,
            payload={
                "draft": body.draft,
                "re_assessment": re_assessment,
                "summary": body.assessment.summary,
            },
        )
        _publish(
            "requirement.assessed",
            {"request_id": request_id, "assessed_by": assessed_by, "draft": body.draft},
        )
        return _to_response(req)

    def _resolve(
        request_id: str, new_status: str, reason: str, credential: Credential
    ) -> SoftwareRequestResolveResponse:
        _require_maintainer(credential)
        existing = software_request_repository.get_by_id(request_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="software request not found"
            )
        if existing.status not in _RESOLVABLE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "invalid_status_transition",
                        "message": (
                            f"cannot resolve a request in status {existing.status!r} "
                            "(only pending/assessed)"
                        ),
                    }
                },
            )
        # Warn-but-allow gates on APPROVAL only: an unassessed (or auto-draft-
        # only) approval proceeds but is flagged in the response + audit log.
        gate_warnings: list[str] = []
        if new_status == "approved":
            if existing.assessment_json is None:
                gate_warnings.append(
                    "no assessment attached — dependencies/security/alternatives were not reviewed"
                )
            elif existing.assessment_draft:
                gate_warnings.append(
                    "assessment is an unreviewed auto-draft — ratify it before "
                    "approving to clear this warning"
                )
        req = software_request_repository.resolve(
            request_id,
            status=new_status,
            resolved_by=credential.maintainer_login or "maintainer",
            reason=reason,
        )
        assert req is not None
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=credential.maintainer_login,
            action=f"software_request.{'approve' if new_status == 'approved' else 'decline'}",
            resource_type="software_request",
            resource_id=request_id,
            payload={
                "title": req.title,
                "new_status": new_status,
                "reason": reason,
                "gate_override": bool(gate_warnings),
                "gate_warnings": gate_warnings,
            },
        )
        _publish(
            "requirement.resolved",
            {
                "request_id": request_id,
                "status": new_status,
                "resolved_by": credential.maintainer_login,
                "gate_override": bool(gate_warnings),
            },
        )
        response = _to_response(req, cls=SoftwareRequestResolveResponse)
        assert isinstance(response, SoftwareRequestResolveResponse)
        response.gate_override = bool(gate_warnings)
        response.gate_warnings = gate_warnings
        return response

    @router.post(
        "/software-requests/{request_id}/actions/approve",
        response_model=SoftwareRequestResolveResponse,
        status_code=status.HTTP_200_OK,
    )
    async def approve_software_request(
        request_id: str,
        body: ResolveRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestResolveResponse:
        return _resolve(request_id, "approved", body.reason, credential)

    @router.post(
        "/software-requests/{request_id}/actions/decline",
        response_model=SoftwareRequestResolveResponse,
        status_code=status.HTTP_200_OK,
    )
    async def decline_software_request(
        request_id: str,
        body: ResolveRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SoftwareRequestResolveResponse:
        return _resolve(request_id, "declined", body.reason, credential)

    return router
