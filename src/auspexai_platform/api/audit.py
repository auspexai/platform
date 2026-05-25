"""Audit-log endpoints — /api/v0/audit.

  GET /api/v0/audit — maintainer-only filtered list of audit entries.

Provides the operator console's audit-log view with filtering by action,
actor class, resource type, and time. Results are sorted most-recent-first
(id DESC) and capped at 500 entries per request.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import AuditRepository


def build_router(credential_dep, audit_repository: AuditRepository) -> APIRouter:
    """Build the /audit router bound to a credential dependency and repository."""

    router = APIRouter()

    @router.get("/audit")
    async def list_audit(
        action: str | None = Query(default=None, description="Filter by action (exact match)"),
        actor_class: str | None = Query(default=None, description="Filter by actor class"),
        resource_type: str | None = Query(default=None, description="Filter by resource type"),
        since: str | None = Query(
            default=None,
            description="ISO 8601 datetime; return entries after this time",
        ),
        limit: int = Query(default=50, ge=1, le=500, description="Max entries to return"),
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict:
        require_maintainer(credential)
        entries, total = audit_repository.list(
            action=action,
            actor_class=actor_class,
            resource_type=resource_type,
            since=since,
            limit=limit,
        )
        return {
            "entries": [
                {
                    "id": e.id,
                    "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                    "actor_class": str(e.actor_class),
                    "actor_identifier": e.actor_identifier,
                    "actor_tenant_id": e.actor_tenant_id,
                    "action": e.action,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "payload": e.payload,
                }
                for e in entries
            ],
            "total": total,
        }

    return router
