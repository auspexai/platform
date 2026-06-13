"""Assessment-policy routes — /api/v0/assessment-policy (§9 #48 inc-4).

The maintainer's auto-approval gate: the dashboard kill-switch for autonomous
experiment auto-approval. `decide()` reads this server-authoritatively, so the
gate — not "is the agent's timer running" — is the authority over whether routine
experiments clear without a click.

  GET  /api/v0/assessment-policy   — current gate (maintainer only)
  POST /api/v0/assessment-policy   — set the gate (maintainer only; reason required)

Enabling auto-approval is a governance action, so the write demands a reason and
is audited (`assessment_policy.update`) — same posture as every other trust action.
Default is DISABLED (migration 0031): autonomy is opt-in, never on by deploy.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import AssessmentPolicyRepository, AuditRepository


class PolicyUpdate(BaseModel):
    enabled: bool
    # Minimum account tier eligible for auto-approval when enabled. T2 or T3 only
    # — auto-approving T0/T1 tenants would defeat the trust gate.
    min_tier: int = Field(ge=2, le=3, default=2)
    # Optional free-text note. The audit row already records who/what/when/state;
    # a reason is accepted but not required (this is the maintainer's own policy
    # toggle, not an action against another party).
    reason: str | None = Field(default=None, max_length=500)


def _payload(policy) -> dict[str, Any]:
    return {
        "enabled": policy.enabled,
        "min_tier": policy.min_tier,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
        "updated_by": policy.updated_by,
        "update_reason": policy.update_reason,
    }


def build_router(
    credential_dep,
    policy_repository: AssessmentPolicyRepository,
    audit_repository: AuditRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/assessment-policy")
    async def get_policy(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        return _payload(policy_repository.get())

    @router.post("/assessment-policy", status_code=status.HTTP_200_OK)
    async def set_policy(
        body: PolicyUpdate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        actor = credential.maintainer_login or "maintainer"
        policy = policy_repository.set(
            enabled=body.enabled,
            min_tier=body.min_tier,
            updated_by=actor,
            reason=body.reason,
        )
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=actor,
            actor_tenant_id=None,
            action="assessment_policy.update",
            resource_type="assessment_policy",
            resource_id="1",
            payload={
                "enabled": policy.enabled,
                "min_tier": policy.min_tier,
                "reason": body.reason,
            },
        )
        return _payload(policy)

    return router
