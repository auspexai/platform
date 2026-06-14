"""Promotion-policy routes — /api/v0/promotion-policy (§6.2 promotion mode).

The maintainer's manual / auto switch for account tier escalation (T1->T2). In
`auto_with_override` the coordinator auto-promotes when all automated gates plus
the identity gate pass (the maintainer can still block/reverse/hand-promote); in
`manual` nothing auto-promotes and qualifying accounts wait in the promotion
queue for a click.

  GET  /api/v0/promotion-policy   — current mode (maintainer only)
  POST /api/v0/promotion-policy   — set the mode (maintainer only; reason audited)

Only the MODE is tunable here; the numeric gate thresholds are versioned config.
Switching mode is a governance action, so the write is audited
(`promotion_policy.update`) — same posture as every other trust action. Default
is `manual` (migration 0032): human-in-the-loop is the ratified default
(governance charter §6 decision 3); relaxing to `auto_with_override` is gated on
the firewall-conformance check (charter §8.4).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import AuditRepository, PromotionPolicyRepository
from auspexai_platform.db.repositories.promotion_policy import PROMOTION_MODES


class PromotionPolicyUpdate(BaseModel):
    # 'manual' | 'auto_with_override' — validated against the repo's mode set.
    t1_t2_mode: str = Field(description="manual | auto_with_override")
    # Optional free-text note; the audit row records who/what/when/state.
    reason: str | None = Field(default=None, max_length=500)


def _payload(policy) -> dict[str, Any]:
    return {
        "t1_t2_mode": policy.t1_t2_mode,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
        "updated_by": policy.updated_by,
        "update_reason": policy.update_reason,
    }


def build_router(
    credential_dep,
    policy_repository: PromotionPolicyRepository,
    audit_repository: AuditRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/promotion-policy")
    async def get_policy(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        return _payload(policy_repository.get())

    @router.post("/promotion-policy", status_code=status.HTTP_200_OK)
    async def set_policy(
        body: PromotionPolicyUpdate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        if body.t1_t2_mode not in PROMOTION_MODES:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "invalid_promotion_mode",
                        "message": f"invalid t1_t2_mode {body.t1_t2_mode!r}; "
                        f"expected one of {sorted(PROMOTION_MODES)}",
                    }
                },
            )
        actor = credential.maintainer_login or "maintainer"
        policy = policy_repository.set(
            t1_t2_mode=body.t1_t2_mode,
            updated_by=actor,
            reason=body.reason,
        )
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=actor,
            actor_tenant_id=None,
            action="promotion_policy.update",
            resource_type="promotion_policy",
            resource_id="1",
            payload={"t1_t2_mode": policy.t1_t2_mode, "reason": body.reason},
        )
        return _payload(policy)

    return router
