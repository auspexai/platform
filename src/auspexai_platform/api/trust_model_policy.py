"""Trust-model-policy routes — /api/v0/trust-model-policy (firewall #1 flip, A2).

The maintainer's equal-trust FLIP switch. When DISABLED (default) trust accrues
only from agreement (current convergence-gradient model); when ENABLED, trust
accrues from process-attestation guarded by STRICT containment OR the reputation
floor, and divergent-but-guarded results earn divergence receipts
(a2_equal_trust_flip_design.md).

  GET  /api/v0/trust-model-policy   — current state (maintainer only)
  POST /api/v0/trust-model-policy   — set the flip (maintainer only; reason
                                      mandatory when enabling; audited)

Enabling is the firewall-#1 ACTIVATION — an explicit governance event gated on
the A7 5-condition gate (charter §8.4), never a silent default. The write is
audited (`trust_model_policy.update`); enabling returns a gate-warning.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.repositories import AuditRepository, TrustModelPolicyRepository

# Surfaced when a maintainer ENABLES the flip. The A7 gate is a governance
# procedure (not auto-enforced here), so the human attests it green — same
# posture as promotion_policy's firewall-conformance gate.
_GATE_WARNING = (
    "Enabling equal-trust is the firewall #1 activation — confirm the A7 "
    "5-condition gate is fully green (M3 served-weights, B1 STRICT containment, "
    "firewall #3 floor, firewall #5 instrumentation, conformance green across "
    "#1 AND #3) before flipping. This changes how trust accrues network-wide."
)


class TrustModelPolicyUpdate(BaseModel):
    equal_trust_enabled: bool = Field(description="enable the firewall #1 equal-trust flip")
    # Mandatory when enabling (enforced in the route); the audit row records state.
    reason: str | None = Field(default=None, max_length=500)


def _payload(policy, *, gate_warning: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "equal_trust_enabled": policy.equal_trust_enabled,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
        "updated_by": policy.updated_by,
        "update_reason": policy.update_reason,
    }
    if gate_warning:
        out["gate_warning"] = gate_warning
    return out


def build_router(
    credential_dep,
    policy_repository: TrustModelPolicyRepository,
    audit_repository: AuditRepository,
) -> APIRouter:
    router = APIRouter()

    @router.get("/trust-model-policy")
    async def get_policy(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        return _payload(policy_repository.get())

    @router.post("/trust-model-policy", status_code=status.HTTP_200_OK)
    async def set_policy(
        body: TrustModelPolicyUpdate,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        require_maintainer(credential)
        # Mandatory reason when ENABLING — the flip is a governance activation.
        if body.equal_trust_enabled and not (body.reason and body.reason.strip()):
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "reason_required",
                        "message": "enabling equal-trust requires a reason "
                        "(firewall #1 activation, A7-gated).",
                    }
                },
            )
        actor = credential.maintainer_login or "maintainer"
        policy = policy_repository.set(
            equal_trust_enabled=body.equal_trust_enabled,
            updated_by=actor,
            reason=body.reason,
        )
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=actor,
            actor_tenant_id=None,
            action="trust_model_policy.update",
            resource_type="trust_model_policy",
            resource_id="1",
            payload={
                "equal_trust_enabled": policy.equal_trust_enabled,
                "reason": body.reason,
            },
        )
        return _payload(
            policy,
            gate_warning=_GATE_WARNING if policy.equal_trust_enabled else None,
        )

    return router
