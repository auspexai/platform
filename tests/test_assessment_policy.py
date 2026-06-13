"""§9 #48 inc-4 — the runtime auto-approval gate (assessment_policy).

Covers the storage repo, the `decide()` gate parameter, the maintainer GET/POST
endpoint, and the end-to-end consequence: with the gate OFF, an experiment that
would otherwise auto-approve routes to human review instead.
"""

from __future__ import annotations

import secrets

from auspexai_platform.assessment import EnvelopeCheck, EnvelopeResult, decide
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AssessmentPolicyRepository

# ── storage repo ─────────────────────────────────────────────────────────────


def test_policy_defaults_disabled(db):
    pol = AssessmentPolicyRepository(db).get()
    assert pol.enabled is False
    assert pol.min_tier == 2


def test_policy_set_get_roundtrip(db):
    repo = AssessmentPolicyRepository(db)
    pol = repo.set(enabled=True, min_tier=3, updated_by="alice", reason="enable T3")
    assert pol.enabled is True and pol.min_tier == 3
    assert pol.updated_by == "alice" and pol.update_reason == "enable T3"
    again = repo.get()
    assert again.enabled is True and again.min_tier == 3 and again.updated_at is not None


# ── decide() gate ────────────────────────────────────────────────────────────


def _passing_envelope() -> EnvelopeResult:
    return EnvelopeResult([EnvelopeCheck("x", True)])


def test_decide_gate_off_forces_review():
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=2,
        envelope=_passing_envelope(),
        auto_approval_enabled=False,
    )
    assert v.decision == "review"
    assert "gate is off" in v.rationale


def test_decide_gate_on_routine_t2_auto():
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=2,
        envelope=_passing_envelope(),
        auto_approval_enabled=True,
    )
    assert v.decision == "auto"


def test_decide_gate_on_min_tier_t3_blocks_t2():
    v = decide(
        research_class="behavioral_drift",
        tenant_tier=2,
        envelope=_passing_envelope(),
        auto_tier=3,
        auto_approval_enabled=True,
    )
    assert v.decision == "review"
    assert "below T3" in v.rationale


# ── endpoint ─────────────────────────────────────────────────────────────────


def _pub() -> str:
    return secrets.token_hex(32)


def _hdr(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def _t2_tenant(account_repository, tenant_repository, tenant_id):
    acct = account_repository.create(
        account_id=f"acct-{tenant_id}",
        idp=IdentityProvider.GITHUB,
        idp_sub=f"gh-{tenant_id}",
        trust_tier=TrustTier.T2_TRUSTED,
    )
    tenant_repository.register(
        tenant_id=tenant_id, maintainer_pubkey=_pub(), account_id=acct.account_id
    )


def _submit_exp(manifest_repository, experiment_repository, tenant_id, label, research_class):
    mj = {
        "schema_version": "0.1",
        "tenant_id": tenant_id,
        "experiment_id": label,
        "research_class": research_class,
        "executor": {"package_sha256": "a" * 64},
        "models": [{"id": "gemma-3-1b-it-q4"}],
        "sensitive_content_flags": [],
    }
    m = manifest_repository.insert(tenant_id=tenant_id, manifest_json=mj, signature_json={})
    return experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=m.manifest_hash
    )


def test_get_policy_returns_state(client, maintainer_token):
    r = client.get("/api/v0/assessment-policy", headers=_hdr(maintainer_token))
    assert r.status_code == 200
    # The shared client fixture turns the gate ON for the suite baseline.
    assert r.json()["enabled"] is True


def test_get_policy_requires_maintainer(client):
    assert client.get("/api/v0/assessment-policy").status_code in (401, 403)


def test_post_policy_sets_and_persists(client, maintainer_token, db):
    r = client.post(
        "/api/v0/assessment-policy",
        headers=_hdr(maintainer_token),
        json={"enabled": False, "min_tier": 2, "reason": "pause autonomy"},
    )
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert AssessmentPolicyRepository(db).get().enabled is False


def test_post_policy_requires_reason(client, maintainer_token):
    r = client.post(
        "/api/v0/assessment-policy",
        headers=_hdr(maintainer_token),
        json={"enabled": True, "min_tier": 2},
    )
    assert r.status_code == 422


def test_post_policy_rejects_sub_t2_min_tier(client, maintainer_token):
    r = client.post(
        "/api/v0/assessment-policy",
        headers=_hdr(maintainer_token),
        json={"enabled": True, "min_tier": 1, "reason": "this should be rejected"},
    )
    assert r.status_code == 422


# ── end-to-end: the gate governs the live decision ──────────────────────────


def test_gate_off_routes_would_be_auto_to_review(
    client,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    client.post(
        "/api/v0/assessment-policy",
        headers=_hdr(maintainer_token),
        json={"enabled": False, "min_tier": 2, "reason": "off for test"},
    )
    _t2_tenant(account_repository, tenant_repository, "tenant-off")
    exp = _submit_exp(
        manifest_repository, experiment_repository, "tenant-off", "lbl-off", "behavioral_drift"
    )
    r = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/assessment", headers=_hdr(maintainer_token)
    )
    assert r.status_code == 200
    body = r.json()
    # Routine + T2 + clean envelope → would be auto, but the gate is off.
    assert body["decision"] == "review"
    assert body["status"] == "submitted"


def test_gate_on_min_tier_t3_blocks_t2_experiment(
    client,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    client.post(
        "/api/v0/assessment-policy",
        headers=_hdr(maintainer_token),
        json={"enabled": True, "min_tier": 3, "reason": "raise the bar to T3"},
    )
    _t2_tenant(account_repository, tenant_repository, "tenant-t2")
    exp = _submit_exp(
        manifest_repository, experiment_repository, "tenant-t2", "lbl-t2", "behavioral_drift"
    )
    r = client.post(
        f"/api/v0/experiments/{exp.experiment_id}/assessment", headers=_hdr(maintainer_token)
    )
    assert r.json()["decision"] == "review"
