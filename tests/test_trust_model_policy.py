"""Firewall #1 equal-trust FLIP toggle (trust_model_policy) — the maintainer's
A2 activation switch. Covers the storage repo and the maintainer GET/POST
endpoint (default OFF, mandatory reason on enable, gate-warning, audit).

The behavioral consequence (ON changes how trust accrues) is exercised against
the accrual path in the divergence-receipt / equal-trust-accrual tests.
"""

from __future__ import annotations

from auspexai_platform.db.repositories import TrustModelPolicyRepository

# ── storage repo ─────────────────────────────────────────────────────────────


def test_policy_defaults_disabled(db):
    # The flip is OFF until an explicit, A7-gated activation.
    pol = TrustModelPolicyRepository(db).get()
    assert pol.equal_trust_enabled is False


def test_policy_set_get_roundtrip(db):
    repo = TrustModelPolicyRepository(db)
    pol = repo.set(equal_trust_enabled=True, updated_by="alice", reason="A7 gate green")
    assert pol.equal_trust_enabled is True
    assert pol.updated_by == "alice" and pol.update_reason == "A7 gate green"
    again = repo.get()
    assert again.equal_trust_enabled is True and again.updated_at is not None
    # And back off.
    off = repo.set(equal_trust_enabled=False, updated_by="alice", reason="rollback")
    assert off.equal_trust_enabled is False


# ── endpoint ─────────────────────────────────────────────────────────────────


def _hdr(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def test_get_policy_returns_default_disabled(client, maintainer_token):
    r = client.get("/api/v0/trust-model-policy", headers=_hdr(maintainer_token))
    assert r.status_code == 200
    assert r.json()["equal_trust_enabled"] is False


def test_get_policy_requires_maintainer(client):
    assert client.get("/api/v0/trust-model-policy").status_code in (401, 403)


def test_post_enable_with_reason_returns_gate_warning_and_persists(client, maintainer_token, db):
    r = client.post(
        "/api/v0/trust-model-policy",
        headers=_hdr(maintainer_token),
        json={"equal_trust_enabled": True, "reason": "A7 5-condition gate confirmed green"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["equal_trust_enabled"] is True
    assert "gate_warning" in body and "firewall #1 activation" in body["gate_warning"]
    assert TrustModelPolicyRepository(db).get().equal_trust_enabled is True


def test_post_enable_requires_reason(client, maintainer_token, db):
    r = client.post(
        "/api/v0/trust-model-policy",
        headers=_hdr(maintainer_token),
        json={"equal_trust_enabled": True},  # no reason
    )
    assert r.status_code == 422
    assert r.json()["detail"]["error"]["code"] == "reason_required"
    # Must NOT have flipped.
    assert TrustModelPolicyRepository(db).get().equal_trust_enabled is False


def test_post_disable_reason_optional_and_no_gate_warning(client, maintainer_token):
    r = client.post(
        "/api/v0/trust-model-policy",
        headers=_hdr(maintainer_token),
        json={"equal_trust_enabled": False},  # disabling needs no reason
    )
    assert r.status_code == 200
    assert r.json()["equal_trust_enabled"] is False
    assert "gate_warning" not in r.json()


def test_post_flip_is_audited(client, maintainer_token, db):
    client.post(
        "/api/v0/trust-model-policy",
        headers=_hdr(maintainer_token),
        json={"equal_trust_enabled": True, "reason": "gate green"},
    )
    rows = db.execute("SELECT action FROM audit_log WHERE action = 'trust_model_policy.update'")
    assert len(rows) >= 1


def test_post_policy_requires_maintainer(client):
    assert client.post(
        "/api/v0/trust-model-policy", json={"equal_trust_enabled": False}
    ).status_code in (401, 403)
