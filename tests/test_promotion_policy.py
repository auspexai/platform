"""§6.2 promotion-mode toggle (promotion_policy) — the maintainer's manual / auto
switch for T1->T2 account escalation.

Covers the storage repo and the maintainer GET/POST endpoint. The behavioral
consequence (manual mode halts auto-promotion) is exercised against the full gate
in test_eligibility_m7f.py, where the receipt/identity setup lives.
"""

from __future__ import annotations

import pytest

from auspexai_platform.db.repositories import PromotionPolicyRepository
from auspexai_platform.db.repositories.promotion_policy import (
    PROMOTION_MODE_AUTO,
    PROMOTION_MODE_MANUAL,
)

# ── storage repo ─────────────────────────────────────────────────────────────


def test_policy_defaults_manual(db):
    # Human-in-the-loop is the ratified default (charter §6 decision 3).
    pol = PromotionPolicyRepository(db).get()
    assert pol.t1_t2_mode == PROMOTION_MODE_MANUAL
    assert pol.auto_promote_t1_t2 is False


def test_policy_set_get_roundtrip(db):
    repo = PromotionPolicyRepository(db)
    pol = repo.set(t1_t2_mode=PROMOTION_MODE_MANUAL, updated_by="alice", reason="pause autos")
    assert pol.t1_t2_mode == PROMOTION_MODE_MANUAL
    assert pol.auto_promote_t1_t2 is False
    assert pol.updated_by == "alice" and pol.update_reason == "pause autos"
    again = repo.get()
    assert again.t1_t2_mode == PROMOTION_MODE_MANUAL and again.updated_at is not None


def test_policy_set_rejects_unknown_mode(db):
    with pytest.raises(ValueError):
        PromotionPolicyRepository(db).set(t1_t2_mode="bogus", updated_by="x")


# ── endpoint ─────────────────────────────────────────────────────────────────


def _hdr(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def test_get_policy_returns_default_manual(client, maintainer_token):
    r = client.get("/api/v0/promotion-policy", headers=_hdr(maintainer_token))
    assert r.status_code == 200
    assert r.json()["t1_t2_mode"] == PROMOTION_MODE_MANUAL


def test_get_policy_requires_maintainer(client):
    assert client.get("/api/v0/promotion-policy").status_code in (401, 403)


def test_post_policy_sets_and_persists(client, maintainer_token, db):
    r = client.post(
        "/api/v0/promotion-policy",
        headers=_hdr(maintainer_token),
        json={"t1_t2_mode": PROMOTION_MODE_MANUAL, "reason": "manual review for now"},
    )
    assert r.status_code == 200 and r.json()["t1_t2_mode"] == PROMOTION_MODE_MANUAL
    assert PromotionPolicyRepository(db).get().t1_t2_mode == PROMOTION_MODE_MANUAL


def test_post_policy_reason_optional(client, maintainer_token):
    r = client.post(
        "/api/v0/promotion-policy",
        headers=_hdr(maintainer_token),
        json={"t1_t2_mode": PROMOTION_MODE_AUTO},  # no reason
    )
    assert r.status_code == 200
    assert r.json()["update_reason"] is None


def test_post_policy_rejects_unknown_mode(client, maintainer_token):
    r = client.post(
        "/api/v0/promotion-policy",
        headers=_hdr(maintainer_token),
        json={"t1_t2_mode": "halfway", "reason": "nope"},
    )
    assert r.status_code == 422


def test_post_policy_requires_maintainer(client):
    assert client.post(
        "/api/v0/promotion-policy", json={"t1_t2_mode": PROMOTION_MODE_MANUAL}
    ).status_code in (401, 403)
