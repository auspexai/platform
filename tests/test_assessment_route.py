"""§9 #48 — POST /experiments/{id}/assessment (class-by-tier auto-approval).

End-to-end through the app: setup via the shared-db repo fixtures (account
tier, tenant linkage, a submitted experiment carrying a research_class), then
the maintainer-credentialed assessment call drives auto-approve vs review.
"""

from __future__ import annotations

import secrets

from fastapi.testclient import TestClient

from auspexai_platform.db.models import (
    ExperimentStatus,
    IdentityProvider,
    ResearchStanding,
    TrustTier,
)


def _pub() -> str:
    return secrets.token_hex(32)  # 64 hex chars, unique per tenant


def _submit_exp(manifest_repo, experiment_repo, *, tenant_id, label, research_class, **mover):
    mj = {
        "schema_version": "0.1",
        "tenant_id": tenant_id,
        "experiment_id": label,
        "research_class": research_class,
        "executor": {"package_sha256": "a" * 64},
        "models": [{"id": "gemma-3-1b-it-q4"}],
        "sensitive_content_flags": [],
    }
    mj.update(mover)
    m = manifest_repo.insert(tenant_id=tenant_id, manifest_json=mj, signature_json={})
    return experiment_repo.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=m.manifest_hash
    )


def _t2_tenant(account_repo, tenant_repo, tenant_id):
    acct = account_repo.create(
        account_id=f"acct-{tenant_id}",
        idp=IdentityProvider.GITHUB,
        idp_sub=f"gh-{tenant_id}",
        trust_tier=TrustTier.T2_TRUSTED,
    )
    # D9 Phase 4: a trusted tenant whose researcher is also ESTABLISHED (R2) — eligible
    # to BYOT, so its uncertified routine work auto-approves (T2 compute + R2 research).
    account_repo.set_research_standing(
        acct.account_id, new_standing=ResearchStanding.R2_ESTABLISHED
    )
    tenant_repo.register(tenant_id=tenant_id, maintainer_pubkey=_pub(), account_id=acct.account_id)


def _t1_tenant(tenant_repo, tenant_id):
    tenant_repo.register(tenant_id=tenant_id, maintainer_pubkey=_pub())  # no account ⇒ T1


def _hdr(maintainer_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {maintainer_token}"}


def _assess(client, exp_id, maintainer_token):
    return client.post(f"/api/v0/experiments/{exp_id}/assessment", headers=_hdr(maintainer_token))


# ── auto-approve ─────────────────────────────────────────────────────────────


def test_routine_trusted_auto_approves(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t2_tenant(account_repository, tenant_repository, "auto-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="auto-lab",
        label="auto-1",
        research_class="behavioral_drift",
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "auto" and body["status"] == "approved"
    assert body["tier"] == 2
    # the experiment row really transitioned + recorded provenance
    got = experiment_repository.get_by_id(exp.experiment_id)
    assert got.status == ExperimentStatus.APPROVED
    assert got.assessment_decision == "auto" and got.research_class == "behavioral_drift"


def test_byot_below_r2_routes_to_review(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    """D9 Phase 4 (§2, warn-but-allow): a T2-COMPUTE but R1-RESEARCH tenant is trusted
    to contribute compute, but not yet ESTABLISHED to bring its own (uncertified) code.
    Its routine work routes to REVIEW, not auto — the BYOT R2 gate. (§6 review then
    decides; promoting to R2 clears it.)"""
    acct = account_repository.create(
        account_id="acct-byot",
        idp=IdentityProvider.GITHUB,
        idp_sub="gh-byot",
        trust_tier=TrustTier.T2_TRUSTED,
    )  # research_standing left at the R1 default
    tenant_repository.register(
        tenant_id="byot-lab", maintainer_pubkey=_pub(), account_id=acct.account_id
    )
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="byot-lab",
        label="byot-1",
        research_class="behavioral_drift",
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.status_code == 200, r.text
    # T2 compute + routine class would normally auto-approve; R1 research holds it back.
    assert r.json()["decision"] == "review"
    assert experiment_repository.get_by_id(exp.experiment_id).status != ExperimentStatus.APPROVED


def test_byot_revoked_routes_to_review_even_at_r2(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    """AUD-13: a T2-compute, R2-research tenant is normally BYOT-eligible (its uncertified
    routine work auto-approves) — but an explicit BYOT revocation holds it back to REVIEW.
    Proves the byot_revoked flag is CONSULTED at the assessment gate, not merely stored
    (the declarative-enforcement guard); standing stays R2 throughout."""
    _t2_tenant(account_repository, tenant_repository, "revoked-lab")  # T2 compute + R2 research
    account_repository.set_byot_revoked("acct-revoked-lab", revoked=True)
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="revoked-lab",
        label="rev-1",
        research_class="behavioral_drift",
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "review"  # would be "auto" without the revocation
    assert experiment_repository.get_by_id(exp.experiment_id).status != ExperimentStatus.APPROVED
    # the revocation did NOT touch research-standing
    assert (
        account_repository.get_by_id("acct-revoked-lab").research_standing
        == ResearchStanding.R2_ESTABLISHED
    )


def test_elevated_never_auto_even_at_t2(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t2_tenant(account_repository, tenant_repository, "elev-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="elev-lab",
        label="elev-1",
        research_class="refusal_boundary_mapping",
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.json()["decision"] == "review"
    assert experiment_repository.get_by_id(exp.experiment_id).status == ExperimentStatus.SUBMITTED


def test_routine_sub_tier_reviews(
    client: TestClient,
    maintainer_token,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t1_tenant(tenant_repository, "t1-lab")  # no account ⇒ T1 < T2
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="t1-lab",
        label="t1-1",
        research_class="behavioral_drift",
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.json()["decision"] == "review" and r.json()["tier"] == 1
    assert experiment_repository.get_by_id(exp.experiment_id).status == ExperimentStatus.SUBMITTED


def test_routine_with_sensitive_flag_reviews(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t2_tenant(account_repository, tenant_repository, "sens-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="sens-lab",
        label="sens-1",
        research_class="behavioral_drift",
        sensitive_content_flags=["jailbreak"],
    )
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.json()["decision"] == "review"  # envelope fails despite routine+T2


# ── guards ───────────────────────────────────────────────────────────────────


def test_idempotent_returns_prior_assessment(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t2_tenant(account_repository, tenant_repository, "idem-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="idem-lab",
        label="idem-1",
        research_class="behavioral_drift",
    )
    first = _assess(client, exp.experiment_id, maintainer_token).json()
    second = _assess(client, exp.experiment_id, maintainer_token).json()
    assert first["decision"] == second["decision"] == "auto"
    assert first["assessed_at"] == second["assessed_at"]  # not re-decided


def test_non_submitted_is_409(
    client: TestClient,
    maintainer_token,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t1_tenant(tenant_repository, "term-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="term-lab",
        label="term-1",
        research_class="behavioral_drift",
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    r = _assess(client, exp.experiment_id, maintainer_token)
    assert r.status_code == 409
    assert r.json()["detail"]["error"]["code"] == "not_assessable"


def test_requires_maintainer(
    client: TestClient,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t1_tenant(tenant_repository, "auth-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="auth-lab",
        label="auth-1",
        research_class="behavioral_drift",
    )
    r = client.post(f"/api/v0/experiments/{exp.experiment_id}/assessment")  # no auth
    assert r.status_code in (401, 403)


# ── review/auto queues ───────────────────────────────────────────────────────


def test_assessment_queue_filter(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    _t2_tenant(account_repository, tenant_repository, "q-auto")
    _t1_tenant(tenant_repository, "q-rev")
    auto = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="q-auto",
        label="q-a",
        research_class="behavioral_drift",
    )
    rev = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="q-rev",
        label="q-r",
        research_class="behavioral_drift",
    )
    _assess(client, auto.experiment_id, maintainer_token)
    _assess(client, rev.experiment_id, maintainer_token)

    review_q = client.get("/api/v0/experiments?assessment=review", headers=_hdr(maintainer_token))
    ids = {e["experiment_id"] for e in review_q.json()["experiments"]}
    assert rev.experiment_id in ids and auto.experiment_id not in ids

    auto_q = client.get("/api/v0/experiments?assessment=auto", headers=_hdr(maintainer_token))
    ids = {e["experiment_id"] for e in auto_q.json()["experiments"]}
    assert auto.experiment_id in ids and rev.experiment_id not in ids


def test_assessment_provenance_on_list_and_detail(
    client: TestClient,
    maintainer_token,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
):
    """#48 inc 3: the assessment verdict + provenance surface on the experiment
    list (the console queues) and detail (the R-D lifecycle timeline)."""
    _t2_tenant(account_repository, tenant_repository, "prov-lab")
    exp = _submit_exp(
        manifest_repository,
        experiment_repository,
        tenant_id="prov-lab",
        label="prov-1",
        research_class="behavioral_drift",
    )
    _assess(client, exp.experiment_id, maintainer_token)

    rows = client.get("/api/v0/experiments", headers=_hdr(maintainer_token)).json()["experiments"]
    row = next(e for e in rows if e["experiment_id"] == exp.experiment_id)
    assert row["assessment_decision"] == "auto"
    assert row["research_class"] == "behavioral_drift"
    assert row["assessment_rationale"]
    assert row["assessment_tier"] == 2

    detail = client.get(
        f"/api/v0/experiments/{exp.experiment_id}", headers=_hdr(maintainer_token)
    ).json()
    assert detail["assessment_decision"] == "auto"
    assert detail["assessment_envelope"]  # the per-check list for the timeline/queue
