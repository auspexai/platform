"""D9 Phase 4 increment 1 — the read-only research-standing model.

`research_standing` defaults to R1 on a bound account; `research_standing_summary`
RECOMPUTES (never stores) the distinct / completed / evidence-attested experiment
count and the R2-review eligibility from attested history. Eligibility earns the
human review — it does NOT promote (R1→R2 is a human act, increment 2).
"""

from __future__ import annotations

import pytest

from auspexai_platform.db.models import (
    ExperimentStatus,
    IdentityProvider,
    ResearchStanding,
)
from auspexai_platform.db.repositories.attestations import AttestationRepository


def _manifest(manifest_repository, tenant_id, body) -> str:
    """Insert a manifest; its content-addressed hash IS the 'config' identity."""
    return manifest_repository.insert(
        tenant_id=tenant_id, manifest_json=body, signature_json={}
    ).manifest_hash


def _experiment(
    experiment_repository,
    attestations,
    tenant_id,
    label,
    manifest_hash,
    *,
    status: ExperimentStatus = ExperimentStatus.COMPLETED,
    attest: bool = True,
):
    """A submitted→approved→<status> experiment, optionally with a final attestation."""
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=manifest_hash
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    experiment_repository.update_status(exp.experiment_id, status)
    if attest:
        attestations.insert(
            attestation_id=f"att-{label}",
            experiment_id=exp.experiment_id,
            tenant_id=tenant_id,
            tenant_experiment_label=label,
            merkle_root="0" * 64,
            algorithm="sha256",
            unit_count=1,
            cose_signed_blob=b"x",
            signing_key_pubkey_hex="ab" * 32,
            partial=False,
        )
    return exp


@pytest.fixture
def acct_tenant(account_repository, tenant_repository, registered_tenant):
    """An account bound to the registered tenant. Returns (account_id, tenant_id)."""
    _, binding = registered_tenant
    account_repository.create(account_id="acct-r", idp=IdentityProvider.GITHUB, idp_sub="gh-r")
    tenant_repository.set_account(binding.tenant_id, "acct-r")
    return "acct-r", binding.tenant_id


class TestResearchStandingModel:
    def test_account_defaults_to_r1(self, account_repository):
        account_repository.create(account_id="acct-x", idp=IdentityProvider.GITHUB, idp_sub="gh-x")
        assert (
            account_repository.get_by_id("acct-x").research_standing == ResearchStanding.R1_VERIFIED
        )

    def test_summary_empty_is_zero_and_ineligible(self, account_repository, acct_tenant):
        account_id, _ = acct_tenant
        s = account_repository.research_standing_summary(account_id)
        assert s.distinct_clean_completed_verified == 0
        assert s.current == ResearchStanding.R1_VERIFIED
        assert s.threshold == 3
        assert s.eligible_for_r2_review is False


class TestResearchStandingSummary:
    def test_counts_distinct_completed_attested_and_clears_threshold(
        self, account_repository, manifest_repository, experiment_repository, db, acct_tenant
    ):
        account_id, tenant_id = acct_tenant
        attestations = AttestationRepository(db)
        for i in range(3):  # 3 DISTINCT configs, each completed + attested
            mh = _manifest(manifest_repository, tenant_id, {"experiment_id": f"e{i}", "n": i})
            _experiment(experiment_repository, attestations, tenant_id, f"e{i}", mh)
        s = account_repository.research_standing_summary(account_id)
        assert s.distinct_clean_completed_verified == 3
        assert s.eligible_for_r2_review is True  # R1 + count>=3 → eligible for the REVIEW

    def test_distinct_dedupes_reruns_of_same_config(
        self, account_repository, manifest_repository, experiment_repository, db, acct_tenant
    ):
        account_id, tenant_id = acct_tenant
        attestations = AttestationRepository(db)
        mh = _manifest(manifest_repository, tenant_id, {"experiment_id": "same", "n": 0})
        # two completed+attested experiments, SAME manifest_hash (a trivial rerun)
        _experiment(experiment_repository, attestations, tenant_id, "run-a", mh)
        _experiment(experiment_repository, attestations, tenant_id, "run-b", mh)
        s = account_repository.research_standing_summary(account_id)
        assert s.distinct_clean_completed_verified == 1  # reruns don't ladder you up

    def test_excludes_incomplete_and_unattested(
        self, account_repository, manifest_repository, experiment_repository, db, acct_tenant
    ):
        account_id, tenant_id = acct_tenant
        attestations = AttestationRepository(db)
        # completed but NO attestation → excluded (no verified evidence)
        mh1 = _manifest(manifest_repository, tenant_id, {"experiment_id": "noatt"})
        _experiment(experiment_repository, attestations, tenant_id, "noatt", mh1, attest=False)
        # attested but ABORTED → excluded (not completed)
        mh2 = _manifest(manifest_repository, tenant_id, {"experiment_id": "ab"})
        _experiment(
            experiment_repository,
            attestations,
            tenant_id,
            "ab",
            mh2,
            status=ExperimentStatus.ABORTED,
        )
        assert (
            account_repository.research_standing_summary(
                account_id
            ).distinct_clean_completed_verified
            == 0
        )

    def test_eligibility_requires_current_r1(
        self, account_repository, manifest_repository, experiment_repository, db, acct_tenant
    ):
        account_id, tenant_id = acct_tenant
        attestations = AttestationRepository(db)
        for i in range(3):
            mh = _manifest(manifest_repository, tenant_id, {"experiment_id": f"e{i}", "n": i})
            _experiment(experiment_repository, attestations, tenant_id, f"e{i}", mh)
        # Simulate a prior human promotion to R2 (increment 2 builds the real action).
        with db.transaction() as cur:
            cur.execute(
                "UPDATE accounts SET research_standing = 2 WHERE account_id = ?", (account_id,)
            )
        s = account_repository.research_standing_summary(account_id)
        assert s.current == ResearchStanding.R2_ESTABLISHED
        # Already R2 → the R1→R2 review gate no longer applies.
        assert s.eligible_for_r2_review is False


class TestResearchStandingRoute:
    """Increment 2 — the promotion action (human, audited, gate-warned, never auto)
    + the reviewer dossier (D8)."""

    @staticmethod
    def _h(maintainer_token):
        return {"Authorization": f"Bearer {maintainer_token}"}

    def _earn(self, manifest_repository, experiment_repository, db, tenant_id, n=3):
        attestations = AttestationRepository(db)
        for i in range(n):
            mh = _manifest(manifest_repository, tenant_id, {"experiment_id": f"e{i}", "n": i})
            _experiment(experiment_repository, attestations, tenant_id, f"e{i}", mh)

    def test_dossier_returns_summary_and_history(
        self, client, maintainer_token, manifest_repository, experiment_repository, db, acct_tenant
    ):
        account_id, tenant_id = acct_tenant
        self._earn(manifest_repository, experiment_repository, db, tenant_id, n=1)
        r = client.get(
            f"/api/v0/accounts/{account_id}/research-standing", headers=self._h(maintainer_token)
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["current_name"] == "R1_VERIFIED"
        assert body["distinct_clean_completed_verified"] == 1
        assert len(body["experiments"]) == 1 and body["experiments"][0]["experiment_id"]

    def test_promote_eligible_no_warning(
        self,
        client,
        maintainer_token,
        account_repository,
        manifest_repository,
        experiment_repository,
        db,
        acct_tenant,
    ):
        account_id, tenant_id = acct_tenant
        self._earn(manifest_repository, experiment_repository, db, tenant_id, n=3)
        r = client.post(
            f"/api/v0/accounts/{account_id}/actions/promote-research-standing",
            headers=self._h(maintainer_token),
            json={"target": 2, "reason": "3 clean drift studies, ethics-reviewed"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["research_standing"] == 2
        assert r.json()["gate_override"] is False and r.json()["gate_warnings"] == []
        assert (
            account_repository.get_by_id(account_id).research_standing
            == ResearchStanding.R2_ESTABLISHED
        )

    def test_promote_below_floor_warns_but_allows(
        self, client, maintainer_token, account_repository, acct_tenant
    ):
        account_id, _ = acct_tenant  # no experiments → below the competence floor
        r = client.post(
            f"/api/v0/accounts/{account_id}/actions/promote-research-standing",
            headers=self._h(maintainer_token),
            json={"target": 2, "reason": "trusted colleague, fast-tracking"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["research_standing"] == 2  # warn-but-ALLOW (mandatory reason recorded)
        assert r.json()["gate_override"] is True
        assert any("threshold not met" in w for w in r.json()["gate_warnings"])

    def test_promote_must_be_one_step(self, client, maintainer_token, acct_tenant):
        account_id, _ = acct_tenant  # current R1
        r = client.post(
            f"/api/v0/accounts/{account_id}/actions/promote-research-standing",
            headers=self._h(maintainer_token),
            json={"target": 3, "reason": "skip R2"},  # R1→R3 is not one step
        )
        assert r.status_code == 422

    def test_promote_r2_to_r3_warns_out_of_band(self, client, maintainer_token, acct_tenant, db):
        account_id, _ = acct_tenant
        with db.transaction() as cur:
            cur.execute(
                "UPDATE accounts SET research_standing = 2 WHERE account_id = ?", (account_id,)
            )
        r = client.post(
            f"/api/v0/accounts/{account_id}/actions/promote-research-standing",
            headers=self._h(maintainer_token),
            json={"target": 3, "reason": "extended clean R2 record, vetted"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["research_standing"] == 3
        # R3 is a trust judgment (arc §3.3) — surfaces the out-of-band reminder.
        assert any("out-of-band" in w for w in r.json()["gate_warnings"])

    def test_dossier_requires_maintainer(self, client, acct_tenant):
        account_id, _ = acct_tenant
        r = client.get(f"/api/v0/accounts/{account_id}/research-standing")  # no auth
        assert r.status_code in (401, 403)
