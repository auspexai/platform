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
