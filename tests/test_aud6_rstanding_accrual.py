"""AUD-6 (A9 audit): research-standing accrues to the RUNNER (submitted_by_account_id),
not the tenant OWNER.

Before the fix, `research_standing_summary`/`history` keyed on tenant ownership
(`tenants.account_id`), so a connected Tier-1 researcher's runs under a PUBLIC
tenant accrued ZERO toward their R2 review and instead inflated the public-tenant
owner's count. The fix keys on the runner, with a NULL-submitter fallback to
ownership for pre-0049 rows (no regression for existing Tier-2 owners).
"""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import ExperimentStatus, IdentityProvider
from auspexai_platform.db.repositories import (
    AccountRepository,
    ExperimentRepository,
    ManifestRepository,
    TenantRepository,
)
from auspexai_platform.db.repositories.attestations import AttestationRepository


def _attested_completed(experiments, attestations, *, tenant_id, label, manifest_hash, submitter):
    exp = experiments.create(
        tenant_id=tenant_id,
        tenant_experiment_label=label,
        manifest_hash=manifest_hash,
        submitted_by_account_id=submitter,
    )
    experiments.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    experiments.update_status(exp.experiment_id, ExperimentStatus.COMPLETED)
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


def _repos(db):
    return (
        AccountRepository(db),
        TenantRepository(db),
        ManifestRepository(db),
        ExperimentRepository(db),
        AttestationRepository(db),
    )


def test_tier1_run_accrues_to_runner_not_tenant_owner(db: Database):
    accounts, tenants, manifests, experiments, attestations = _repos(db)
    accounts.create(account_id="acct-owner", idp=IdentityProvider.GITHUB, idp_sub="gh-owner")
    accounts.create(account_id="acct-runner", idp=IdentityProvider.GITHUB, idp_sub="gh-runner")
    tenants.register(tenant_id="pub-tenant", maintainer_pubkey="aa" * 32)
    tenants.set_account("pub-tenant", "acct-owner")
    mh = manifests.insert(
        tenant_id="pub-tenant", manifest_json={"models": []}, signature_json={}
    ).manifest_hash
    # acct-runner (Tier-1 connected researcher) runs the public tenant's certified starter.
    _attested_completed(
        experiments,
        attestations,
        tenant_id="pub-tenant",
        label="run-1",
        manifest_hash=mh,
        submitter="acct-runner",
    )

    # Credit goes to the RUNNER.
    assert accounts.research_standing_summary("acct-runner").distinct_clean_completed_verified == 1
    assert len(accounts.research_standing_history("acct-runner")) == 1
    # NOT the tenant owner (the inflation fix).
    assert accounts.research_standing_summary("acct-owner").distinct_clean_completed_verified == 0
    assert accounts.research_standing_history("acct-owner") == []


def test_legacy_null_submitter_still_credits_tenant_owner(db: Database):
    """Backward-compat: a pre-0049 experiment (NULL submitter) under an owned tenant
    still counts for the owner via the fallback clause — no regression."""
    accounts, tenants, manifests, experiments, attestations = _repos(db)
    accounts.create(account_id="acct-owner", idp=IdentityProvider.GITHUB, idp_sub="gh-owner")
    tenants.register(tenant_id="own-tenant", maintainer_pubkey="bb" * 32)
    tenants.set_account("own-tenant", "acct-owner")
    mh = manifests.insert(
        tenant_id="own-tenant", manifest_json={"models": []}, signature_json={}
    ).manifest_hash
    _attested_completed(
        experiments,
        attestations,
        tenant_id="own-tenant",
        label="legacy-1",
        manifest_hash=mh,
        submitter=None,
    )
    assert accounts.research_standing_summary("acct-owner").distinct_clean_completed_verified == 1
