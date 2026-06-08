"""R4 (§6.2.2 anti-Sybil): the vouch gate's distinct-tenant receipt summary.

`account_receipt_summary` must count DISTINCT TENANTS (not experiments) — the
placeholder in compute_receipt_stats uses distinct experiments, which would let
an attacker satisfy "≥2 tenants" with ≥2 experiments under ONE tenant.
"""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    TenantRepository,
    WorkerRepository,
)


def _make_experiment(manifests, experiments, *, tenant_id, label):
    """Insert a (distinct) manifest then an experiment referencing its hash —
    experiments.manifest_hash FKs to manifests."""
    m = manifests.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label, "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    return experiments.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=m.manifest_hash
    )


def test_account_receipt_summary_counts_distinct_tenants_not_experiments(db: Database):
    accounts = AccountRepository(db)
    tenants = TenantRepository(db)
    workers = WorkerRepository(db)
    experiments = ExperimentRepository(db)
    manifests = ManifestRepository(db)
    receipts = ReceiptIndexRepository(db)

    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    tenants.register(tenant_id="tenant-b", maintainer_pubkey="bb" * 32)
    workers.enroll(worker_id="wkr-1", pubkey_hex="cc" * 32)
    workers.bind_account("wkr-1", account_id="acct-1", trust_tier=TrustTier.T2_TRUSTED)

    # THREE experiments but only TWO tenants (two under tenant-a) — so distinct
    # experiments (3) != distinct tenants (2). The placeholder would say 3.
    exp_a1 = _make_experiment(manifests, experiments, tenant_id="tenant-a", label="exp-a1")
    exp_a2 = _make_experiment(manifests, experiments, tenant_id="tenant-a", label="exp-a2")
    exp_b1 = _make_experiment(manifests, experiments, tenant_id="tenant-b", label="exp-b1")
    for i, exp in enumerate([exp_a1, exp_a2, exp_b1]):
        receipts.record(
            receipt_id=f"rcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id="wkr-1",
            worker_pubkey="cc" * 32,
            result_id=f"res-{i}",
        )

    total, distinct_tenants = receipts.account_receipt_summary("acct-1")
    assert total == 3
    assert distinct_tenants == 2  # 3 experiments, 2 tenants — counts tenants


def test_account_receipt_summary_zero_for_unknown_account(db: Database):
    assert ReceiptIndexRepository(db).account_receipt_summary("acct-none") == (0, 0)
