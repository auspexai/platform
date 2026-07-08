"""A4 firewall #3 independence floor — account-weighted trust accrual.

The trust metric the T2/vouch gates consult counts DISTINCT WORK UNITS an account
corroborated, not raw receipts — so an operator's N workers under ONE account
can't farm the threshold by redundantly covering the same units (F3-a), and a
single controller's leverage is K accounts, not M pubkeys (F3-c). Completion /
consensus stays per-pubkey (a4_independence_floor_design.md) and is not exercised
here; this is the trust dimension. `COALESCE(unit_id, receipt_id)` keeps pre-0035
rows (no unit_id) at one-each, so the dedup engages only on real issuance.
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


def _exp(manifests, experiments, *, tenant_id, label):
    m = manifests.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label, "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    return experiments.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=m.manifest_hash
    )


def _repos(db):
    return (
        AccountRepository(db),
        TenantRepository(db),
        WorkerRepository(db),
        ExperimentRepository(db),
        ManifestRepository(db),
        ReceiptIndexRepository(db),
    )


def test_within_account_same_unit_collapses_to_one(db: Database):
    """F3-a: 3 workers (3 pubkeys) of ONE account all corroborate the SAME unit →
    1 unit of trust, not 3. The raw receipt total (display) is still 3."""
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")

    for i in range(3):
        pk = f"{i:02x}" * 32
        workers.enroll(worker_id=f"wkr-{i}", pubkey_hex=pk)
        workers.bind_account(f"wkr-{i}", account_id="acct-1", trust_tier=TrustTier.T1_AUTHENTICATED)
        receipts.record(
            receipt_id=f"rcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id=f"wkr-{i}",
            worker_pubkey=pk,
            result_id=f"res-{i}",
            unit_id="u-1",  # SAME unit — must not multiply trust
        )

    units, tenant_count = receipts.account_corroboration_summary("acct-1")
    assert units == 1, "3 workers on the same unit must earn 1 unit of trust, not 3"
    assert tenant_count == 1
    # Display total is untouched — raw receipts still count 3.
    assert receipts.account_receipt_summary("acct-1")[0] == 3


def test_distinct_units_count_as_breadth(db: Database):
    """One worker corroborating 3 DISTINCT units = 3 trust — breadth still counts."""
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")
    workers.enroll(worker_id="wkr-1", pubkey_hex="cc" * 32)
    workers.bind_account("wkr-1", account_id="acct-1", trust_tier=TrustTier.T1_AUTHENTICATED)

    for i in range(3):
        receipts.record(
            receipt_id=f"rcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id="wkr-1",
            worker_pubkey="cc" * 32,
            result_id=f"res-{i}",
            unit_id=f"u-{i}",  # DISTINCT units
        )

    assert receipts.account_corroboration_summary("acct-1")[0] == 3


def test_null_unit_id_preserves_one_each(db: Database):
    """Backward-compat: pre-0035 rows (no unit_id) COALESCE to receipt_id → one
    each, so existing data + tests that don't set unit_id are unaffected."""
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")
    workers.enroll(worker_id="wkr-1", pubkey_hex="cc" * 32)
    workers.bind_account("wkr-1", account_id="acct-1", trust_tier=TrustTier.T1_AUTHENTICATED)

    for i in range(3):
        receipts.record(
            receipt_id=f"rcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id="wkr-1",
            worker_pubkey="cc" * 32,
            result_id=f"res-{i}",
            # unit_id omitted (NULL) — the pre-0035 case
        )

    # No dedup without unit_id → counts one-each, matching the raw total.
    assert receipts.account_corroboration_summary("acct-1")[0] == 3
    assert receipts.account_receipt_summary("acct-1")[0] == 3


def test_one_controller_many_pubkeys_is_bounded_per_account(db: Database):
    """F3-c: one controller, M=4 pubkeys across K=2 accounts, all on the SAME unit.
    Each account collapses to 1 (not 2); the controller's leverage is K accounts,
    not M pubkeys. (The K-account residual is bounded by the T2 gates, by design.)"""
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")

    w = 0
    for acct in ("acct-1", "acct-2"):
        accounts.create(account_id=acct, idp=IdentityProvider.GITHUB, idp_sub=str(100 + w))
        for _ in range(2):  # 2 pubkeys per account
            pk = f"{w:02x}" * 32
            workers.enroll(worker_id=f"wkr-{w}", pubkey_hex=pk)
            workers.bind_account(f"wkr-{w}", account_id=acct, trust_tier=TrustTier.T1_AUTHENTICATED)
            receipts.record(
                receipt_id=f"rcpt-{w}",
                experiment_id=exp.experiment_id,
                worker_id=f"wkr-{w}",
                worker_pubkey=pk,
                result_id=f"res-{w}",
                unit_id="u-1",  # all on the same unit
            )
            w += 1

    assert receipts.account_corroboration_summary("acct-1")[0] == 1
    assert receipts.account_corroboration_summary("acct-2")[0] == 1


def test_corroboration_summary_zero_for_unknown_account(db: Database):
    assert ReceiptIndexRepository(db).account_corroboration_summary("acct-none") == (0, 0)


def test_same_unit_id_across_experiments_counts_separately(db: Database):
    """AUD-37: unit_ids are tenant-chosen and collide across experiments — the
    corroboration count must key by (experiment_id, unit_id), so corroborating a
    like-named unit in two DIFFERENT experiments is 2 units of breadth, not 1."""
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp1 = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")
    exp2 = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-2")
    workers.enroll(worker_id="wkr-1", pubkey_hex="cc" * 32)
    workers.bind_account("wkr-1", account_id="acct-1", trust_tier=TrustTier.T1_AUTHENTICATED)

    for i, exp in enumerate((exp1, exp2)):
        receipts.record(
            receipt_id=f"rcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id="wkr-1",
            worker_pubkey="cc" * 32,
            result_id=f"res-{i}",
            unit_id="u-0",  # SAME name, DIFFERENT experiments
        )

    assert receipts.account_corroboration_summary("acct-1")[0] == 2
