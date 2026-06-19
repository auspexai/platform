"""A2 firewall #1 equal-trust accrual (data layer) — the toggle-gated trust metric.

Per the ratified firewall #1 design (D7): post-flip, trust accrues from the process
bundle — which REQUIRES STRICT containment — equally per unit for agreement AND
divergence, never reading integrity_basis. OFF (default, the live state until the
activation gate) is byte-identical to A4's behavior. These exercise the repo
branch; the issuance/submit wiring is exercised separately.
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


def _worker(workers, wid, pk, account):
    workers.enroll(worker_id=wid, pubkey_hex=pk)
    workers.bind_account(wid, account_id=account, trust_tier=TrustTier.T1_AUTHENTICATED)


def _fixture(db):
    accounts, tenants, workers, experiments, manifests, receipts = _repos(db)
    accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
    tenants.register(tenant_id="tenant-a", maintainer_pubkey="aa" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-a", label="exp-1")
    return workers, receipts, exp


def test_off_counts_agreement_regardless_of_containment(db: Database):
    """OFF (default = current behavior): agreement receipts count whether they ran
    STRICT or permissive — the flip is not active, nothing changes."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-s", "11" * 32, "acct-1")
    _worker(workers, "wkr-p", "22" * 32, "acct-1")
    receipts.record(
        receipt_id="r-s",
        experiment_id=exp.experiment_id,
        worker_id="wkr-s",
        worker_pubkey="11" * 32,
        unit_id="u-strict",
        ran_under_strict=True,
    )
    receipts.record(
        receipt_id="r-p",
        experiment_id=exp.experiment_id,
        worker_id="wkr-p",
        worker_pubkey="22" * 32,
        unit_id="u-perm",
        ran_under_strict=False,
    )
    assert receipts.account_corroboration_summary("acct-1")[0] == 2


def test_on_counts_only_strict_agreement(db: Database):
    """ON (post-flip): the bundle requires STRICT containment, so a permissive
    agreement unit no longer earns trust — only the STRICT one counts."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-s", "11" * 32, "acct-1")
    _worker(workers, "wkr-p", "22" * 32, "acct-1")
    receipts.record(
        receipt_id="r-s",
        experiment_id=exp.experiment_id,
        worker_id="wkr-s",
        worker_pubkey="11" * 32,
        unit_id="u-strict",
        ran_under_strict=True,
    )
    receipts.record(
        receipt_id="r-p",
        experiment_id=exp.experiment_id,
        worker_id="wkr-p",
        worker_pubkey="22" * 32,
        unit_id="u-perm",
        ran_under_strict=False,
    )
    assert receipts.account_corroboration_summary("acct-1", equal_trust_enabled=True)[0] == 1


def test_on_counts_strict_divergence_equally_with_agreement(db: Database):
    """D7 core: a STRICT divergence earns trust EQUAL to a STRICT agreement. OFF
    ignores divergence entirely (the interim agreement-only model)."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-a", "11" * 32, "acct-1")
    _worker(workers, "wkr-d", "22" * 32, "acct-1")
    receipts.record(
        receipt_id="r-a",
        experiment_id=exp.experiment_id,
        worker_id="wkr-a",
        worker_pubkey="11" * 32,
        unit_id="u-agree",
        ran_under_strict=True,
    )
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="wkr-d",
        worker_pubkey="22" * 32,
        unit_id="u-diverge",
        ran_under_strict=True,
    )
    assert receipts.account_corroboration_summary("acct-1", equal_trust_enabled=True)[0] == 2
    assert receipts.account_corroboration_summary("acct-1")[0] == 1  # OFF: agreement only


def test_on_excludes_permissive_divergence(db: Database):
    """A permissive divergence has no bundle → no trust, even ON."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-d", "22" * 32, "acct-1")
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="wkr-d",
        worker_pubkey="22" * 32,
        unit_id="u-perm-div",
        ran_under_strict=False,
    )
    assert receipts.account_corroboration_summary("acct-1", equal_trust_enabled=True)[0] == 0


def test_on_dedups_same_unit_across_agreement_and_divergence(db: Database):
    """A4 per-unit holds through the union: agreeing AND diverging on the same unit
    is still ONE unit of trust."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-a", "11" * 32, "acct-1")
    _worker(workers, "wkr-d", "22" * 32, "acct-1")
    receipts.record(
        receipt_id="r-a",
        experiment_id=exp.experiment_id,
        worker_id="wkr-a",
        worker_pubkey="11" * 32,
        unit_id="u-1",
        ran_under_strict=True,
    )
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="wkr-d",
        worker_pubkey="22" * 32,
        unit_id="u-1",
        ran_under_strict=True,
    )
    assert receipts.account_corroboration_summary("acct-1", equal_trust_enabled=True)[0] == 1


def test_off_ignores_divergence_index(db: Database):
    """OFF never reads divergence_index — the disagreement class is dormant until
    the flip."""
    workers, receipts, exp = _fixture(db)
    _worker(workers, "wkr-d", "22" * 32, "acct-1")
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="wkr-d",
        worker_pubkey="22" * 32,
        unit_id="u-d",
        ran_under_strict=True,
    )
    assert receipts.account_corroboration_summary("acct-1")[0] == 0
