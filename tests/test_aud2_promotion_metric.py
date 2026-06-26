"""AUD-2 (A9 audit): the T1→T2 promotion/readiness surface consults the
firewall-aligned corroboration metric (account-dedup'd), not the raw,
account-farmable receipt COUNT(*).

Regression for the gap where `compute_receipt_stats` (which feeds the ops-console
"earned green" via `_t2_readiness` and the per-account eligibility readout) read
`account_receipt_summary` — so N workers under one account corroborating the SAME
unit inflated the receipt count N-fold, bypassing firewall #3 (A4).
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
from auspexai_platform.eligibility import EligibilityThresholds, compute_receipt_stats


def _exp(manifests, experiments, *, tenant_id, label):
    m = manifests.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label, "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    return experiments.create(
        tenant_id=tenant_id, tenant_experiment_label=label, manifest_hash=m.manifest_hash
    )


def test_within_account_farming_does_not_inflate_t2_readiness(db: Database):
    """3 workers of ONE account corroborate the SAME unit (raw receipts = 3,
    corroborated units = 1). With a receipt threshold of 2, the FARMED raw count
    would read "met"; the firewall-aligned corroborated count must read "not met"."""
    accounts = AccountRepository(db)
    tenants = TenantRepository(db)
    workers = WorkerRepository(db)
    experiments = ExperimentRepository(db)
    manifests = ManifestRepository(db)
    receipts = ReceiptIndexRepository(db)

    account = accounts.create(account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="100")
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
            unit_id="u-1",  # SAME unit — farming
        )

    thresholds = EligibilityThresholds(
        t2_receipt_threshold=2, t2_distinct_tenants=1, t2_min_account_age_days=0
    )
    stats = compute_receipt_stats(
        account_id="acct-1",
        current_tier=int(TrustTier.T1_AUTHENTICATED),
        receipt_index_repository=receipts,
        thresholds=thresholds,
        account=account,
        active_vouches=[],
    )

    t2 = stats.eligibility_by_tier[0]
    # The eligibility readout reads the DEDUP'd corroborated count (1), not raw 3.
    assert t2.actuals["receipts"] == 1
    assert t2.receipt_threshold_met is False, "farmed raw count (3) must not satisfy threshold 2"
    # Display total stays the honest raw receipt count.
    assert stats.total_receipts == 3


def test_t2_readiness_endpoint_uses_dedupd_metric(client, maintainer_token, db):
    """AUD-4 endpoint-level conformance: the WIRED GET /accounts `t2_readiness`
    surface (the ops-console "earned green") reports the dedup'd corroboration
    count, not the raw farmable receipt total. Closes the audit gap where the
    conformance suite tested only repo methods, never the endpoint."""
    accounts = AccountRepository(db)
    tenants = TenantRepository(db)
    workers = WorkerRepository(db)
    experiments = ExperimentRepository(db)
    manifests = ManifestRepository(db)
    receipts = ReceiptIndexRepository(db)

    accounts.create(
        account_id="acct-farm", idp=IdentityProvider.GITHUB, idp_sub="200"
    )  # T1 default
    tenants.register(tenant_id="tenant-f", maintainer_pubkey="cc" * 32)
    exp = _exp(manifests, experiments, tenant_id="tenant-f", label="exp-f")
    for i in range(3):
        pk = f"{i + 10:02x}" * 32
        workers.enroll(worker_id=f"fw-{i}", pubkey_hex=pk)
        workers.bind_account(
            f"fw-{i}", account_id="acct-farm", trust_tier=TrustTier.T1_AUTHENTICATED
        )
        receipts.record(
            receipt_id=f"frcpt-{i}",
            experiment_id=exp.experiment_id,
            worker_id=f"fw-{i}",
            worker_pubkey=pk,
            result_id=f"fres-{i}",
            unit_id="fu-1",  # SAME unit — farming
        )

    r = client.get("/api/v0/accounts", headers={"Authorization": f"Bearer {maintainer_token}"})
    assert r.status_code == 200, r.text
    accounts_list = r.json()["accounts"] if isinstance(r.json(), dict) else r.json()
    acct = next(a for a in accounts_list if a["account_id"] == "acct-farm")
    readiness = acct["t2_readiness"]
    assert readiness is not None, "T1 account must have a t2_readiness surface"
    # The endpoint reports 1 corroborated unit, NOT the 3 farmed raw receipts.
    assert readiness["receipts"] == 1
