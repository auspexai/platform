"""Tests for M7f — receipt-stats endpoint + tier-eligibility calculator.

Reframed M7f per §6.1 + §6.2 alignment: this is a READ-ONLY signal,
not auto-promotion. Tests cover the eligibility calculator in isolation,
the GET /accounts/{account_id}/receipt-stats endpoint (account-self +
maintainer scope), and the explicit "no auto-promote" property — even
with both thresholds crossed, the account's trust_tier doesn't change.

inc-2 (firewall #3): breadth is now distinct TENANTS (via the
receipt_index ⨝ workers ⨝ experiments join), plus an anti-burst account-age
gate. The helpers seed real experiments so the tenant join resolves.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.config import Config
from auspexai_platform.db.models import Account, IdentityProvider, TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.eligibility import (
    EligibilityThresholds,
    compute_receipt_stats,
    compute_t2_eligibility,
)

AUTHORITY = "testserver"

# age window 0 = the age gate is vacuous (gates exercised explicitly below).
_THRESHOLDS_LOW = EligibilityThresholds(
    t2_receipt_threshold=3, t2_distinct_tenants=2, t2_min_account_age_days=0
)


def _seed_account_with_receipts(
    *,
    account_repository: AccountRepository,
    worker_repository: WorkerRepository,
    receipt_index_repository: ReceiptIndexRepository,
    experiment_repository: ExperimentRepository,
    tenant_repository: TenantRepository,
    manifest_repository: ManifestRepository,
    account_id: str = "acct-test",
    idp_sub: str | None = None,
    n_receipts: int = 0,
    n_distinct_tenants: int = 1,
) -> tuple:
    """One account + a bound worker + N receipts spread across
    `n_distinct_tenants` experiments, each owned by a distinct tenant (so the
    receipt_index ⨝ experiments tenant join resolves)."""
    account = account_repository.create(
        account_id=account_id,
        idp=IdentityProvider.GITHUB,
        idp_sub=idp_sub or f"gh-{account_id}",
    )
    worker = worker_repository.enroll(worker_id=f"wkr-{account_id}", pubkey_hex="a" * 64)
    worker_repository.bind_account(
        worker.worker_id, account_id=account.account_id, trust_tier=TrustTier.T1_AUTHENTICATED
    )
    exp_ids: list[str] = []
    for t in range(max(n_distinct_tenants, 1)):
        tenant_id = f"tenant-{account_id}-{t}"
        tenant_repository.register(tenant_id=tenant_id, maintainer_pubkey=f"{t:02x}" * 32)
        label = f"label-{account_id}-{t}"
        manifest = manifest_repository.insert(
            tenant_id=tenant_id,
            manifest_json={"tenant_id": tenant_id, "experiment_id": label},
            signature_json={},
        )
        exp = experiment_repository.create(
            tenant_id=tenant_id,
            tenant_experiment_label=label,
            manifest_hash=manifest.manifest_hash,
        )
        exp_ids.append(exp.experiment_id)
    for i in range(n_receipts):
        receipt_index_repository.record(
            receipt_id=f"rcpt-{account_id}-{i}",
            experiment_id=exp_ids[i % len(exp_ids)],
            worker_id=worker.worker_id,
            worker_pubkey=worker.pubkey_hex,
        )
    return account, worker


# ---- compute_t2_eligibility (pure function) -----------------------------


class TestComputeT2Eligibility:
    def test_both_thresholds_met_no_identity(self) -> None:
        e = compute_t2_eligibility(receipt_count=10, distinct_tenants=5, thresholds=_THRESHOLDS_LOW)
        assert e.tier == int(TrustTier.T2_TRUSTED)
        assert e.tier_name == "T2 trusted"
        assert e.receipt_threshold_met is True
        assert e.distinct_tenants_threshold_met is True
        assert e.thresholds == {"receipts": 3, "distinct_tenants": 2, "min_account_age_days": 0}
        assert e.actuals["receipts"] == 10
        assert e.actuals["distinct_tenants"] == 5
        assert e.identity_gate.satisfied is False
        assert e.ready_for_human_review is False  # identity gate not satisfied

    def test_receipt_threshold_unmet(self) -> None:
        e = compute_t2_eligibility(receipt_count=2, distinct_tenants=5, thresholds=_THRESHOLDS_LOW)
        assert e.receipt_threshold_met is False
        assert e.distinct_tenants_threshold_met is True
        assert e.ready_for_human_review is False

    def test_distinct_tenants_threshold_unmet(self) -> None:
        e = compute_t2_eligibility(receipt_count=10, distinct_tenants=1, thresholds=_THRESHOLDS_LOW)
        assert e.receipt_threshold_met is True
        assert e.distinct_tenants_threshold_met is False
        assert e.ready_for_human_review is False

    def test_zero_receipts(self) -> None:
        e = compute_t2_eligibility(receipt_count=0, distinct_tenants=0, thresholds=_THRESHOLDS_LOW)
        assert e.receipt_threshold_met is False
        assert e.distinct_tenants_threshold_met is False
        assert e.ready_for_human_review is False

    def test_account_age_gate(self) -> None:
        """Anti-burst: a young account fails the age gate even with thresholds +
        identity met; an old-enough account passes it."""
        thresholds = EligibilityThresholds(
            t2_receipt_threshold=3, t2_distinct_tenants=2, t2_min_account_age_days=7
        )
        now = datetime(2026, 6, 14, tzinfo=UTC)

        def _acct(age_days: int) -> Account:
            return Account(
                account_id="a",
                idp=IdentityProvider.GITHUB,
                idp_sub="s",
                trust_tier=TrustTier.T1_AUTHENTICATED,
                created_at=now - timedelta(days=age_days),
                identity_verified_at=now,  # identity satisfied
            )

        young = compute_t2_eligibility(
            receipt_count=10, distinct_tenants=5, thresholds=thresholds, account=_acct(2), now=now
        )
        assert young.account_age_threshold_met is False
        assert young.ready_for_human_review is False

        old = compute_t2_eligibility(
            receipt_count=10, distinct_tenants=5, thresholds=thresholds, account=_acct(30), now=now
        )
        assert old.account_age_threshold_met is True
        assert old.ready_for_human_review is True


# ---- compute_receipt_stats (against the receipt_index) ------------------


class TestComputeReceiptStats:
    def test_aggregates_from_index(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
        experiment_repository: ExperimentRepository,
        tenant_repository: TenantRepository,
        manifest_repository: ManifestRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            experiment_repository=experiment_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            n_receipts=5,
            n_distinct_tenants=2,
        )
        account = account_repository.get_by_id("acct-test")
        assert account is not None

        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_AUTHENTICATED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
            account=account,
        )
        assert stats.total_receipts == 5
        assert stats.distinct_tenants == 2  # the authoritative tenant join
        assert stats.current_tier_name == "T1 authenticated"
        assert stats.first_receipt_at is not None

        t2 = stats.eligibility_by_tier[0]
        assert t2.distinct_tenants_threshold_met is True
        assert t2.identity_gate.satisfied is False
        assert t2.ready_for_human_review is False

        # With identity verification: ready_for_human_review flips True.
        from auspexai_platform.db.models import IdentityVerificationMethod

        account = account_repository.verify_identity(
            "acct-test",
            verified_by="maintainer",
            method=IdentityVerificationMethod.MAINTAINER_ATTESTED,
            note="test",
        )
        stats2 = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_AUTHENTICATED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
            account=account,
        )
        t2_verified = stats2.eligibility_by_tier[0]
        assert t2_verified.identity_gate.satisfied is True
        assert t2_verified.ready_for_human_review is True

    def test_account_with_no_receipts(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
        experiment_repository: ExperimentRepository,
        tenant_repository: TenantRepository,
        manifest_repository: ManifestRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            experiment_repository=experiment_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            n_receipts=0,
        )
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_AUTHENTICATED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        assert stats.total_receipts == 0
        assert stats.distinct_tenants == 0
        t2 = stats.eligibility_by_tier[0]
        assert t2.receipt_threshold_met is False
        assert t2.distinct_tenants_threshold_met is False
        assert t2.ready_for_human_review is False

    def test_already_t2_omits_t2_eligibility_readout(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
        experiment_repository: ExperimentRepository,
        tenant_repository: TenantRepository,
        manifest_repository: ManifestRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            experiment_repository=experiment_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            n_receipts=5,
            n_distinct_tenants=2,
        )
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T2_TRUSTED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        assert stats.eligibility_by_tier == []
        assert stats.current_tier_name == "T2 trusted"


# ---- M7f explicit non-promotion property --------------------------------


class TestNoAutoPromotion:
    def test_threshold_crossing_does_not_change_trust_tier(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
        experiment_repository: ExperimentRepository,
        tenant_repository: TenantRepository,
        manifest_repository: ManifestRepository,
    ) -> None:
        """compute_receipt_stats is a read-only signal — even sky-high receipts
        across many tenants don't change the stored trust_tier."""
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            experiment_repository=experiment_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            n_receipts=100,
            n_distinct_tenants=10,
        )
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_AUTHENTICATED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        assert stats.eligibility_by_tier[0].receipt_threshold_met is True
        assert stats.eligibility_by_tier[0].identity_gate.satisfied is False
        assert stats.eligibility_by_tier[0].ready_for_human_review is False
        account = account_repository.get_by_id("acct-test")
        assert account.trust_tier == TrustTier.T1_AUTHENTICATED


# ---- GET /accounts/{account_id}/receipt-stats endpoint -----------------


def _signed_get(client: TestClient, *, privkey: Ed25519PrivateKey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


class TestReceiptStatsEndpoint:
    def _setup_account_with_receipts(
        self, client: TestClient, n_receipts: int = 5, n_distinct_experiments: int = 2
    ):
        """Helper using the live app's repositories so the stats endpoint sees the
        seeded data. (Tenant join not exercised here — these assert auth + the
        kept distinct_experiments field.)"""
        account_repository: AccountRepository = client.app.state.account_repository
        worker_repository: WorkerRepository = client.app.state.worker_repository
        receipt_index_repository: ReceiptIndexRepository = client.app.state.receipt_index_repository
        account = account_repository.create(
            account_id="acct-test", idp=IdentityProvider.GITHUB, idp_sub="gh-test"
        )
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-test", pubkey_hex=pub)
        worker_repository.bind_account(
            worker.worker_id, account_id=account.account_id, trust_tier=TrustTier.T1_AUTHENTICATED
        )
        for i in range(n_receipts):
            exp_idx = i % n_distinct_experiments
            receipt_index_repository.record(
                receipt_id=f"rcpt-test-{i}",
                experiment_id=f"exp-{exp_idx}",
                worker_id=worker.worker_id,
                worker_pubkey=worker.pubkey_hex,
            )
        return priv, pub, account, worker

    def test_account_self_can_fetch(self, client: TestClient) -> None:
        priv, pub, account, _worker = self._setup_account_with_receipts(client)
        response = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/accounts/{account.account_id}/receipt-stats",
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["account_id"] == account.account_id
        assert body["current_tier"] == int(TrustTier.T1_AUTHENTICATED)
        assert body["total_receipts"] == 5
        assert body["distinct_experiments"] == 2
        t2 = body["eligibility_by_tier"][0]
        assert t2["tier"] == int(TrustTier.T2_TRUSTED)
        assert t2["identity_check_pending"] is True

    def test_maintainer_can_fetch_any_account(
        self, client: TestClient, maintainer_token: str
    ) -> None:
        _priv, _pub, account, _worker = self._setup_account_with_receipts(client)
        response = client.get(
            f"/api/v0/accounts/{account.account_id}/receipt-stats",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        assert response.json()["total_receipts"] == 5

    def test_different_account_holder_forbidden(self, client: TestClient) -> None:
        _priv_a, _pub_a, account_a, _worker_a = self._setup_account_with_receipts(client)
        account_repository: AccountRepository = client.app.state.account_repository
        worker_repository: WorkerRepository = client.app.state.worker_repository
        account_b = account_repository.create(
            account_id="acct-other", idp=IdentityProvider.GITHUB, idp_sub="gh-other"
        )
        priv_b = Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()
        worker_b = worker_repository.enroll(worker_id="wkr-other", pubkey_hex=pub_b)
        worker_repository.bind_account(
            worker_b.worker_id,
            account_id=account_b.account_id,
            trust_tier=TrustTier.T1_AUTHENTICATED,
        )
        response = _signed_get(
            client,
            privkey=priv_b,
            pubkey_hex=pub_b,
            path=f"/api/v0/accounts/{account_a.account_id}/receipt-stats",
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"]["code"] == "account_self_or_maintainer_required"

    def test_anonymous_forbidden(self, client: TestClient) -> None:
        _priv, _pub, account, _worker = self._setup_account_with_receipts(client)
        response = client.get(f"/api/v0/accounts/{account.account_id}/receipt-stats")
        assert response.status_code in (401, 403)

    def test_unknown_account_returns_404(self, client: TestClient, maintainer_token: str) -> None:
        response = client.get(
            "/api/v0/accounts/acct-does-not-exist/receipt-stats",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error"]["code"] == "account_not_found"


# ---- Config validation -------------------------------------------------


class TestConfigEligibilityFields:
    def test_defaults(self, tmp_path) -> None:
        config = Config(state_dir=tmp_path)
        assert config.tier_t2_receipt_threshold == 50
        assert config.tier_t2_distinct_tenants == 3
        assert config.tier_t2_min_account_age_days == 7
        assert config.vouch_min_receipts == 20
        assert config.vouch_min_distinct_tenants == 2
        assert config.containment_strict_below_tier == 0

    def test_invalid_threshold_rejected(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="tier_t2_receipt_threshold"):
            Config(state_dir=tmp_path, tier_t2_receipt_threshold=0)
        with pytest.raises(ValueError, match="tier_t2_min_account_age_days"):
            Config(state_dir=tmp_path, tier_t2_min_account_age_days=-1)

    def test_env_override(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUSPEXAI_TIER_T2_RECEIPT_THRESHOLD", "7")
        monkeypatch.setenv("AUSPEXAI_TIER_T2_DISTINCT_TENANTS", "2")
        monkeypatch.setenv("AUSPEXAI_TIER_T2_MIN_ACCOUNT_AGE_DAYS", "0")
        config = Config.from_env(state_dir=tmp_path)
        assert config.tier_t2_receipt_threshold == 7
        assert config.tier_t2_distinct_tenants == 2
        assert config.tier_t2_min_account_age_days == 0
