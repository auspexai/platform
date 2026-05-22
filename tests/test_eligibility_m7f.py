"""Tests for M7f — receipt-stats endpoint + tier-eligibility calculator.

Reframed M7f per §6.1 + §6.2 alignment: this is a READ-ONLY signal,
not auto-promotion. Tests cover the eligibility calculator in isolation,
the GET /accounts/{account_id}/receipt-stats endpoint (account-self +
maintainer scope), and the explicit "no auto-promote" property — even
with both thresholds crossed, the account's trust_tier doesn't change.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.config import Config
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    ReceiptIndexRepository,
    WorkerRepository,
)
from auspexai_platform.eligibility import (
    EligibilityThresholds,
    compute_receipt_stats,
    compute_t2_eligibility,
)

AUTHORITY = "testserver"

_THRESHOLDS_LOW = EligibilityThresholds(t2_receipt_threshold=3, t2_distinct_experiments=2)


def _seed_account_with_receipts(
    *,
    account_repository: AccountRepository,
    worker_repository: WorkerRepository,
    receipt_index_repository: ReceiptIndexRepository,
    account_id: str = "acct-test",
    idp_sub: str | None = None,
    n_receipts: int = 0,
    n_distinct_experiments: int = 1,
) -> tuple:
    """Set up one account + one worker bound to it + N receipts spread
    across `n_distinct_experiments` experiment IDs."""
    account = account_repository.create(
        account_id=account_id,
        idp=IdentityProvider.GITHUB,
        idp_sub=idp_sub or f"gh-{account_id}",
    )
    worker = worker_repository.enroll(
        worker_id=f"wkr-{account_id}",
        pubkey_hex="a" * 64,
    )
    worker_repository.bind_account(
        worker.worker_id,
        account_id=account.account_id,
        trust_tier=TrustTier.T1_VERIFIED,
    )
    for i in range(n_receipts):
        exp_idx = i % n_distinct_experiments
        receipt_index_repository.record(
            receipt_id=f"rcpt-{account_id}-{i}",
            experiment_id=f"exp-{exp_idx}",
            worker_id=worker.worker_id,
            worker_pubkey=worker.pubkey_hex,
        )
    return account, worker


# ---- compute_t2_eligibility (pure function) -----------------------------


class TestComputeT2Eligibility:
    def test_both_thresholds_met(self) -> None:
        e = compute_t2_eligibility(
            receipt_count=10,
            distinct_experiments=5,
            thresholds=_THRESHOLDS_LOW,
        )
        assert e.tier == int(TrustTier.T2_VOUCHED)
        assert e.tier_name == "T2 vouched"
        assert e.receipt_threshold_met is True
        assert e.distinct_experiments_threshold_met is True
        assert e.thresholds == {"receipts": 3, "distinct_experiments": 2}
        assert e.actuals == {"receipts": 10, "distinct_experiments": 5}
        # The pending flags NEVER flip to False from automatic computation.
        assert e.identity_check_pending is True
        assert e.vouching_pending is True
        # ready_for_human_review reflects automatic-gate status only.
        assert e.ready_for_human_review is True

    def test_receipt_threshold_unmet(self) -> None:
        e = compute_t2_eligibility(
            receipt_count=2,
            distinct_experiments=5,
            thresholds=_THRESHOLDS_LOW,
        )
        assert e.receipt_threshold_met is False
        assert e.distinct_experiments_threshold_met is True
        assert e.ready_for_human_review is False

    def test_distinct_experiments_threshold_unmet(self) -> None:
        e = compute_t2_eligibility(
            receipt_count=10,
            distinct_experiments=1,
            thresholds=_THRESHOLDS_LOW,
        )
        assert e.receipt_threshold_met is True
        assert e.distinct_experiments_threshold_met is False
        assert e.ready_for_human_review is False

    def test_zero_receipts(self) -> None:
        e = compute_t2_eligibility(
            receipt_count=0,
            distinct_experiments=0,
            thresholds=_THRESHOLDS_LOW,
        )
        assert e.receipt_threshold_met is False
        assert e.distinct_experiments_threshold_met is False
        assert e.ready_for_human_review is False


# ---- compute_receipt_stats (against the receipt_index) ------------------


class TestComputeReceiptStats:
    def test_aggregates_from_index(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            n_receipts=5,
            n_distinct_experiments=2,
        )
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_VERIFIED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        assert stats.total_receipts == 5
        assert stats.distinct_experiments == 2
        assert stats.current_tier == int(TrustTier.T1_VERIFIED)
        assert stats.current_tier_name == "T1 verified"
        assert stats.first_receipt_at is not None
        assert stats.last_receipt_at is not None

        # T2 eligibility readout present because account is below T2.
        assert len(stats.eligibility_by_tier) == 1
        t2 = stats.eligibility_by_tier[0]
        assert t2.tier == int(TrustTier.T2_VOUCHED)
        assert t2.ready_for_human_review is True

    def test_account_with_no_receipts(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            n_receipts=0,
        )
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T1_VERIFIED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        assert stats.total_receipts == 0
        assert stats.distinct_experiments == 0
        assert stats.first_receipt_at is None
        assert stats.last_receipt_at is None
        # T2 eligibility still in the readout — gates just all show unmet.
        assert len(stats.eligibility_by_tier) == 1
        t2 = stats.eligibility_by_tier[0]
        assert t2.receipt_threshold_met is False
        assert t2.distinct_experiments_threshold_met is False
        assert t2.ready_for_human_review is False

    def test_already_t2_omits_t2_eligibility_readout(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
    ) -> None:
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            n_receipts=5,
            n_distinct_experiments=2,
        )
        # Pretend the account was promoted to T2 already (in real life this
        # would happen via the future tier-bump endpoint).
        stats = compute_receipt_stats(
            account_id="acct-test",
            current_tier=int(TrustTier.T2_VOUCHED),
            receipt_index_repository=receipt_index_repository,
            thresholds=_THRESHOLDS_LOW,
        )
        # Already T2 — no T2 readout shown. T3 readout not yet implemented.
        assert stats.eligibility_by_tier == []
        assert stats.current_tier == int(TrustTier.T2_VOUCHED)
        assert stats.current_tier_name == "T2 vouched"


# ---- M7f explicit non-promotion property --------------------------------


class TestNoAutoPromotion:
    def test_threshold_crossing_does_not_change_trust_tier(
        self,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
        receipt_index_repository: ReceiptIndexRepository,
    ) -> None:
        """Even with receipts well over threshold + distinct experiments
        well over threshold, the account's trust_tier stays at whatever it
        was. M7f is a read-only signal — no auto-promotion."""
        _seed_account_with_receipts(
            account_repository=account_repository,
            worker_repository=worker_repository,
            receipt_index_repository=receipt_index_repository,
            n_receipts=100,
            n_distinct_experiments=10,
        )
        # Multiple calls to compute_receipt_stats — even with sky-high
        # numbers, the account stays at T1.
        for _ in range(3):
            stats = compute_receipt_stats(
                account_id="acct-test",
                current_tier=int(TrustTier.T1_VERIFIED),
                receipt_index_repository=receipt_index_repository,
                thresholds=_THRESHOLDS_LOW,
            )
            assert stats.eligibility_by_tier[0].ready_for_human_review is True
            assert stats.eligibility_by_tier[0].identity_check_pending is True
            assert stats.eligibility_by_tier[0].vouching_pending is True

        # The actual stored tier is unchanged.
        account = account_repository.get_by_id("acct-test")
        assert account.trust_tier == TrustTier.T1_VERIFIED


# ---- GET /accounts/{account_id}/receipt-stats endpoint -----------------


def _signed_get(
    client: TestClient,
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    path: str,
):
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
        self,
        client: TestClient,
        n_receipts: int = 5,
        n_distinct_experiments: int = 2,
    ):
        """Helper using the live app's repositories so the stats endpoint
        sees the seeded data."""
        account_repository: AccountRepository = client.app.state.account_repository
        worker_repository: WorkerRepository = client.app.state.worker_repository
        receipt_index_repository: ReceiptIndexRepository = client.app.state.receipt_index_repository
        account = account_repository.create(
            account_id="acct-test",
            idp=IdentityProvider.GITHUB,
            idp_sub="gh-test",
        )
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-test", pubkey_hex=pub)
        worker_repository.bind_account(
            worker.worker_id,
            account_id=account.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
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
        assert body["current_tier"] == int(TrustTier.T1_VERIFIED)
        assert body["current_tier_name"] == "T1 verified"
        assert body["total_receipts"] == 5
        assert body["distinct_experiments"] == 2
        # Eligibility readout for T2 present and shows the pending flags.
        assert len(body["eligibility_by_tier"]) == 1
        t2 = body["eligibility_by_tier"][0]
        assert t2["tier"] == int(TrustTier.T2_VOUCHED)
        assert t2["identity_check_pending"] is True
        assert t2["vouching_pending"] is True

    def test_maintainer_can_fetch_any_account(
        self,
        client: TestClient,
        maintainer_token: str,
    ) -> None:
        _priv, _pub, account, _worker = self._setup_account_with_receipts(client)
        response = client.get(
            f"/api/v0/accounts/{account.account_id}/receipt-stats",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["account_id"] == account.account_id
        assert body["total_receipts"] == 5

    def test_different_account_holder_forbidden(self, client: TestClient) -> None:
        # Set up account A with receipts.
        _priv_a, _pub_a, account_a, _worker_a = self._setup_account_with_receipts(client)

        # Set up worker B bound to a different account.
        account_repository: AccountRepository = client.app.state.account_repository
        worker_repository: WorkerRepository = client.app.state.worker_repository
        account_b = account_repository.create(
            account_id="acct-other",
            idp=IdentityProvider.GITHUB,
            idp_sub="gh-other",
        )
        priv_b = Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()
        worker_b = worker_repository.enroll(worker_id="wkr-other", pubkey_hex=pub_b)
        worker_repository.bind_account(
            worker_b.worker_id,
            account_id=account_b.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )

        # Worker B tries to fetch account A's stats — denied.
        response = _signed_get(
            client,
            privkey=priv_b,
            pubkey_hex=pub_b,
            path=f"/api/v0/accounts/{account_a.account_id}/receipt-stats",
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"]["code"] == "account_self_or_maintainer_required"

    def test_anonymous_forbidden(self, client: TestClient) -> None:
        # Set up an account so the endpoint route resolves, but call without
        # any credentials.
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
        assert config.tier_t2_distinct_experiments == 3

    def test_invalid_threshold_rejected(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="tier_t2_receipt_threshold"):
            Config(state_dir=tmp_path, tier_t2_receipt_threshold=0)

    def test_env_override(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUSPEXAI_TIER_T2_RECEIPT_THRESHOLD", "7")
        monkeypatch.setenv("AUSPEXAI_TIER_T2_DISTINCT_EXPERIMENTS", "2")
        config = Config.from_env(state_dir=tmp_path)
        assert config.tier_t2_receipt_threshold == 7
        assert config.tier_t2_distinct_experiments == 2
