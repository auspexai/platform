"""Migration 0044 — a worker's trust_tier is DB-derived from its account
(account-as-root). DB triggers keep them in sync through bind / promote / demote so
they can't drift (the bug: a worker binding to an already-promoted account got a
hardcoded T1)."""

from __future__ import annotations

from auspexai_platform.db.models import IdentityProvider, TrustTier


def test_late_bind_inherits_account_tier(account_repository, worker_repository):
    # Account already at T2 when the worker binds — the bind hardcodes T1, but the
    # trigger inherits the account's CURRENT tier (the reported drift, fixed).
    account_repository.create(account_id="a", idp=IdentityProvider.GITHUB, idp_sub="g")
    account_repository.promote("a", target_tier=TrustTier.T2_TRUSTED)
    worker_repository.enroll(worker_id="w", pubkey_hex="ab" * 32)
    worker_repository.bind_account("w", account_id="a", trust_tier=TrustTier.T1_AUTHENTICATED)
    assert worker_repository.get_by_id("w").trust_tier == TrustTier.T2_TRUSTED


def test_account_promote_then_demote_syncs_workers(account_repository, worker_repository):
    account_repository.create(account_id="a", idp=IdentityProvider.GITHUB, idp_sub="g")
    worker_repository.enroll(worker_id="w", pubkey_hex="ab" * 32)
    worker_repository.bind_account("w", account_id="a", trust_tier=TrustTier.T1_AUTHENTICATED)
    account_repository.promote("a", target_tier=TrustTier.T2_TRUSTED)
    assert worker_repository.get_by_id("w").trust_tier == TrustTier.T2_TRUSTED  # promote syncs
    account_repository.demote("a", target_tier=TrustTier.T1_AUTHENTICATED)
    assert worker_repository.get_by_id("w").trust_tier == TrustTier.T1_AUTHENTICATED  # demote syncs


def test_two_workers_one_account_share_one_tier(account_repository, worker_repository):
    # The exact reported shape: two workers, one account — they must NOT diverge.
    account_repository.create(account_id="a", idp=IdentityProvider.GITHUB, idp_sub="g")
    worker_repository.enroll(worker_id="early", pubkey_hex="ab" * 32)
    worker_repository.bind_account("early", account_id="a", trust_tier=TrustTier.T1_AUTHENTICATED)
    account_repository.promote("a", target_tier=TrustTier.T2_TRUSTED)  # early -> T2 via sync
    worker_repository.enroll(worker_id="late", pubkey_hex="cd" * 32)
    worker_repository.bind_account("late", account_id="a", trust_tier=TrustTier.T1_AUTHENTICATED)
    a = worker_repository.get_by_id("early").trust_tier
    b = worker_repository.get_by_id("late").trust_tier
    assert a == b == TrustTier.T2_TRUSTED  # same account, same tier


def test_unbound_worker_keeps_t0(worker_repository):
    # No account → no trigger → the stored tier stands (so accountless test workers
    # and real T0 anonymous workers are unaffected).
    worker_repository.enroll(worker_id="w", pubkey_hex="ab" * 32)
    assert worker_repository.get_by_id("w").trust_tier == TrustTier.T0_ANONYMOUS
