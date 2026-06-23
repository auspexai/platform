-- 0044_worker_tier_follows_account.sql — a worker's trust_tier is DERIVED from its
-- account (account-as-root), DB-enforced so it can never desync.
--
-- The drift this fixes: a worker that BINDS to an already-promoted account got a
-- hardcoded T1 (api/workers.py upgrade) instead of the account's current tier, and
-- the account's tier only propagated to workers on a promotion event — so a worker
-- joining an established (T2/T3) account, or one present across a demote, drifted
-- from its account. (Surfaced 2026-06-22: two workers, one account, two tiers.)
--
-- Enforcing it in the DB (triggers) rather than in each call site closes ALL paths
-- at once (bind / promote / demote / future raw updates) and supersedes the
-- application-side sync (worker_repository.update_tier_for_account + the bind tier),
-- which is now belt-and-suspenders. The worker's own compute-standing accrual is the
-- account's; a worker's tier is never independent of its account.

-- (1) One-time: sync every bound, non-retired worker to its account's current tier.
UPDATE workers
SET trust_tier = (SELECT a.trust_tier FROM accounts a WHERE a.account_id = workers.account_id)
WHERE account_id IS NOT NULL
  AND retired_at IS NULL
  AND (SELECT a.trust_tier FROM accounts a WHERE a.account_id = workers.account_id) IS NOT NULL;

-- (2) On a worker binding to (or changing) an account: inherit the account's tier.
--     Fires on the bind UPDATE (account_id NULL -> value), overriding the hardcoded
--     T1. Does NOT fire on unbind (NEW.account_id IS NULL) — the explicit unbind-to-T0
--     stands. Updates trust_tier only, so it can't re-trigger itself.
CREATE TRIGGER worker_tier_inherit_on_bind
AFTER UPDATE OF account_id ON workers
WHEN NEW.account_id IS NOT NULL
BEGIN
    UPDATE workers
    SET trust_tier = COALESCE(
        (SELECT a.trust_tier FROM accounts a WHERE a.account_id = NEW.account_id),
        NEW.trust_tier
    )
    WHERE worker_id = NEW.worker_id;
END;

-- (3) Same, for a worker INSERTed already bound (defensive — the normal path enrolls
--     accountless then binds via UPDATE, but a direct bound insert must not desync).
CREATE TRIGGER worker_tier_inherit_on_insert
AFTER INSERT ON workers
WHEN NEW.account_id IS NOT NULL
BEGIN
    UPDATE workers
    SET trust_tier = COALESCE(
        (SELECT a.trust_tier FROM accounts a WHERE a.account_id = NEW.account_id),
        NEW.trust_tier
    )
    WHERE worker_id = NEW.worker_id;
END;

-- (4) On an account's tier change (promote / demote): sync all its non-retired workers.
CREATE TRIGGER worker_tier_follow_account_change
AFTER UPDATE OF trust_tier ON accounts
BEGIN
    UPDATE workers
    SET trust_tier = NEW.trust_tier
    WHERE account_id = NEW.account_id AND retired_at IS NULL;
END;
