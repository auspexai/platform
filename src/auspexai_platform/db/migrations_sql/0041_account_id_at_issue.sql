-- 0041_account_id_at_issue.sql — permanent receipt/divergence -> account link.
--
-- Today a receipt's (and a divergence record's) ACCOUNT attribution is resolved
-- LIVE, by joining receipt_index -> workers on worker_id and reading
-- workers.account_id. That live link breaks the moment a worker "unbinds" (its
-- account_id is set back to NULL on logout/unbind): every PAST contribution the
-- worker made would retroactively lose its account, orphaning receipts and
-- divergence rows that an account has already earned. So we SNAPSHOT the worker's
-- account_id AT ISSUANCE onto each row — the account-attribution analog of
-- public_attribution_at_issue (0039), which snapshots the consent a contribution
-- was made under so a later flag change can't rewrite the past.
--
-- The backfill sets account_id_at_issue to the worker's CURRENT account_id, which
-- is EXACTLY what the live JOIN returns for all existing data. So switching the
-- account-scoped queries from the workers JOIN to this denormalized column is
-- BEHAVIOR-PRESERVING: identical results for current data, divergence appearing
-- only once a worker actually unbinds in the future. Rows whose worker is
-- anonymous/T0 (account_id IS NULL) snapshot NULL, matching the INNER JOIN that
-- already excluded them. See worker_unbind_gap.md + citation_consent_snapshot.md.

ALTER TABLE receipt_index ADD COLUMN account_id_at_issue TEXT;
UPDATE receipt_index
SET account_id_at_issue = (
    SELECT w.account_id FROM workers w WHERE w.worker_id = receipt_index.worker_id
);

ALTER TABLE divergence_index ADD COLUMN account_id_at_issue TEXT;
UPDATE divergence_index
SET account_id_at_issue = (
    SELECT w.account_id FROM workers w WHERE w.worker_id = divergence_index.worker_id
);
