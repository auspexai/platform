-- 0010_account_trust_escalation.sql — identity verification + suspension columns
-- on accounts, trust_tier cap at T3, vouches table.
--
-- Ratified 2026-05-24: Q22 (identity verification), Q23 (vouching),
-- Q24 (tier-bump endpoint). See AuspexAI_Principles_and_Scope.md §6.2.1–§6.2.3.
--
-- Changes to accounts:
--   - identity_verified_at/by/method/note: §6.2.1 identity gate artifact
--   - suspended_at: §6.2.3 account-level suspension (distinct from per-worker quarantine)
--   - trust_tier CHECK relaxed from 0–4 to 0–3 (T4 removed; Maintainer is account-role, not tier)
--
-- New table: vouches (§6.2.2 vouching mechanism)

-- SQLite cannot ALTER CHECK constraints in-place. The existing CHECK(trust_tier BETWEEN 0 AND 4)
-- on accounts and workers remains in the schema from 0003/0004 — SQLite CHECK constraints
-- from CREATE TABLE are immutable. We enforce the T3 cap at the application layer
-- (TrustTier enum + promote endpoint validation). Existing rows with trust_tier=4
-- would need a data migration if any exist; in practice none do (T4 was never assigned).

ALTER TABLE accounts ADD COLUMN identity_verified_at TEXT;
ALTER TABLE accounts ADD COLUMN identity_verified_by TEXT;
ALTER TABLE accounts ADD COLUMN identity_verification_method TEXT;
ALTER TABLE accounts ADD COLUMN identity_verification_note TEXT;
ALTER TABLE accounts ADD COLUMN suspended_at TEXT;


CREATE TABLE vouches (
    vouch_id            TEXT    PRIMARY KEY,
    voucher_account_id  TEXT    NOT NULL,
    target_account_id   TEXT    NOT NULL,
    rationale           TEXT,
    created_at          TEXT    NOT NULL,                -- ISO 8601 UTC
    revoked_at          TEXT,
    FOREIGN KEY (voucher_account_id) REFERENCES accounts(account_id),
    FOREIGN KEY (target_account_id) REFERENCES accounts(account_id),
    UNIQUE (voucher_account_id, target_account_id)
);

CREATE INDEX vouches_target_idx ON vouches(target_account_id);
CREATE INDEX vouches_voucher_idx ON vouches(voucher_account_id);
