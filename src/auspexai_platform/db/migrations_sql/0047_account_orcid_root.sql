-- 0047_account_orcid_root: allow ORCID as an account ROOT idp (not just linked).
--
-- D8 (0045) added ORCID as a *linked* secondary identity on a GitHub-rooted
-- account. The ORCID-root work (researcher = ORCID-or-GitHub root; worker stays
-- GitHub-rooted) needs accounts whose root idp is 'orcid'. SQLite cannot ALTER a
-- CHECK constraint, so we rebuild `accounts` with the relaxed
-- `CHECK (idp IN ('github','orcid'))`, preserving every column + value, the
-- (idp,idp_sub) UNIQUE/index, and the on-accounts trust-tier trigger. The two
-- on-workers triggers (0044) are unaffected (they're defined on `workers`).
--
-- Inbound FKs to accounts(account_id) — workers, account_oauth_bindings,
-- tenants, account_trust_escalation(×2) — are resolved by name, so they bind to
-- the rebuilt table after RENAME. We disable FK enforcement for the swap and
-- re-enable it after (data is byte-identical, so no row can dangle).

-- legacy_alter_table=ON so the RENAME below does NOT re-validate/rewrite the
-- on-workers triggers (0044) that reference `accounts` by name — without it,
-- modern SQLite errors ("no such table: accounts") mid-rebuild because the
-- original table is already dropped. The triggers reference `accounts` by name
-- and resolve to the rebuilt table at fire time.
PRAGMA foreign_keys=OFF;
PRAGMA legacy_alter_table=ON;
BEGIN;

CREATE TABLE accounts_new (
    account_id        TEXT    PRIMARY KEY,
    idp               TEXT    NOT NULL,
    idp_sub           TEXT    NOT NULL,                  -- stable IdP subject (GitHub numeric id / ORCID iD)
    display_name      TEXT,
    email             TEXT,
    trust_tier        INTEGER NOT NULL DEFAULT 1,        -- T1 verified by default per §6.1
    created_at        TEXT    NOT NULL,                  -- ISO 8601 UTC
    retired_at        TEXT,
    identity_verified_at TEXT,
    identity_verified_by TEXT,
    identity_verification_method TEXT,
    identity_verification_note TEXT,
    suspended_at TEXT,
    suspension_reason TEXT,
    tier_set_by_class TEXT,
    public_attribution INTEGER NOT NULL DEFAULT 0,
    attribution_name TEXT,
    research_standing INTEGER NOT NULL DEFAULT 1,
    orcid_id TEXT,
    UNIQUE (idp, idp_sub),
    CHECK (idp IN ('github', 'orcid')),                  -- ORCID may now ROOT an account (researcher persona)
    CHECK (trust_tier BETWEEN 0 AND 4)
);

INSERT INTO accounts_new SELECT * FROM accounts;

DROP TABLE accounts;
ALTER TABLE accounts_new RENAME TO accounts;

CREATE INDEX accounts_idp_sub_idx ON accounts(idp, idp_sub);

-- Recreate the on-accounts trigger dropped with the old table (0044). The
-- on-workers triggers (worker_tier_inherit_on_bind / _on_insert) are untouched.
CREATE TRIGGER worker_tier_follow_account_change
AFTER UPDATE OF trust_tier ON accounts
BEGIN
    UPDATE workers
    SET trust_tier = NEW.trust_tier
    WHERE account_id = NEW.account_id AND retired_at IS NULL;
END;

COMMIT;
PRAGMA legacy_alter_table=OFF;
PRAGMA foreign_keys=ON;
