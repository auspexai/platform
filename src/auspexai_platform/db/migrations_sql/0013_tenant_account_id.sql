-- 0013_tenant_account_id.sql — b-lite account linkage.
--
-- Reserve the tenant -> account join column. Operator-populated at tenant
-- creation (POST /api/v0/tenants) for now; the OAuth-onboarding path that
-- writes it automatically arrives in Phase 2 (principles §6.9 / §9 #26).
--
-- Nullable: NULL = "no account linked yet" (the genesis / Maintainer-run
-- tenants and every pre-existing row). FK to accounts so a link can only ever
-- point at a real account — foreign_keys = ON is set on every connection
-- (db/database.py), and SQLite permits ADD COLUMN with a REFERENCES clause as
-- long as the column is nullable with a NULL default (which this is).
--
-- This is the first increment of option (c): once the column exists the
-- researcher credential carries account_id (auth/resolver.py via TenantBinding)
-- and the ACCOUNT_SCOPED exposure tag goes live for same-account visibility
-- (exposure/filter.py), unblocking R-D3 own-worker enrichment and the ops
-- worker<->tenant association view.

ALTER TABLE tenants ADD COLUMN account_id TEXT REFERENCES accounts(account_id);
