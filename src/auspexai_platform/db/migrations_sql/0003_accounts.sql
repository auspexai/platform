-- 0003_accounts.sql — identity-bound accounts + short-lived OAuth binding tokens.
--
-- Tables created here:
--   accounts                  — humans who have proved an identity via an IdP
--                               device flow. Identity is the (idp, idp_sub)
--                               pair; account_id is coordinator-generated.
--                               trust_tier defaults to T1 (verified) because
--                               creating an account requires completing an IdP
--                               flow — anonymous workers (T0) never get an
--                               account row. Per-account, not per-receipt,
--                               recognition (§6.8.2 layer 3).
--   account_oauth_bindings    — short-lived (5 min default), one-shot tokens
--                               returned from OAuth exchange that M6b consumes
--                               to bind a worker (or researcher SDK key) to
--                               an account. Stored rather than relying on
--                               in-memory state so coordinator restarts don't
--                               void in-flight tokens.


CREATE TABLE accounts (
    account_id        TEXT    PRIMARY KEY,
    idp               TEXT    NOT NULL,
    idp_sub           TEXT    NOT NULL,                  -- stable IdP subject (e.g., GitHub numeric user id)
    display_name      TEXT,
    email             TEXT,
    trust_tier        INTEGER NOT NULL DEFAULT 1,        -- T1 verified by default per §6.1
    created_at        TEXT    NOT NULL,                  -- ISO 8601 UTC
    retired_at        TEXT,
    UNIQUE (idp, idp_sub),
    CHECK (idp IN ('github')),                           -- Phase 1: GitHub only; extend in migration when new IdPs added
    CHECK (trust_tier BETWEEN 0 AND 4)
);

CREATE INDEX accounts_idp_sub_idx ON accounts(idp, idp_sub);


CREATE TABLE account_oauth_bindings (
    binding_token     TEXT    PRIMARY KEY,
    account_id        TEXT    NOT NULL,
    created_at        TEXT    NOT NULL,
    expires_at        TEXT    NOT NULL,
    consumed_at       TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);

CREATE INDEX account_oauth_bindings_account_idx ON account_oauth_bindings(account_id);
CREATE INDEX account_oauth_bindings_expires_idx ON account_oauth_bindings(expires_at);
