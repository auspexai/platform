-- 0004_workers.sql — Ed25519-keyed worker daemons.
--
-- Workers enroll anonymously (pubkey-only) at T0. They optionally upgrade
-- to T1 by binding to an account via the M6a OAuth binding-token flow —
-- worker.account_id is the FK link to the bound account, NULL when anon.
--
-- Pubkeys live in their own column (NOT NULL, UNIQUE) because the auth-side
-- signature verifier looks them up to resolve the credential. The same
-- pubkey cannot be both a tenant maintainer_pubkey and a worker pubkey;
-- enforcement is at enrollment-time in WorkerRegistry (no schema-level
-- cross-table UNIQUE because tenants and workers live in separate tables).
--
-- capabilities is stored opaquely as JSON in v0. The scheduler (M6d) parses
-- specific fields (os, gpu, model names) as needed; coordinator schema
-- doesn't pre-commit to a shape.
--
-- last_heartbeat_at + retired_at give the scheduler what it needs to filter
-- assignable workers without an extra status column.


CREATE TABLE workers (
    worker_id          TEXT    PRIMARY KEY,
    pubkey_hex         TEXT    NOT NULL UNIQUE,        -- 64 lowercase hex chars (32-byte Ed25519 pubkey)
    account_id         TEXT,                            -- NULL until upgraded via M6a binding token
    trust_tier         INTEGER NOT NULL DEFAULT 0,      -- T0 anonymous on enroll; T1+ after account-bind
    capabilities_json  TEXT    NOT NULL DEFAULT '{}',   -- worker-declared; opaque to v0
    registered_at      TEXT    NOT NULL,                -- ISO 8601 UTC
    last_heartbeat_at  TEXT,
    retired_at         TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    CHECK (trust_tier BETWEEN 0 AND 4)
);

CREATE INDEX workers_pubkey_idx     ON workers(pubkey_hex);
CREATE INDEX workers_account_idx    ON workers(account_id);
CREATE INDEX workers_heartbeat_idx  ON workers(last_heartbeat_at);
CREATE INDEX workers_retired_idx    ON workers(retired_at);
