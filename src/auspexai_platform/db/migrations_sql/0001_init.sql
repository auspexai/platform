-- 0001_init.sql — initial coordinator schema.
--
-- Tables created here:
--   tenants    — pubkey-bound research tenants. Replaces the in-memory
--                TenantRegistry from M2 once M5 wires routes through this.
--   audit_log  — append-only operator + researcher actions. Every write
--                from M5+ goes through this.
--
-- Subsequent milestones add:
--   M5 — manifests, experiments
--   M6 — workers, work_units, assignments, results, per-job DB pattern
--   M7 — receipts, accounts, retired_keys
--   M8 — alerts


-- ---- tenants ---------------------------------------------------------------

CREATE TABLE tenants (
    tenant_id          TEXT    PRIMARY KEY,
    maintainer_pubkey  TEXT    NOT NULL UNIQUE,    -- 64 lowercase hex chars (32-byte Ed25519 pubkey)
    display_name       TEXT,
    contact_email      TEXT,
    contact_public     TEXT,
    description        TEXT,
    registered_at      TEXT    NOT NULL,           -- ISO 8601 UTC
    revision           INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX tenants_pubkey_idx ON tenants(maintainer_pubkey);


-- ---- audit_log -------------------------------------------------------------

CREATE TABLE audit_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at       TEXT    NOT NULL,            -- ISO 8601 UTC
    actor_class       TEXT    NOT NULL,            -- 'maintainer' | 'researcher' | 'anonymous' | 'account'
    actor_identifier  TEXT,                        -- pubkey hex (researcher), NULL otherwise
    actor_tenant_id   TEXT,                        -- researcher's tenant, NULL otherwise
    action            TEXT    NOT NULL,            -- 'tenant.register', 'experiment.abort', etc.
    resource_type     TEXT,
    resource_id       TEXT,
    payload           TEXT                         -- JSON-serialized structured details (nullable)
);

CREATE INDEX audit_log_occurred_at_idx ON audit_log(occurred_at);
CREATE INDEX audit_log_actor_idx ON audit_log(actor_class, actor_identifier);
CREATE INDEX audit_log_resource_idx ON audit_log(resource_type, resource_id);
