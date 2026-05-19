-- 0002_experiments.sql — manifests + experiments tables.
--
-- Adds the two tables that M5 resource routes write to.
--
--   manifests   — content-addressed (manifest_hash = SHA-256 of canonical JSON).
--                 Stores manifest body + ManifestSignature as JSON blobs.
--                 Per §5.14 content-addressing forecloses mid-flight swap.
--   experiments — coordinator-generated `experiment_id`; per (tenant_id,
--                 tenant_experiment_label) uniqueness lets tenants reference
--                 by their own naming. Status enum spans submitted →
--                 (approved → running) → terminal (aborted | completed) → archived.


CREATE TABLE manifests (
    manifest_hash      TEXT    PRIMARY KEY,        -- lowercase hex SHA-256 of canonical manifest JSON
    tenant_id          TEXT    NOT NULL,
    manifest_json      TEXT    NOT NULL,           -- the manifest body, opaque to v0
    signature_json     TEXT    NOT NULL,           -- the ManifestSignature object, opaque to v0
    uploaded_at        TEXT    NOT NULL,           -- ISO 8601 UTC
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE INDEX manifests_tenant_idx ON manifests(tenant_id);


CREATE TABLE experiments (
    experiment_id              TEXT    PRIMARY KEY,        -- coordinator-generated, e.g., 'exp-<random>'
    tenant_id                  TEXT    NOT NULL,
    tenant_experiment_label    TEXT    NOT NULL,           -- the `experiment_id` field from the tenant's manifest
    manifest_hash              TEXT    NOT NULL,
    status                     TEXT    NOT NULL,           -- 'submitted' | 'approved' | 'paused' | 'aborted' | 'completed' | 'archived'
    submitted_at               TEXT    NOT NULL,
    started_at                 TEXT,
    completed_at               TEXT,
    revision                   INTEGER NOT NULL DEFAULT 1,
    error_summary              TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id),
    FOREIGN KEY (manifest_hash) REFERENCES manifests(manifest_hash),
    UNIQUE (tenant_id, tenant_experiment_label)
);

CREATE INDEX experiments_tenant_idx ON experiments(tenant_id);
CREATE INDEX experiments_status_idx ON experiments(status);
