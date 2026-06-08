-- 0022_attestations.sql — control-DB store of canonical result-set attestations.
--
-- The per-experiment result-set attestation (#34 §6.3) was previously
-- recomputed on demand from the per-job DB and never persisted: it had a fresh
-- attestation_id on every call and vanished when the per-job DB was removed
-- (e.g. a coordinator clean-slate). This table makes the FINAL attestation
-- CANONICAL and DURABLE — written once when an experiment reaches COMPLETED
-- (eager, from either completion path) or lazily on first GET — so it survives
-- per-job DB deletion exactly the way receipt_index (0007) does.
--
-- The COSE-signed blob is the canonical artifact a verifier consumes;
-- merkle_root + the Rekor anchor + (later) the Zenodo doi are denormalized for
-- fast lookup/serving. rekor_log_index = 0 / 'lab-mode-no-rekor' is the
-- not-yet-anchored placeholder the A2 backfill replaces.
--
-- No FK on experiment_id (mirrors receipt_index): the attestation is a durable
-- historical record and must NOT cascade-delete with the experiment row. Only
-- FINAL (partial=0) attestations are persisted — a checkpoint/partial is a
-- transient consensus-so-far snapshot, not a canonical artifact, so it stays
-- on demand. The partial-unique index enforces at most one canonical
-- attestation per experiment (race-safe idempotency for the two emit paths).

CREATE TABLE attestations (
    attestation_id           TEXT    PRIMARY KEY,                  -- 'att-<...>'
    experiment_id            TEXT    NOT NULL,                     -- coord's exp- id
    tenant_id                TEXT    NOT NULL,
    tenant_experiment_label  TEXT    NOT NULL,
    merkle_root              TEXT    NOT NULL,
    algorithm                TEXT    NOT NULL,
    unit_count               INTEGER NOT NULL,
    cose_signed_blob         BLOB    NOT NULL,                     -- the canonical artifact
    signing_key_pubkey_hex   TEXT    NOT NULL,
    rekor_log_index          INTEGER NOT NULL DEFAULT 0,           -- 0 = not yet anchored (A2)
    rekor_entry_uuid         TEXT    NOT NULL DEFAULT 'lab-mode-no-rekor',
    partial                  INTEGER NOT NULL DEFAULT 0,           -- always 0 for persisted rows
    doi                      TEXT,                                 -- Workstream-D seam (nullable)
    issued_at                TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX attestations_final_experiment_idx
    ON attestations(experiment_id) WHERE partial = 0;
