-- 0052_feature_schema_enforcement.sql — D16.1 (the self-describing feature
-- schema) coordinator enforcement substrate: Inc 2 (submit-time validation) +
-- Inc 4 (result-ingest §7 structural enforcement). See feature_schema_design.md.
--
-- Two pieces:
--   * experiments.certified — was this experiment running a CERTIFIED starter at
--     SUBMIT (cert resolved via certified_match)? Captured at submit because
--     certification "vouches for the code" is a submit-time property (a later
--     cert revocation must not change how a running experiment's results are
--     enforced). It governs the §7 reject-vs-flag decision at ingest:
--     certified ⇒ REJECT a non-conforming result; BYOT ⇒ FLAG + accept.
--   * schema_rejection_index — the parallel index for the §7 rejection class,
--     modeled on divergence_index (0037): one row per (worker, unit) whose
--     emitted payload violated the manifest's declared feature_schema. Recorded
--     for BOTH certified (rejected, terminal-for-unit) and BYOT (flagged,
--     accepted) so the maintainer needs-attention surface (E14) can alert on
--     certified rejections — a §7 leak or executor/schema mismatch — and a
--     researcher can later see their BYOT flags. NOT minted as a Receipt (it is
--     a fault, not corroboration), exactly as divergence gets its own index.

ALTER TABLE experiments ADD COLUMN certified INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS schema_rejection_index (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id   TEXT    NOT NULL,
    worker_id       TEXT    NOT NULL,
    worker_pubkey   TEXT    NOT NULL,
    unit_id         TEXT    NOT NULL,
    certified       INTEGER NOT NULL DEFAULT 0,
    violations_json TEXT    NOT NULL,
    recorded_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (worker_id, unit_id),
    FOREIGN KEY (worker_id) REFERENCES workers(worker_id)
);
CREATE INDEX schema_rejection_index_unit_idx       ON schema_rejection_index(unit_id);
CREATE INDEX schema_rejection_index_experiment_idx ON schema_rejection_index(experiment_id);
