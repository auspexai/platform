-- 0037_equal_trust_accrual.sql — firewall #1 equal-trust flip accrual substrate (A2).
--
-- Per the ratified firewall #1 design (firewall_1_divergence_receipt_design.md, D7),
-- post-flip trust accrues from the process-attestation bundle — equally per unit for
-- agreement AND divergence — and the bundle REQUIRES STRICT containment. So:
--   * receipt_index gains `ran_under_strict` — the containment the agreeing worker
--     ran under, captured at issuance, so the equal-trust accrual can keep only
--     STRICT-contained units;
--   * `divergence_index` is the parallel trust-index for the disagreement class —
--     one row per diverging worker per unit (D7 §11: divergence is NOT minted as a
--     Receipt object, so it gets its own index, not a fake receipt).
--
-- Both are DORMANT until trust_model_policy.equal_trust_enabled flips ON: the
-- account_corroboration_summary OFF path ignores them (counts agreement receipts,
-- any containment — current behavior), so this migration changes NO live trust
-- behavior. ran_under_strict DEFAULT 0 on existing rows is "unknown"; the flip's
-- activation transition backfills via the footprint / rebuild-index (an activation
-- concern, not a pre-flip one).

ALTER TABLE receipt_index ADD COLUMN ran_under_strict INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS divergence_index (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id    TEXT    NOT NULL,
    worker_id        TEXT    NOT NULL,
    worker_pubkey    TEXT    NOT NULL,
    unit_id          TEXT    NOT NULL,
    ran_under_strict INTEGER NOT NULL DEFAULT 0,
    recorded_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (worker_id, unit_id),
    FOREIGN KEY (worker_id) REFERENCES workers(worker_id)
);
CREATE INDEX divergence_index_unit_idx       ON divergence_index(unit_id);
CREATE INDEX divergence_index_experiment_idx ON divergence_index(experiment_id);
