-- 0057_receipt_outcomes.sql — control-DB record of results that will NEVER
-- receive a canonical receipt (D22-B teardown-race fix).
--
-- The receipt_index (0007) records POSITIVE outcomes: one row per ISSUED
-- receipt. It is read by trust-accounting queries (list_for_worker,
-- list_for_account, account_contributor_worker_ids) so it must contain ONLY
-- issued receipts — a negative marker there would inflate contribution counts.
-- This sibling table — modelled on divergence_index (0037) and
-- schema_rejection_index (0052) — records the NEGATIVE terminal outcome: a
-- submitted (worker, result) pair for which no receipt was, or ever will be,
-- issued.
--
-- Two writers:
--   * issuance.py, at consensus finalization — every submitted result of a
--     unit that did not win a receipt (quorum disagreed, or this replica was
--     an outlier). reason = 'quorum_disagreed' | 'diverged_from_consensus'.
--   * the abort/terminal cascade (scheduler/teardown.py) — every still-
--     outstanding result of an experiment that went terminal (aborted /
--     archived) before its unit reached consensus. reason = 'experiment_<status>'.
--
-- The canonical-receipt endpoint consults receipt_index first (issued → 200),
-- then this table (terminal → 410 receipt_will_not_issue), else 404 (still
-- pending → transient). This lets the worker's M7-tail backfill loop STOP
-- polling a receipt that will never come, instead of a perpetual 404 loop.
--
-- Idempotent writes (INSERT OR IGNORE on UNIQUE (worker_id, result_id)), so a
-- re-finalization / re-run of the settle sweep is a no-op.

CREATE TABLE IF NOT EXISTS receipt_outcomes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id       TEXT    NOT NULL,
    result_id       TEXT    NOT NULL,
    experiment_id   TEXT    NOT NULL,
    unit_id         TEXT,
    outcome         TEXT    NOT NULL,   -- 'no_receipt' (consensus, unselected) | 'experiment_terminal' (aborted/archived)
    reason          TEXT,               -- quorum_disagreed | diverged_from_consensus | experiment_aborted | experiment_archived
    recorded_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (worker_id, result_id),
    FOREIGN KEY (worker_id) REFERENCES workers(worker_id)
);

CREATE INDEX IF NOT EXISTS receipt_outcomes_experiment_idx ON receipt_outcomes(experiment_id);
CREATE INDEX IF NOT EXISTS receipt_outcomes_result_idx     ON receipt_outcomes(result_id);
