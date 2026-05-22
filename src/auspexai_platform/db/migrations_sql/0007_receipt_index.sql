-- 0007_receipt_index.sql — control-DB index of issued receipts.
--
-- M7c stores the canonical receipt rows (full COSE-Sign1 + CBOR payload)
-- on the per-job DB next to the work_units and results they attest. Cross-
-- experiment queries — "fetch this receipt by id," "list all receipts for
-- this account," "list all receipts for this worker" — would otherwise
-- need to walk every per-job DB linearly. The receipt_index table is a
-- denormalized control-DB pointer that makes those queries O(1) /
-- O(receipts-per-key) instead.
--
-- Populated alongside each receipt insertion (M7c hook) so the index
-- never lags the per-job storage. M7c does both writes; partial failure
-- (per-job insert succeeds, index insert fails) is recoverable because
-- the per-job DB is the single source of truth — a sweep can rebuild
-- the index from per-job DBs if needed.
--
-- worker_pubkey is denormalized here (vs joining workers) so the
-- account-scoped + worker-scoped queries don't need a cross-table join
-- in the hot path. workers.pubkey_hex is the canonical source.
--
-- No FK on experiment_id (no `experiments(experiment_id)` FK target
-- exists in this file; the table is in 0002_experiments.sql; FK across
-- migrations works in SQLite but we keep this table independent of
-- experiment lifecycle — a deleted experiment shouldn't cascade and
-- destroy the receipt index entries since the per-job DB persists).

CREATE TABLE receipt_index (
    receipt_id      TEXT    PRIMARY KEY,                       -- 'rcpt-<...>'
    experiment_id   TEXT    NOT NULL,                          -- coord's exp- id
    worker_id       TEXT    NOT NULL,
    worker_pubkey   TEXT    NOT NULL,                          -- 64 lowercase hex
    issued_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (worker_id) REFERENCES workers(worker_id)
);

CREATE INDEX receipt_index_worker_idx     ON receipt_index(worker_id);
CREATE INDEX receipt_index_pubkey_idx     ON receipt_index(worker_pubkey);
CREATE INDEX receipt_index_experiment_idx ON receipt_index(experiment_id);
CREATE INDEX receipt_index_issued_idx     ON receipt_index(issued_at);
