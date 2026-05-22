-- 0008_receipt_index_result_id.sql — add result_id to receipt_index for M7-tail.
--
-- M7-tail's worker-side fetch loop needs to look up a receipt by
-- (worker_id, result_id) — the worker tracks result_id natively from the
-- M6d submit_result response, but doesn't know the receipt_id at the time
-- it asks for the canonical blob. Adding result_id to the index makes
-- that lookup a single-table O(1) hit instead of requiring a per-job-DB
-- scan + JSON match on work_unit_ids.
--
-- The column is nullable because rows created before this migration
-- (e.g., M7c receipts indexed before M7-tail shipped) don't have it. New
-- receipt-index rows always carry result_id once M7-tail is in place.
-- A backfill from per-job-DB receipts is left as a future operator task
-- if needed at lab altitude.

ALTER TABLE receipt_index ADD COLUMN result_id TEXT;

CREATE INDEX receipt_index_result_idx ON receipt_index(result_id);
