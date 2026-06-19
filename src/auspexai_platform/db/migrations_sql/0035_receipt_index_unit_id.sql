-- 0035_receipt_index_unit_id.sql — add unit_id to receipt_index for the
-- firewall #3 (A4) independence floor.
--
-- The A4 floor counts trust as DISTINCT WORK UNITS corroborated per ACCOUNT,
-- not raw receipts: an operator's N workers under one account corroborating the
-- same unit must earn ONE account's worth of trust, not N (closes within-account
-- receipt-farming toward T2 / the vouch gate). The per-account trust query
-- COUNT(DISTINCT COALESCE(unit_id, receipt_id)) so rows created before this
-- migration (unit_id NULL) keep their prior one-each behavior — the dedup only
-- engages on rows carrying unit_id. New issuance always sets it; the
-- `receipts rebuild-index` CLI backfills it from the per-job results table.
--
-- This is the TRUST/independence dimension only. Completion/consensus
-- (agreeing_workers) stays per-pubkey, so the floor never deadlocks a
-- single-account fleet (a4_independence_floor_design.md).

ALTER TABLE receipt_index ADD COLUMN unit_id TEXT;

CREATE INDEX receipt_index_unit_idx ON receipt_index(unit_id);
