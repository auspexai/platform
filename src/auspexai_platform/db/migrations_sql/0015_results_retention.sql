-- 0015_results_retention.sql — M-Results per-experiment retention controls.
--
-- Result payloads live in per-job DBs (db/per_job.py); these control-DB columns
-- are the per-experiment *policy* the age-off sweep reads:
--   raw_payload_ttl_days   — T-X (raw replica) TTL post-anchor; NULL = platform default (30d)
--   consensus_ttl_days     — T-C (consensus) TTL after collection; NULL = platform default
--   retention_hold         — when 1, the sweep skips this experiment entirely
--                            (audit/legal hold — keep the org's own copy)
--   retention_hold_reason  — mandatory reason captured when a hold is placed
--   results_collected_at   — the offload anchor: stamped when the researcher pulls
--                            the export bundle (custody transferred). Age-off is
--                            collection-anchored; never-collected data is kept.

ALTER TABLE experiments ADD COLUMN raw_payload_ttl_days INTEGER;
ALTER TABLE experiments ADD COLUMN consensus_ttl_days INTEGER;
ALTER TABLE experiments ADD COLUMN retention_hold INTEGER NOT NULL DEFAULT 0;
ALTER TABLE experiments ADD COLUMN retention_hold_reason TEXT;
ALTER TABLE experiments ADD COLUMN results_collected_at TEXT;
