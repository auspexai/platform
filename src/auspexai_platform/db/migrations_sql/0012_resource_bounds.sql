-- 0012_resource_bounds.sql — per-experiment resource bounds set by Maintainer
-- at approval time.
--
-- Ratified 2026-05-24: prevents resource abuse by researchers (oversized
-- work units, pool monopolization). Maintainer sets bounds alongside
-- integrity_policy at experiment approval.
--
-- Columns:
--   max_unit_duration_seconds — wall-clock cap per work unit (NULL = platform default)
--   max_units                — total work-unit count cap for the experiment (NULL = no cap)
--   max_concurrent_assignments — max simultaneous worker assignments (NULL = no cap)
--   max_payload_bytes        — per-unit payload size limit (NULL = platform default)

ALTER TABLE experiments ADD COLUMN max_unit_duration_seconds INTEGER;
ALTER TABLE experiments ADD COLUMN max_units INTEGER;
ALTER TABLE experiments ADD COLUMN max_concurrent_assignments INTEGER;
ALTER TABLE experiments ADD COLUMN max_payload_bytes INTEGER;
