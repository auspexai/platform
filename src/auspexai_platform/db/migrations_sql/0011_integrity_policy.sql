-- 0011_integrity_policy.sql — per-experiment integrity policy (replaces
-- researcher-set replication_target).
--
-- Ratified 2026-05-24: replication_target is a platform concern, not a
-- research design parameter. The Maintainer sets integrity_policy at
-- experiment approval time; the coordinator computes replication_target
-- from it.
--
-- Policies:
--   standard — base replication_target=3 (all tiers eligible; tier floors apply)
--   high     — base replication_target=5 (higher replication for sensitive work)
--   trusted  — base replication_target=1 (only T2+ workers eligible via tier floor)

ALTER TABLE experiments ADD COLUMN integrity_policy TEXT NOT NULL DEFAULT 'standard';
