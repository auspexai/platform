-- 0034_experiment_required_containment.sql — §41 containment floor. The minimum
-- sandbox containment a unit must run under, seeded at submit from the tenant's
-- trust tier (the host-isolation analogue of the A' replication floor on
-- experiments.integrity_policy). The scheduler routes a unit only to a worker
-- whose reported sandbox policy meets-or-exceeds this. 'permissive' is the
-- Phase-1 default (the floor activates via AUSPEXAI_CONTAINMENT_STRICT_BELOW_TIER
-- when untrusted tenants arrive); existing rows backfill to permissive.
ALTER TABLE experiments ADD COLUMN required_containment TEXT NOT NULL DEFAULT 'permissive';
