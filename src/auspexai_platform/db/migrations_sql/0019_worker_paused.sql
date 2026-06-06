-- 0019_worker_paused.sql — operator "pause" lever for the scheduler view (M4).
--
-- Distinct from quarantine: pause is an OPERATIONAL pause ("stop feeding this
-- worker"), NOT a fault/trust signal — so it has its own column and audit action
-- and is NOT surfaced to the volunteer as a quarantine/trust event. A paused
-- worker stays enrolled + may keep heartbeating, but is excluded from the
-- active-and-available set: the scheduler skips it (`pick_for_worker` → None) and
-- it drops out of count_active / count_capable / model_inventory_counts (network
-- capacity + catalog reflect only workers actually available for work). Cleared
-- by unpause. NULL = not paused (the default for every existing worker).

ALTER TABLE workers ADD COLUMN paused_at TEXT;
