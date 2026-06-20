-- 0040_replication_target_floor.sql — C14 replication-model redesign, Phase 1.
--
-- Decouples the replication COUNT from the 3-value integrity_policy enum so repl-2
-- (a valid EXACT hash-agreement cross-check) is expressible. The 1/3/5 ladder rounded
-- repl-2 up to repl-3 (scheduler/__init__.py: `effective <= 3 -> STANDARD`), which
-- stalls a 2-worker fleet — the Vigiles keystone was forced to process_only. From here
-- `replication_target` is the SOURCE OF TRUTH for the count; integrity_policy stays as
-- a DERIVED coarse label. `replication_floor` is the minimum corroboration the experiment
-- accepts — set at submit (default 2 = a real cross-check) but only CONSUMED by the
-- capacity-aware completion (regime 2) in a later increment. See
-- replication_model_redesign_design.md.
--
-- Backfill PRESERVES current behavior: target = floor = the old policy's replication
-- ({trusted:1, standard:3, high:5}), so existing experiments complete exactly as before.

ALTER TABLE experiments ADD COLUMN replication_target INTEGER NOT NULL DEFAULT 3;
ALTER TABLE experiments ADD COLUMN replication_floor INTEGER NOT NULL DEFAULT 2;

UPDATE experiments SET replication_target = CASE integrity_policy
    WHEN 'trusted' THEN 1
    WHEN 'standard' THEN 3
    WHEN 'high' THEN 5
    ELSE 3 END;
UPDATE experiments SET replication_floor = replication_target;
