-- 0005_experiment_lifecycle.sql — M6e additions to the experiments table.
--
-- Adds three columns:
--   submissions_finalized   — researcher (or maintainer) flips this when the
--                             tenant's work-unit submission stream is done.
--                             POST /experiments/{id}/work-units 409s when
--                             true. Auto-complete only fires after this flag
--                             is set AND all units complete.
--   last_action_at          — wall-clock time of the most recent state-
--                             changing action (status transition OR finalize).
--                             Populated by ExperimentRepository.update_status
--                             and finalize_submissions.
--   last_action_by_class    — credential class that triggered the most recent
--                             action: 'maintainer' | 'researcher' | 'worker' |
--                             'anonymous' | 'system'. SYSTEM is the new
--                             coordinator-driven actor (M6e auto-complete).
--
-- All three are nullable (last_action_*) or have safe defaults
-- (submissions_finalized=0) so existing M5+ experiments load cleanly.


ALTER TABLE experiments ADD COLUMN submissions_finalized INTEGER NOT NULL DEFAULT 0
    CHECK (submissions_finalized IN (0, 1));
ALTER TABLE experiments ADD COLUMN last_action_at TEXT;
ALTER TABLE experiments ADD COLUMN last_action_by_class TEXT;
