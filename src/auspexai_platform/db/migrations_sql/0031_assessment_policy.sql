-- 0031_assessment_policy.sql — §9 #48 increment 4: the runtime-tunable
-- auto-approval gate (the maintainer's dashboard kill-switch).
--
-- A single-row policy table (id = 1). `decide()` reads it server-authoritatively
-- via an injected reader; the operator console writes it. Two knobs:
--
--   auto_approval_enabled  -- master switch. 0 => NOTHING auto-approves; every
--                             assessment routes to human review (auto-triage
--                             still runs — the experiment is classified +
--                             envelope-checked, just not auto-approved).
--   auto_approve_min_tier  -- the minimum tenant account tier eligible for
--                             auto-approval when enabled (default T2).
--
-- DEFAULT IS DISABLED. Autonomy is opt-in by the maintainer from the console,
-- never on by deploy: enabling auto-approval is a deliberate governance action,
-- so it must be a dashboard click with a recorded reason — not a migration
-- side-effect. The agent (systemd timer) can run while this is off; it just
-- triages into the review queue.

CREATE TABLE IF NOT EXISTS assessment_policy (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    auto_approval_enabled INTEGER NOT NULL DEFAULT 0,
    auto_approve_min_tier INTEGER NOT NULL DEFAULT 2,
    updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by            TEXT,
    update_reason         TEXT
);

-- Seed the single row disabled. IGNORE so a re-run never clobbers a maintainer's
-- live setting.
INSERT OR IGNORE INTO assessment_policy (id, auto_approval_enabled, auto_approve_min_tier)
VALUES (1, 0, 2);
