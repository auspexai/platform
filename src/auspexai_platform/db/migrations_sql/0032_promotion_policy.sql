-- 0032_promotion_policy.sql — §6.2 per-transition promotion mode (the
-- maintainer's manual / auto switch for account tier escalation).
--
-- Single-row policy table (id = 1). `_maybe_auto_promote` reads `t1_t2_mode`
-- server-authoritatively; the operator console writes it. Two modes:
--
--   auto_with_override  -- (default) the system auto-promotes a T1 account to T2
--                          when ALL automated gates pass (receipts + breadth +
--                          time window) AND the identity gate is satisfied; the
--                          maintainer may still block / reverse / hand-promote.
--   manual              -- nothing auto-promotes. Qualifying accounts surface in
--                          the promotion queue (ready_for_human_review) and wait
--                          for a maintainer click.
--
-- T2->T3 is ALWAYS manual ("personally vetted" can't be automated) and is not
-- represented here. The numeric THRESHOLDS the gates compare against are
-- versioned config (AUSPEXAI_TIER_T2_*), not runtime — only the mode is tunable
-- here.
--
-- DEFAULT IS manual: human-in-the-loop is the ratified default (governance
-- charter §6 decision 3 — the visible human checkpoint is a stabilizing
-- re-anchor, not mere friction). Switching to `auto_with_override` is a
-- deliberate action gated on the firewall-conformance check (charter §8.4), not
-- a single population proxy. Every change carries a recorded reason.

CREATE TABLE IF NOT EXISTS promotion_policy (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    t1_t2_mode    TEXT NOT NULL DEFAULT 'manual'
                  CHECK (t1_t2_mode IN ('manual', 'auto_with_override')),
    updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by    TEXT,
    update_reason TEXT
);

-- Seed the single row at the human-in-the-loop default. IGNORE so a re-run
-- never clobbers a maintainer's live setting.
INSERT OR IGNORE INTO promotion_policy (id, t1_t2_mode) VALUES (1, 'manual');
