-- 0036_trust_model_policy.sql — firewall #1 equal-trust FLIP toggle (A2).
--
-- Single-row policy table (id = 1). The trust-accrual path reads
-- `equal_trust_enabled` server-authoritatively:
--
--   0 / disabled  -- trust accrues ONLY from agreement (the convergence
--                    gradient — current behavior). The default.
--   1 / enabled   -- trust accrues from PROCESS-ATTESTATION guarded by STRICT
--                    containment OR the reputation floor, regardless of
--                    agreement; a divergent-but-guarded result earns a
--                    divergence receipt (a2_equal_trust_flip_design.md).
--
-- DEFAULT IS DISABLED: the flip is the firewall-#1 ACTIVATION — an explicit
-- governance event flipped only when the A7 5-condition gate is fully green
-- (charter §8.4), never a silent default. Every change carries a recorded
-- reason; the write is audited (`trust_model_policy.update`). The integrity
-- machinery the flip consults (integrity_basis, containment, reputation floor)
-- is versioned config/code, not tunable here — only the on/off flip is.

CREATE TABLE IF NOT EXISTS trust_model_policy (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    equal_trust_enabled INTEGER NOT NULL DEFAULT 0
                        CHECK (equal_trust_enabled IN (0, 1)),
    updated_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by          TEXT,
    update_reason       TEXT
);

-- Seed the single row DISABLED (the current convergence-gradient model). IGNORE
-- so a re-run never clobbers a maintainer's live setting.
INSERT OR IGNORE INTO trust_model_policy (id, equal_trust_enabled) VALUES (1, 0);
