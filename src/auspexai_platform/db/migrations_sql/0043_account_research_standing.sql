-- 0043_account_research_standing.sql — D9 Phase 4: the researcher research-standing
-- tier (R0–R3), the Vigiles on-ramp ladder.
--
-- ORTHOGONAL to trust_tier (compute T0–T3): research_standing gates BYOT (R2+) and
-- experiment-risk-class eligibility (R3 → high-risk). A bound account is R1 (OAuth-
-- verified) by default; R0 is the no-account state (SDK installed, unverified).
--
-- R1→R2 and R2→R3 are HUMAN promotions (ethics review / maintainer vetting), NEVER
-- auto-promoted — the standing SUMMARY (recomputed from attested experiment history,
-- not stored) only earns the review. Stored INTEGER so >=/<= gating works.
-- See vigiles_onramp_phase4_design.md §0/§1.

ALTER TABLE accounts ADD COLUMN research_standing INTEGER NOT NULL DEFAULT 1;
