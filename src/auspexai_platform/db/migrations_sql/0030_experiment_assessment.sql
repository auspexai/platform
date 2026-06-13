-- 0030_experiment_assessment.sql — §9 #48 admission-assessment provenance.
--
-- The class-by-tier auto-approval decision + its provenance, denormalized onto
-- the experiment row so the review/auto queues + the dashboard lifecycle
-- timeline read it without re-parsing the opaque manifest blob. All columns are
-- additive + NULLable: pre-migration rows read as unassessed.
--
--   research_class            -- mirrors the manifest's declared class (or NULL)
--   assessment_decision       -- 'auto' | 'review' (| 'declined' for a later override)
--   assessment_tier           -- the tenant's account tier AT assessment time
--   assessment_envelope_json  -- the per-check EnvelopeResult, as JSON
--   assessment_rationale      -- the one-line human-readable reason
--   assessed_at / assessed_by -- when + which maintainer/agent login decided
--
-- NB increment 1 does NOT add ExperimentStatus values: a 'review' decision
-- leaves the experiment in 'submitted' (the assessment is metadata; the
-- maintainer approves from 'submitted' as today). 'assessed' / 'provisioning'
-- land with the lifecycle-timeline surfacing increment, so the transition map
-- is untouched here.

ALTER TABLE experiments ADD COLUMN research_class TEXT;
ALTER TABLE experiments ADD COLUMN assessment_decision TEXT;
ALTER TABLE experiments ADD COLUMN assessment_tier INTEGER;
ALTER TABLE experiments ADD COLUMN assessment_envelope_json TEXT;
ALTER TABLE experiments ADD COLUMN assessment_rationale TEXT;
ALTER TABLE experiments ADD COLUMN assessed_at TEXT;
ALTER TABLE experiments ADD COLUMN assessed_by TEXT;
