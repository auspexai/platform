-- 0038_account_public_attribution.sql — System B: public-citation opt-in (D).
--
-- A volunteer's contribution is already recognized on the integrity surfaces via
-- the CRYPTOGRAPHIC linkages (receipts → footprint independence) — anonymously,
-- by design. `public_attribution` is the SEPARATE, opt-in consent to also be
-- NAMED in the PUBLIC CITATION of work they contribute to (the DOI'd result's
-- contributor list / a paper's acknowledgments). Default 0 = not named: the
-- citation aggregates them anonymously. `attribution_name` is how they wish to be
-- credited (falls back to display_name, then a generic, when null).
--
-- Auth-consent (the GitHub linkage) is NOT attribution-consent — hence an
-- explicit, default-OFF flag. See trust_artifacts_purpose_audience_surface.md
-- (ratified 2026-06-19) and the on-ramp arc.

ALTER TABLE accounts ADD COLUMN public_attribution INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN attribution_name TEXT;
