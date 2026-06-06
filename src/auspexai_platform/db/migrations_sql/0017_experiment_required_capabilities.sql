-- 0017_experiment_required_capabilities.sql — #30 capability-matching (M1).
--
-- An experiment may require workers to hold specific locally-staged models
-- (BYOM, §5.8). Derived at submit from the manifest's `models[]` entries whose
-- `local_weights_required` is true, keyed by the worker store model_id
-- (<repo-slug>-<quant>, an exact match — hash-agreement consensus requires every
-- replica run the SAME quant). NULL / '{}' = no requirement: every worker is
-- eligible (the pre-M1 behavior), so this column is additive + backward-compatible.
-- Phase-1 populates only the "models" key; the JSON shape leaves room for other
-- capability dimensions (os / gpu / ...) without another migration.

ALTER TABLE experiments ADD COLUMN required_capabilities_json TEXT;
