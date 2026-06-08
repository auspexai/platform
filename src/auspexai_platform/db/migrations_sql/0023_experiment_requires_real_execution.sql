-- 0023_experiment_requires_real_execution.sql — consensus-safe routing for
-- real-execution experiments that declare NO local weights (audit 2026-06-08).
--
-- `worker_satisfies` keys "real-execution → provisioned-only" routing off the
-- presence of a `models` requirement (M9 leg 4). A tenant whose executor runs
-- real code but declares no local weights would otherwise route to
-- synthetic-mode workers that ECHO the input — and an all-synthetic fleet would
-- echo identically and reach a FALSE consensus + receipt. This explicit flag,
-- derived at submit from the manifest's top-level `requires_real_execution`,
-- lets such an experiment require provisioned-mode workers even with no model
-- requirement. 0 = old behavior (every worker eligible) — additive +
-- backward-compatible; existing rows default to 0.

ALTER TABLE experiments ADD COLUMN requires_real_execution INTEGER NOT NULL DEFAULT 0;
