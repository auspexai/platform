-- 0063_serve_failures_rate_aware.sql — make the observed-OOM ground truth RATE-AWARE
-- and SUCCESS-TEMPERED, so a fit-but-flaky worker isn't benched forever by one OOM.
--
-- 0061 recorded only OOMs and excluded a worker permanently once a model OOM'd at its
-- size. But a borderline model on a memory-constrained worker (e.g. qwen3-1.7b on a
-- 4.44 GB Jetson) SERVES most of the time and OOMs only under transient memory pressure
-- — it delivered dozens of results AND OOM'd a few times. A once-OOM-forever rule then
-- permanently excludes a worker that demonstrably serves the model.
--
-- Two signals fix this (see ModelServeFailureRepository.oom_thresholds):
--   * success_count — a serve SUCCESS by a worker in the excluded class (usable <= the
--     OOM'd size) tempers the exclusion; the model is only treated as too_big when OOMs
--     DOMINATE (rate >= cutoff), not on a single flaky failure.
--   * staleness — `last_observed_at` gates exclusion by recency: an OOM the fleet hasn't
--     reproduced within the cooldown no longer excludes, so the model is retried (and a
--     stale, possibly-transient OOM can't bench a worker indefinitely). This also breaks
--     the chicken-and-egg — an excluded model can't serve to earn successes, so a stale
--     record must lift on its own to give it the retry that then records those successes.
ALTER TABLE model_serve_failures ADD COLUMN success_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE model_serve_failures ADD COLUMN last_success_at TEXT;
