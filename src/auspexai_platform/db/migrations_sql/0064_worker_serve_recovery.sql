-- 0064_worker_serve_recovery.sql — per-worker serve-recovery, so a REMEDIATED node can
-- retry a model BEFORE the model-level OOM exclusion's 6h cooldown lifts.
--
-- The observed-OOM guard (model_serve_failures) excludes a model from EVERY worker with
-- usable <= the OOM'd size — a safe-but-broad default (better to over-bench than crash a
-- worker). But the exclusion is model-level, while a volunteer's fix ("sudo sync &&
-- drop_caches; systemctl restart ollama") is node-level: the operator fixes THEIR box.
-- Without a per-worker recovery, the fixed node stays benched the full 6h and — worse in
-- a volunteer network — a fleet-wide reset would re-offer the model to OTHER, un-remediated
-- nodes and crash them ("my fix causes your OOM").
--
-- This records that a SPECIFIC worker remediated after a model OOM'd on it. The fit verdict
-- (serve_fits) then SHADOWS the model-level exclusion for that one worker if its
-- recovered_at is newer than the model's last_observed_at — a one-shot probe: a serve
-- SUCCESS tempers the shared exclusion; a re-OOM writes a newer last_observed_at and the
-- shadow lifts. Exclude broadly, recover surgically.
CREATE TABLE IF NOT EXISTS worker_serve_recovery (
    worker_id    TEXT NOT NULL,
    model_id     TEXT NOT NULL,
    recovered_at TEXT NOT NULL,
    PRIMARY KEY (worker_id, model_id)
);
