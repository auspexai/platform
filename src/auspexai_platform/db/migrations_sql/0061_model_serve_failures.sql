-- 0061_model_serve_failures.sql — GROUND TRUTH for the serve-fit verdict (the
-- "learn from failures" half of the sizing fix).
--
-- The catalog's "fits/too_big" label is an ESTIMATE (weights + KV cache + runtime;
-- serve_memory.py). When a worker actually OOMs serving a model (the Layer-1
-- refusal "insufficient GPU memory to serve <model>"), that's ground truth the
-- estimate can't argue with: the model does NOT fit a worker with that much usable
-- memory. Record the LARGEST usable-GB at which a model has been observed to OOM;
-- any worker with usable <= that is then labelled too_big for the model regardless
-- of the estimate. Self-correcting: it needs no architecture data and fixes exactly
-- the RAM-fit-not-serveable gap (a Jetson passed the RAM check, then OOM'd).
--
-- Keyed by model_id (one row per model = the worst observed OOM). max_ooomd_usable_gb
-- only ever moves UP (a bigger box that also OOM'd tightens the bound). A successful
-- serve does NOT clear it here — the estimate + a future observed-SUCCESS signal
-- handle recovery; this table is a conservative floor.
CREATE TABLE IF NOT EXISTS model_serve_failures (
    model_id             TEXT PRIMARY KEY,
    max_ooomd_usable_gb  REAL NOT NULL,   -- largest usable-GB a worker OOM'd at serving this
    last_observed_at     TEXT NOT NULL,   -- ISO-8601 UTC
    observation_count    INTEGER NOT NULL DEFAULT 1
);
