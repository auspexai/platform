-- 0062_worker_reservations.sql — capacity-aware scheduling (reservation model).
--
-- A worker is reserved to AT MOST ONE experiment at a time, so an admitted
-- experiment runs UNINTERRUPTED on a stable worker set: no mid-run model reloads
-- (which would confound a drift measurement) and no per-unit thrash when concurrent
-- experiments demand different models than the constrained fleet can hold. Experiments
-- that can't be granted a floor-meeting reservation QUEUE (approved, "queued" phase)
-- until a reservation frees.
--
-- The reservation set is RECONCILED continuously against the LIVE fleet (workers
-- join, pause, retire): a reservation held by a now-inactive worker is released (so a
-- paused/offline worker is never left pegged to a maybe-finished experiment and
-- stranded), and an experiment left under its replication target reserves a free
-- REPLACEMENT so it continues rather than hangs. A reservation for a terminal (or
-- no-work) experiment is released too.
--
-- REAPED (persistence_registry): rows are transient scheduling state — deleted on
-- release; nothing accumulates.
CREATE TABLE IF NOT EXISTS worker_reservations (
    worker_id     TEXT PRIMARY KEY,   -- one experiment per worker at a time
    experiment_id TEXT NOT NULL,
    reserved_at   TEXT NOT NULL       -- ISO-8601 UTC
);
CREATE INDEX IF NOT EXISTS worker_reservations_experiment_idx
    ON worker_reservations(experiment_id);
