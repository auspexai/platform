-- Migration 0009: maintainer-applied worker quarantine
--
-- Adds a reversible "this specific worker is suspended from receiving
-- assignments" flag, separate from retirement (which is permanent and
-- forecloses re-binding the retired key per §5.15). Quarantine is the
-- operational kill switch for "this worker is misbehaving / I want to
-- pause it; reverse later if needed."
--
-- Effect on schedule: GET /workers/{id}/assignments returns 423 Locked
-- on quarantined workers; the scheduler is never asked for work on
-- their behalf. Heartbeats continue to work — the worker is still
-- "alive" and visible in operator state, just not receiving work.
--
-- Effect on receipts: quarantine doesn't touch already-issued receipts
-- (those are permanent per §5.16). It just stops new assignments,
-- which stops new receipts from accruing.
--
-- Lifting quarantine clears both columns; the worker's existing tier,
-- bindings, and history are unaffected.

ALTER TABLE workers ADD COLUMN quarantined_at TEXT;
ALTER TABLE workers ADD COLUMN quarantine_reason TEXT;
CREATE INDEX workers_quarantined_idx ON workers(quarantined_at);
