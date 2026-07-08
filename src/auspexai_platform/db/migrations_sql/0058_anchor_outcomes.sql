-- 0058_anchor_outcomes.sql — Rekor anchoring retry state with a terminal
-- 'un-anchorable' verdict (A11 reaper-audit follow-up; see
-- persistent_artifact_reaper_audit.md).
--
-- The Rekor backfill (receipts/attestation_backfill.py) re-scans rows still
-- carrying the placeholder (rekor_log_index=0) every run and re-submits them. A
-- row Rekor STRUCTURALLY rejects (the cose/hashedrekord kinds reject Ed25519 — a
-- deterministic 400) would be re-submitted FOREVER: the D22-B perpetual-retry
-- shape, at the work layer. This sibling table — modelled on receipt_outcomes
-- (0057) — records per-artifact anchoring FAILURE state so the backfill can give
-- up on a genuinely un-anchorable row while NEVER abandoning one for an outage.
--
-- `terminal` is set ONLY after N confirmed PERMANENT rejections (a 4xx that is
-- not 408/429). TRANSIENT failures (5xx / rate-limit / timeout / connection / a
-- degraded placeholder response) increment `attempts` for visibility but never
-- go terminal — so a long Rekor outage is ridden out, not abandoned. On a
-- successful anchor the row is cleared (transient state self-heals).

CREATE TABLE IF NOT EXISTS anchor_outcomes (
    artifact_type       TEXT    NOT NULL,   -- 'attestation' | 'pre_registration' | 'deviation'
    artifact_id         TEXT    NOT NULL,   -- attestation_id / experiment_id / deviation_id
    attempts            INTEGER NOT NULL DEFAULT 0,   -- total failed attempts (visibility)
    permanent_failures  INTEGER NOT NULL DEFAULT 0,   -- confirmed 4xx rejections (drive terminal)
    terminal            INTEGER NOT NULL DEFAULT 0,   -- 1 = un-anchorable; the backfill stops retrying
    last_error          TEXT,
    first_attempt_at    TEXT    NOT NULL,
    last_attempt_at     TEXT    NOT NULL,
    PRIMARY KEY (artifact_type, artifact_id)
);

CREATE INDEX IF NOT EXISTS anchor_outcomes_terminal_idx ON anchor_outcomes(artifact_type, terminal);
