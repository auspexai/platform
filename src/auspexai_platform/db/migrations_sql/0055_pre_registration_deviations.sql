-- 0055_pre_registration_deviations.sql — D16.2-D: append-only deviation records
-- (preregistration_design.md §5).
--
-- Real research deviates; the integrity rule is that a deviation is a NEW,
-- separately-timestamped, signed record referencing the original — never a
-- silent edit (the original pre_registrations row is immutable). Each row
-- carries TWO signatures: the TENANT's (the researcher's own declaration of
-- what changed and why — the declarer is accountable) and the coordinator's
-- COSE anchor statement (binding the content hash + the coordinator-observed
-- declared_at), Rekor-anchored by the same hourly sweep so WHEN the deviation
-- was declared is publicly provable. Exploratory analysis is allowed and
-- valuable — it just may not masquerade as confirmatory; these records are how
-- a reader tells the difference.
--
-- Append-only by construction: no UPDATE path in the repository; multiple
-- deviations per experiment are expected (each its own row + anchor). Mirrors
-- the pre_registrations (0054) anchor conventions.

CREATE TABLE pre_registration_deviations (
    deviation_id             TEXT    PRIMARY KEY,                  -- 'dev-<...>'
    experiment_id            TEXT    NOT NULL,
    tenant_id                TEXT    NOT NULL,
    manifest_hash            TEXT    NOT NULL,                     -- the ORIGINAL design's hash
    what_changed             TEXT    NOT NULL,
    why                      TEXT    NOT NULL,
    tenant_pubkey_hex        TEXT    NOT NULL,                     -- the declarer
    tenant_signature_b64     TEXT    NOT NULL,                     -- over the canonical declaration
    cose_signed_blob         BLOB    NOT NULL,                     -- the coordinator anchor statement
    signing_key_pubkey_hex   TEXT    NOT NULL,
    declared_at              TEXT    NOT NULL,                     -- coordinator-observed
    rekor_log_index          INTEGER NOT NULL DEFAULT 0,           -- 0 = not yet anchored
    rekor_entry_uuid         TEXT    NOT NULL DEFAULT 'lab-mode-no-rekor',
    rekor_inclusion_proof_json TEXT
);
CREATE INDEX pre_registration_deviations_experiment_idx
    ON pre_registration_deviations(experiment_id);
