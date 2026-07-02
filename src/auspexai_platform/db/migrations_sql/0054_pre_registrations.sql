-- 0054_pre_registrations.sql — D16.2: the submit-time pre-registration anchor
-- (preregistration_design.md §4, the "strong tier").
--
-- One row per experiment whose signed manifest declared a `pre_registration`
-- block. Written AT SUBMIT: the coordinator COSE-signs a predicate binding the
-- manifest hash (the design lives inside the content-addressed manifest) + the
-- block + the submit time, persists it here with the not-yet-anchored
-- placeholder, and the hourly Rekor backfill (A2, extended) anchors it. The
-- anchor's timestamp precedes the result attestation's completion-time anchor,
-- making `design ≺ data` publicly provable — no trust in the coordinator's
-- clock required.
--
-- Required for a citable/DOI'd result (§7 — a TECHNICAL gate, ratified
-- no-waiver 2026-07-01): DOI issuance refuses without this row's hash chain.
-- Mirrors the attestations table (0022) conventions: no FK (durable historical
-- record), placeholder anchor sentinels, one row per experiment.

CREATE TABLE pre_registrations (
    experiment_id            TEXT    PRIMARY KEY,                  -- coord's exp- id
    tenant_id                TEXT    NOT NULL,
    tenant_experiment_label  TEXT    NOT NULL,
    manifest_hash            TEXT    NOT NULL,                     -- the anchored design
    cose_signed_blob         BLOB    NOT NULL,                     -- the canonical artifact
    signing_key_pubkey_hex   TEXT    NOT NULL,
    submitted_at             TEXT    NOT NULL,                     -- coordinator-observed
    rekor_log_index          INTEGER NOT NULL DEFAULT 0,           -- 0 = not yet anchored
    rekor_entry_uuid         TEXT    NOT NULL DEFAULT 'lab-mode-no-rekor',
    rekor_inclusion_proof_json TEXT                                -- captured at anchor time
);
