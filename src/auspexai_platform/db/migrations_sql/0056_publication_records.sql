-- G6+F4 (ratified 2026-07-06): coordinator-side records of researcher
-- publication actions. Each row is written AT AUTHORIZATION TIME and mixes
-- two epistemic classes the surfaces must keep distinct:
--   COORDINATOR FACTS: standing_at_issue, attestation roots + Rekor ids
--     (copied from the coordinator's own attestation records — ratified Q2);
--   RESEARCHER CLAIMS: the signed summary (peak/breadth/reference for
--     benchmarks; the coordinator never re-scores — descriptive-only line).
-- kind: 'benchmark' | 'doi'. DOI rows additionally carry the minted DOI.
CREATE TABLE IF NOT EXISTS publication_records (
    record_id           TEXT    PRIMARY KEY,
    experiment_id       TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    tenant_id           TEXT    NOT NULL,
    publisher_pubkey    TEXT    NOT NULL,
    standing_at_issue   INTEGER NOT NULL,
    summary_json        TEXT    NOT NULL,
    obs_merkle_root     TEXT,
    obs_rekor_uuid      TEXT,
    ref_merkle_root     TEXT,
    ref_rekor_uuid      TEXT,
    doi                 TEXT,
    created_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_publication_records_experiment
    ON publication_records (experiment_id, kind);
