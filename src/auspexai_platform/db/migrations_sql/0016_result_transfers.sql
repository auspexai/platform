-- 0016_result_transfers.sql — proof-of-transfer / custody record (M-Results).
--
-- When a researcher collects their results (pulls the export bundle), the
-- coordinator writes a permanent, signed custody record: it proves Auspex
-- delivered exactly these results (by `result_set_root` over the consensus
-- result hashes) to exactly this collector at this time. Per policy (Terms of
-- Participation), legal responsibility for the data passes to the researcher on
-- transfer — so Auspex keeps this tiny proof forever rather than the payloads.
-- `coordinator_signature` is Ed25519 (the §5.16 receipt-signing key) over the
-- canonical record, making the record tamper-evident.

CREATE TABLE result_transfers (
    transfer_id           TEXT    PRIMARY KEY,
    experiment_id         TEXT    NOT NULL,
    tenant_id             TEXT    NOT NULL,
    collected_by_pubkey   TEXT    NOT NULL,
    collected_at          TEXT    NOT NULL,
    manifest_hash         TEXT    NOT NULL,
    result_set_root       TEXT    NOT NULL,
    receipt_count         INTEGER NOT NULL,
    coordinator_signature TEXT    NOT NULL
);

CREATE INDEX result_transfers_experiment_idx ON result_transfers(experiment_id);
