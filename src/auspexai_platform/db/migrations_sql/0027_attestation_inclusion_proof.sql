-- 0027_attestation_inclusion_proof.sql — EB-1 (§9 #47): persist the Rekor
-- inclusion proof alongside the anchor so the evidence bundle is
-- offline-verifiable FOREVER without a live Rekor fetch.
--
-- Captured from the create-entry response (verification.inclusionProof:
-- checkpoint + hashes + logIndex + rootHash + treeSize) at anchor time —
-- either the completion-path record() or the hourly backfill-rekor sweep.
-- NULL = anchored before this migration (or lab-mode): the SDK falls back to
-- the online inclusion check exactly as before, so the column is additive.

ALTER TABLE attestations ADD COLUMN rekor_inclusion_proof_json TEXT;
