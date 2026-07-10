-- 0060_doi_mints.sql — crash-safe bookkeeping for the Zenodo DOI mint, so the
-- mint is idempotent + resumable.
--
-- The mint is a multi-step external transaction (create draft → reserve DOI →
-- upload attestation.json → publish). Any failure AFTER the irreversible publish
-- but BEFORE we persist the DOI (e.g. the final HTTP response is lost to a
-- Cloudflare 5xx) would, on a naive retry, create a SECOND record and mint a
-- SECOND real DOI for the same result — a permanent duplicate + a gaming vector.
-- A failure mid-draft orphans a Zenodo draft and, on retry, reserves yet another
-- DOI.
--
-- This table is the local record of the in-flight/completed mint, one row per
-- experiment. The Zenodo record id + reserved DOI are persisted the moment the
-- draft is reserved — BEFORE publish — so a retry reconciles against Zenodo
-- (already published → return that DOI, no duplicate; still a draft → resume the
-- same draft, no new orphan) instead of minting anew. The reserved DOI is known
-- pre-publish (Zenodo reserves it on the draft), which is what makes exactly-once
-- possible.

CREATE TABLE IF NOT EXISTS doi_mints (
    experiment_id   TEXT    PRIMARY KEY,
    attestation_id  TEXT    NOT NULL,
    record_id       TEXT,               -- Zenodo internal record id (stable across draft→published)
    reserved_doi    TEXT,               -- DOI reserved on the draft (known before publish)
    status          TEXT    NOT NULL,   -- draft | published
    doi             TEXT,               -- final published DOI (normally == reserved_doi)
    record_url      TEXT,
    mode            TEXT,               -- sandbox | production
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (experiment_id) REFERENCES experiments(experiment_id)
);
