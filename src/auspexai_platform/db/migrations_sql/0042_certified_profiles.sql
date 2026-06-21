-- 0042_certified_profiles.sql — the promotion-gate certification registry
-- (RFC 0001 / Research Ethics Policy §6.7).
--
-- A coordinator-side registry of CERTIFIED starter profiles. A certification is a
-- signed, content-bound, publishable attestation that a specific RELEASED profile
-- is safe to expose to unverified researchers (Ethics §6.7.2). It is the single
-- source of truth for the gate: at submit, the coordinator looks up a submission's
-- executor package_sha256 here and, on a locked-field match (§6.7.3), the run
-- clears §6 under the profile's standing approval (§6.7.5) regardless of the
-- submitter's accrued trust tier.
--
-- Tamper-evidence (mirrors receipt_index / attestations 0022): keyed by the
-- content-addressed package_sha256 — a tenant cannot alter the executor / reducer /
-- probe-set without changing the digest — AND maintainer-written only. The
-- certificate envelope is COSE-signed (not a bare row), so the cert is
-- independently verifiable against AUTHORIZED_SIGNERS.md. Per RFC 0001 §6.7.4 the
-- independence is risk-proportionate: a LOW-risk starter cert is maintainer-token
-- authenticated + coordinator-signed + published + contestable (advisor = NULL);
-- a HIGH-risk cert additionally carries an external advisor co-signature.
--
-- This migration only ADDS an (empty) table; nothing reads it until the certify
-- CLI + the submit-time check ship — behavior-preserving on its own.

CREATE TABLE IF NOT EXISTS certified_profiles (
    package_sha256          TEXT    PRIMARY KEY,             -- content-addressed key (executor package digest)
    snapshot_version        TEXT    NOT NULL,                -- e.g. "vigiles-tenant@v0.1.0"
    tenant_id               TEXT    NOT NULL,                -- owning tenant (account-rooted provenance)
    profile_name            TEXT    NOT NULL,                -- e.g. "starter"

    -- The LOCKED envelope (§6.7.2 / §6.7.3) — matched field-by-field at submit.
    research_class          TEXT,                            -- locked
    sensitive_content_flags TEXT    NOT NULL DEFAULT '[]',   -- JSON array; must be [] for a certified starter
    model_ids               TEXT    NOT NULL DEFAULT '[]',   -- JSON array of allowed model ids
    replication_floor       INTEGER NOT NULL,                -- the certified floor (the §6.7 floor exemption rides this)
    max_units_ceiling       INTEGER,                         -- §6.7.3 "count up to a certified ceiling" backstop
    duration_hours_ceiling  REAL,                            -- locked upper bound

    -- The signed certificate (verifiable, not a bare claim).
    cose_signed_blob        BLOB    NOT NULL,                -- COSE_Sign over the canonical certificate envelope
    signing_key_pubkey_hex  TEXT    NOT NULL,                -- the signer (verified vs AUTHORIZED_SIGNERS.md roster)
    certified_by            TEXT    NOT NULL,                -- maintainer identity (from the authenticated token)
    advisor                 TEXT,                            -- external advisor co-signer (HIGH-risk only; NULL for low-risk)
    rekor_log_index         INTEGER,                         -- transparency-log anchor (nullable; backfilled like attestations)

    certified_at            TEXT    NOT NULL,                -- ISO-8601 UTC
    status                  TEXT    NOT NULL DEFAULT 'certified',  -- 'certified' | 'revoked' | 'superseded'
    revoked_at              TEXT,
    revoked_reason          TEXT
);

-- Resolve the current certification for a tenant's profile (re-certify a new
-- release; surface what's certified). The submit-time hot path is the PRIMARY KEY
-- lookup by package_sha256 above.
CREATE INDEX IF NOT EXISTS idx_certified_profiles_tenant_profile
    ON certified_profiles (tenant_id, profile_name, status);
