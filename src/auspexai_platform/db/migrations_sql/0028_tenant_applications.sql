-- 0028_tenant_applications.sql — researcher-onboarding application queue
-- (researcher onboarding Option D, ratified).
--
-- `auspexai-tenant apply` runs the GitHub Device Flow client-side, then POSTs
-- an application SIGNED BY THE APPLYING KEY (RFC 9421 verified against its
-- own keyid — deliberate proof-of-possession for a not-yet-registered key).
-- The coordinator verifies the GitHub access token via the same identity
-- machinery as volunteer enrollment and resolves-or-creates the account row,
-- so every application is bound to a real IdP identity. Lifecycle:
--   pending  — submitted, awaiting maintainer review (one pending
--              application per account at a time).
--   approved — maintainer approved: a tenant is created atomically with the
--              application's pubkey bound as maintainer_pubkey and
--              tenants.account_id linked; created_tenant_id is stamped.
--   declined — maintainer declined (mandatory reason).

CREATE TABLE tenant_applications (
    application_id      TEXT PRIMARY KEY,                 -- 'tapp-<random>'
    account_id          TEXT NOT NULL,                    -- resolved-or-created account (IdP-bound)
    github_login        TEXT,                             -- login at application time (display; idp_sub is on the account)
    requested_tenant_id TEXT NOT NULL,                    -- the tenant_id the applicant wants
    contact_name        TEXT NOT NULL,
    affiliation         TEXT NOT NULL,
    research_summary    TEXT NOT NULL,
    pubkey_hex          TEXT NOT NULL,                    -- the verified applying keyid (proof-of-possession)
    status              TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|declined
    created_at          TEXT NOT NULL,
    resolved_at         TEXT,
    resolved_by         TEXT,                             -- maintainer_login
    resolution_reason   TEXT,                             -- mandatory on decline
    created_tenant_id   TEXT                              -- stamped on approve
);

CREATE INDEX tenant_applications_status_idx ON tenant_applications(status);
CREATE INDEX tenant_applications_account_idx ON tenant_applications(account_id);
CREATE INDEX tenant_applications_pubkey_idx ON tenant_applications(pubkey_hex);
