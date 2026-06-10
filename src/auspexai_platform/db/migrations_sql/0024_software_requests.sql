-- 0024_software_requests.sql — code-plane requirements pipeline (§9 #46).
--
-- The software analog of 0018's model_requests demand board. A researcher
-- signals that an experiment needs a capability the worker baseline does not
-- provide (e.g. an inference backend, a new runtime). Unlike model requests
-- there is no "available" auto-status — code-plane requests always enter the
-- maintainer review queue. Lifecycle:
--   pending  — submitted, awaiting assessment + review.
--   assessed — a dependencies/security/alternatives assessment is attached
--              (assessment_draft=1 marks an unratified auto-draft; a
--              maintainer ratifies by re-attaching with draft=0).
--   approved — maintainer approved (mandatory reason; approving without a
--              ratified assessment is allowed but recorded as a gate
--              override in the audit log).
--   declined — maintainer declined (mandatory reason).
--   released — a recorded release (0025) names this request in
--              fulfils_request_ids; release_version is stamped.

CREATE TABLE software_requests (
    request_id         TEXT    PRIMARY KEY,                 -- 'swr-<random>'
    tenant_id          TEXT    NOT NULL,                    -- requesting researcher's tenant
    title              TEXT    NOT NULL,                    -- short capability name
    description        TEXT    NOT NULL,                    -- what capability is needed
    reason             TEXT    NOT NULL,                    -- researcher's "why"
    status             TEXT    NOT NULL DEFAULT 'pending',  -- pending|assessed|approved|declined|released
    created_at         TEXT    NOT NULL,
    assessment_json    TEXT,                                -- {dependencies, security, alternatives, summary?}
    assessment_draft   INTEGER NOT NULL DEFAULT 0,          -- 1 = unratified auto-draft
    assessed_at        TEXT,
    assessed_by        TEXT,                                -- maintainer_login (or agent identity)
    resolved_at        TEXT,
    resolved_by        TEXT,                                -- maintainer_login
    resolution_reason  TEXT,                                -- mandatory on approve/decline
    release_version    TEXT,                                -- stamped when the fulfilling release is recorded
    released_at        TEXT
);

CREATE INDEX software_requests_status_idx ON software_requests(status);
CREATE INDEX software_requests_tenant_idx ON software_requests(tenant_id);
