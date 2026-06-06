-- 0018_model_requests.sql — demand-board / researcher "new requirement" queue (M2).
--
-- A researcher signals demand for a model (BYOM, §5.8 + §9 #32/#39). Every
-- request is recorded as a demand signal; `status` distinguishes the queue:
--   available — ≥1 active worker already holds `model_id` (informational; the
--               network can run it now — no maintainer action needed).
--   pending   — no active worker holds it → the maintainer review queue
--               (recruit capable volunteers / decide to support / decline).
--   fulfilled — a maintainer resolved a pending request affirmatively.
--   declined  — a maintainer declined it (with reason).
-- `model_id` is the worker store id (<repo-slug>-<quant>) — the same exact-match
-- space the M1 scheduler routes on, so "available" is computed against the
-- inventory the scheduler actually uses. `hf_repo` is an optional source hint.

CREATE TABLE model_requests (
    request_id         TEXT    PRIMARY KEY,                 -- 'mrq-<random>'
    tenant_id          TEXT    NOT NULL,                    -- requesting researcher's tenant
    model_id           TEXT    NOT NULL,                    -- worker store model_id requested
    hf_repo            TEXT,                                -- optional HF repo hint
    reason             TEXT    NOT NULL,                    -- researcher's one-line "why"
    status             TEXT    NOT NULL DEFAULT 'pending',  -- available | pending | fulfilled | declined
    created_at         TEXT    NOT NULL,
    resolved_at        TEXT,                                -- when a maintainer fulfilled/declined
    resolved_by        TEXT,                                -- maintainer_login
    resolution_reason  TEXT                                 -- mandatory reason on fulfil/decline
);

CREATE INDEX model_requests_status_idx ON model_requests(status);
CREATE INDEX model_requests_tenant_idx ON model_requests(tenant_id);
