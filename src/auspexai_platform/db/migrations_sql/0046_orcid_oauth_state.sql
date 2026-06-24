-- 0046_orcid_oauth_state: single-use CSRF state for the ORCID OAuth link flow.
--
-- `POST /accounts/orcid/start` (authenticated) mints a random state bound to the
-- caller's account and hands back the ORCID authorize URL. The public
-- `GET /accounts/orcid/callback` consumes the state (single-use, TTL-checked) to
-- recover which account to link — the state is the CSRF binding between the
-- browser round-trip and the authenticated researcher. Rows are deleted on
-- consume; stale rows age out by created_at.

CREATE TABLE orcid_oauth_states (
    state       TEXT    PRIMARY KEY,
    account_id  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);
