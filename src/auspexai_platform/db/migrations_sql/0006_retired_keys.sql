-- 0006_retired_keys.sql — registry of withdrawn worker pubkeys.
--
-- Per Principles & Scope §5.15: when a worker withdraws (POST /workers/{id}
-- /actions/retire), its Ed25519 pubkey is recorded here. Subsequent enroll
-- attempts with the same pubkey are refused — a withdrawn key cannot be
-- re-bound to a new worker_id. This is the load-bearing property that
-- closes the worker M6 withdraw loop: the volunteer's explicit "I'm
-- leaving" act is permanent for that key, not a reversible scheduling
-- pause.
--
-- The table outlives the workers row it references. After retire, the
-- workers row stays (for historical audit / receipt anchoring) but its
-- retired_at is set; the pubkey lives here forever. If a worker row is
-- ever hard-deleted (not currently supported), the retired_keys row stays.
--
-- pubkey_hex is UNIQUE: a single pubkey can only be retired once. If a
-- duplicate retire is somehow attempted, the enforcement should surface
-- as an integrity error in the application layer rather than silently
-- accumulating duplicate rows.
--
-- worker_id is the historical reference — which worker this pubkey was
-- associated with at retire time. Nullable in case future paths (operator-
-- initiated revocation of a pubkey that was never enrolled, key-compromise
-- registry imports) ever need to write rows without a workers FK.
--
-- reason is the policy field — currently always 'withdraw' but future
-- values could include 'operator_revoke', 'compromise', 'admin_purge' as
-- those flows ship. Application code defaults to 'withdraw' on the
-- retire endpoint.

CREATE TABLE retired_keys (
    pubkey_hex   TEXT    PRIMARY KEY,                       -- 64 lowercase hex chars
    worker_id    TEXT,                                       -- historical, nullable
    retired_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason       TEXT    NOT NULL DEFAULT 'withdraw'
);

CREATE INDEX retired_keys_worker_idx     ON retired_keys(worker_id);
CREATE INDEX retired_keys_retired_at_idx ON retired_keys(retired_at);
