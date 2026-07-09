-- 0059_driver_status.sql — coordinator record of the tenant DRIVER's liveness.
--
-- The driver (tenant-sdk `run_until`) runs OFF the coordinator — on the tenant's
-- own machine, reaching the coordinator over the public tunnel. So the
-- coordinator otherwise has NO signal that a driver is alive, stalled, or why it
-- stopped: a dead/interrupted driver is invisible server-side and silently
-- strands an APPROVED run (the failure the auto-wrap sweep now tolerates but
-- could not explain — driver deaths were only ever visible in the Mac-side
-- driver.log). Confirmed cause of a real strand (2026-07-09, exp-omJ9jjXw): a
-- transient Cloudflare HTTP 502 the driver treated as fatal.
--
-- This table closes that blind spot: the driver POSTs a lightweight heartbeat
-- each round and on its exit paths, so a driver's last-seen / status / exit
-- reason becomes a timestamped, queryable server-side fact (diagnosability), and
-- the run's phase can distinguish "running" (driver alive) from "stalled"
-- (driver silent). One row per experiment — the current/last driver — upserted
-- on each heartbeat.

CREATE TABLE IF NOT EXISTS driver_status (
    experiment_id   TEXT    PRIMARY KEY,
    run_id          TEXT,               -- the detached-driver run id (nullable: foreground drivers have none)
    status          TEXT    NOT NULL,   -- driving | finalizing | exiting | gone
    reason          TEXT,               -- exit / last reason: completed | interrupted | http_502 | coordinator_unreachable | ...
    round           INTEGER,            -- driver's round counter, for progress context
    last_seen_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (experiment_id) REFERENCES experiments(experiment_id)
);
