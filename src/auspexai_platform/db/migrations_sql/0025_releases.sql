-- 0025_releases.sql — release registry + fleet announcement channel (§9 #46).
--
-- A maintainer records a published (GitHub) release here to ANNOUNCE it to the
-- fleet: the worker-heartbeat response carries the latest release for the
-- worker's channel, and the volunteer elects to upgrade (never automatic).
-- `channel` is the per-flavor seam — single 'worker' channel today; per-flavor
-- release notes become additive rows later. The coordinator never serves
-- artifacts: release_url points at the signed GitHub release.

CREATE TABLE releases (
    version       TEXT NOT NULL,                    -- bare version, no leading 'v'
    channel       TEXT NOT NULL DEFAULT 'worker',
    headline      TEXT NOT NULL,                    -- one-line motivation shown to volunteers
    notes         TEXT,
    release_url   TEXT,                             -- GitHub release URL
    published_at  TEXT NOT NULL,
    announced_by  TEXT NOT NULL,                    -- maintainer_login
    PRIMARY KEY (channel, version)
);

CREATE INDEX releases_published_idx ON releases(channel, published_at);
