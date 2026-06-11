-- 0026_release_drafts.sql — §9 #46 follow-on: GitHub release → DRAFT announcement.
--
-- A draft is a release the registry knows about but has NOT announced: the
-- heartbeat relay skips it, so no worker banner fires until a maintainer
-- reviews the volunteer-facing wording and publishes it (the announce
-- action). `source` records where the row came from (github-webhook vs
-- manual console/API record) for the audit trail.

ALTER TABLE releases ADD COLUMN draft INTEGER NOT NULL DEFAULT 0;
ALTER TABLE releases ADD COLUMN source TEXT;
