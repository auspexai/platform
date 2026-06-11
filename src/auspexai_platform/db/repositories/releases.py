"""ReleaseRepository — release registry / fleet announcement channel (§9 #46, migration 0025).

A recorded release is an ANNOUNCEMENT, not an artifact: the coordinator relays
{version, headline, url} to workers in the heartbeat response; the volunteer
elects to upgrade. PK is (channel, version) — single 'worker' channel today.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


class ReleaseExistsError(Exception):
    """A release with this (channel, version) is already recorded."""


class ReleaseNotDraftError(Exception):
    """The announce action targets a release that isn't an unpublished draft."""


@dataclass(frozen=True)
class Release:
    version: str
    channel: str
    headline: str
    notes: str | None
    release_url: str | None
    published_at: datetime
    announced_by: str
    # Draft = known to the registry but NOT announced: heartbeats skip it,
    # no worker banner until a maintainer publishes (0026).
    draft: bool = False
    source: str | None = None


class ReleaseRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        *,
        version: str,
        channel: str,
        headline: str,
        announced_by: str,
        notes: str | None = None,
        release_url: str | None = None,
        draft: bool = False,
        source: str | None = None,
    ) -> Release:
        published_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO releases (
                    version, channel, headline, notes, release_url, published_at,
                    announced_by, draft, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version,
                    channel,
                    headline,
                    notes,
                    release_url,
                    published_at,
                    announced_by,
                    1 if draft else 0,
                    source,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise ReleaseExistsError(f"release {channel}/{version} already recorded") from e
        got = self.get(version=version, channel=channel)
        assert got is not None
        return got

    def get(self, *, version: str, channel: str) -> Release | None:
        rows = self.db.execute(
            "SELECT * FROM releases WHERE channel = ? AND version = ?", (channel, version)
        )
        return self._row(rows[0]) if rows else None

    def latest(self, *, channel: str = "worker") -> Release | None:
        # Drafts are invisible to the fleet: only published rows are ever
        # relayed in heartbeats.
        rows = self.db.execute(
            "SELECT * FROM releases WHERE channel = ? AND draft = 0 "
            "ORDER BY published_at DESC LIMIT 1",
            (channel,),
        )
        return self._row(rows[0]) if rows else None

    def list(self, *, channel: str | None = None, include_drafts: bool = False) -> list[Release]:
        draft_clause = "" if include_drafts else " AND draft = 0"
        if channel is not None:
            rows = self.db.execute(
                f"SELECT * FROM releases WHERE channel = ?{draft_clause} "
                "ORDER BY published_at DESC",
                (channel,),
            )
        else:
            rows = self.db.execute(
                f"SELECT * FROM releases WHERE 1 = 1{draft_clause} ORDER BY published_at DESC"
            )
        return [self._row(r) for r in rows]

    def publish_draft(
        self,
        *,
        version: str,
        channel: str,
        announced_by: str,
        headline: str | None = None,
        notes: str | None = None,
        release_url: str | None = None,
    ) -> Release:
        """Flip a draft to published — THE announce moment. Maintainer-edited
        fields override the webhook-supplied ones when given; published_at is
        re-stamped to the announce time (it's the announcement timestamp, not
        the GitHub release date)."""
        existing = self.get(version=version, channel=channel)
        if existing is None:
            raise KeyError(f"release {channel}/{version} not found")
        if not existing.draft:
            raise ReleaseNotDraftError(f"release {channel}/{version} is already published")
        self.db.execute(
            """
            UPDATE releases
            SET draft = 0, headline = ?, notes = ?, release_url = ?,
                published_at = ?, announced_by = ?
            WHERE channel = ? AND version = ?
            """,
            (
                headline if headline is not None else existing.headline,
                notes if notes is not None else existing.notes,
                release_url if release_url is not None else existing.release_url,
                datetime.now(UTC).isoformat(),
                announced_by,
                channel,
                version,
            ),
        )
        got = self.get(version=version, channel=channel)
        assert got is not None
        return got

    @staticmethod
    def _row(row) -> Release:
        return Release(
            version=row["version"],
            channel=row["channel"],
            headline=row["headline"],
            notes=row["notes"],
            release_url=row["release_url"],
            published_at=datetime.fromisoformat(row["published_at"]),
            announced_by=row["announced_by"],
            draft=bool(row["draft"]),
            source=row["source"],
        )
