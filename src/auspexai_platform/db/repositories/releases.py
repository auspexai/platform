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


@dataclass(frozen=True)
class Release:
    version: str
    channel: str
    headline: str
    notes: str | None
    release_url: str | None
    published_at: datetime
    announced_by: str


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
    ) -> Release:
        published_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO releases (
                    version, channel, headline, notes, release_url, published_at, announced_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (version, channel, headline, notes, release_url, published_at, announced_by),
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
        rows = self.db.execute(
            "SELECT * FROM releases WHERE channel = ? ORDER BY published_at DESC LIMIT 1",
            (channel,),
        )
        return self._row(rows[0]) if rows else None

    def list(self, *, channel: str | None = None) -> list[Release]:
        if channel is not None:
            rows = self.db.execute(
                "SELECT * FROM releases WHERE channel = ? ORDER BY published_at DESC", (channel,)
            )
        else:
            rows = self.db.execute("SELECT * FROM releases ORDER BY published_at DESC")
        return [self._row(r) for r in rows]

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
        )
