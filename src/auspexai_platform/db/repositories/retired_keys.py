"""RetiredKeyRepository — registry of withdrawn worker pubkeys.

Per Principles & Scope §5.15: withdrawal is permanent for the affected
keypair. The enroll endpoint consults this table before allowing a new
worker_id to be issued for a pubkey; the retire endpoint inserts the
pubkey here after marking the workers row retired.

Single PK on pubkey_hex; a key can be retired only once.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.database import Database


class DuplicateRetiredKeyError(Exception):
    """Raised when the same pubkey is inserted into retired_keys twice."""


@dataclass(frozen=True)
class RetiredKey:
    pubkey_hex: str
    worker_id: str | None
    retired_at: datetime
    reason: str


class RetiredKeyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def retire(
        self,
        *,
        pubkey_hex: str,
        worker_id: str | None,
        reason: str = "withdraw",
    ) -> RetiredKey:
        """Record a pubkey as retired. Raises DuplicateRetiredKeyError if the
        pubkey is already in the table (caller should treat as no-op success
        per idempotency expectations — but the explicit error gives callers
        the choice to surface a real bug if the same retire path was hit
        twice unexpectedly)."""
        pubkey_hex = pubkey_hex.lower()
        try:
            self.db.execute(
                """
                INSERT INTO retired_keys (pubkey_hex, worker_id, reason)
                VALUES (?, ?, ?)
                """,
                (pubkey_hex, worker_id, reason),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateRetiredKeyError(str(e)) from e
        got = self.get(pubkey_hex)
        assert got is not None
        return got

    # ---- reads ----

    def contains(self, pubkey_hex: str) -> bool:
        """True if the pubkey has been retired. Used by the enroll endpoint
        to refuse re-binding of a withdrawn key."""
        rows = self.db.execute(
            "SELECT 1 FROM retired_keys WHERE pubkey_hex = ?",
            (pubkey_hex.lower(),),
        )
        return bool(rows)

    def get(self, pubkey_hex: str) -> RetiredKey | None:
        rows = self.db.execute(
            "SELECT pubkey_hex, worker_id, retired_at, reason "
            "FROM retired_keys WHERE pubkey_hex = ?",
            (pubkey_hex.lower(),),
        )
        if not rows:
            return None
        row = rows[0]
        return RetiredKey(
            pubkey_hex=row["pubkey_hex"],
            worker_id=row["worker_id"],
            retired_at=_parse_ts(row["retired_at"]),
            reason=row["reason"],
        )

    def list_all(self) -> list[RetiredKey]:
        rows = self.db.execute(
            "SELECT pubkey_hex, worker_id, retired_at, reason "
            "FROM retired_keys ORDER BY retired_at DESC"
        )
        return [
            RetiredKey(
                pubkey_hex=r["pubkey_hex"],
                worker_id=r["worker_id"],
                retired_at=_parse_ts(r["retired_at"]),
                reason=r["reason"],
            )
            for r in rows
        ]


def _parse_ts(raw: str) -> datetime:
    # SQLite CURRENT_TIMESTAMP yields "YYYY-MM-DD HH:MM:SS"; isoformat
    # writes use "T". Normalize both.
    if " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)
