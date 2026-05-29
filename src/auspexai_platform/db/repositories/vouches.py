"""VouchRepository — T2+ vouching for T1 accounts (§6.2.2).

A vouch satisfies the identity gate as an alternative to direct Maintainer
verification. Vouching is a volunteer action (T2+ account), not a
Maintainer or Approver action. The vouch does NOT auto-promote — the
actual tier-bump still requires Maintainer approval via the promote
endpoint (§6.2.3).
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Vouch


class DuplicateVouchError(Exception):
    """Raised when the voucher has already vouched for this target."""


class VouchNotFoundError(Exception):
    """Raised when a vouch_id is unknown."""


class VouchRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def create(
        self,
        *,
        voucher_account_id: str,
        target_account_id: str,
        rationale: str | None = None,
    ) -> Vouch:
        """Create a vouch. Raises DuplicateVouchError if already vouched."""
        vouch_id = f"vch-{secrets.token_urlsafe(9)}"
        created_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO vouches (
                    vouch_id, voucher_account_id, target_account_id,
                    rationale, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (vouch_id, voucher_account_id, target_account_id, rationale, created_at),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateVouchError(str(e)) from e
        got = self.get_by_id(vouch_id)
        assert got is not None
        return got

    def revoke(self, vouch_id: str) -> Vouch:
        """Revoke a vouch. Idempotent (re-revoke preserves original timestamp).
        Raises VouchNotFoundError if unknown."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE vouches SET revoked_at = COALESCE(revoked_at, ?)
                WHERE vouch_id = ?
                """,
                (now, vouch_id),
            )
            if cur.rowcount == 0:
                raise VouchNotFoundError(vouch_id)
        got = self.get_by_id(vouch_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, vouch_id: str) -> Vouch | None:
        rows = self.db.execute(
            "SELECT * FROM vouches WHERE vouch_id = ?",
            (vouch_id,),
        )
        return self._row_to_vouch(rows[0]) if rows else None

    def list_for_target(self, target_account_id: str, *, active_only: bool = True) -> list[Vouch]:
        """All vouches targeting an account, newest first."""
        if active_only:
            rows = self.db.execute(
                """
                SELECT * FROM vouches
                WHERE target_account_id = ? AND revoked_at IS NULL
                ORDER BY created_at DESC
                """,
                (target_account_id,),
            )
        else:
            rows = self.db.execute(
                """
                SELECT * FROM vouches
                WHERE target_account_id = ?
                ORDER BY created_at DESC
                """,
                (target_account_id,),
            )
        return [self._row_to_vouch(r) for r in rows]

    def list_by_voucher(self, voucher_account_id: str) -> list[Vouch]:
        """All vouches made by a voucher, newest first."""
        rows = self.db.execute(
            """
            SELECT * FROM vouches
            WHERE voucher_account_id = ?
            ORDER BY created_at DESC
            """,
            (voucher_account_id,),
        )
        return [self._row_to_vouch(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_vouch(row: sqlite3.Row) -> Vouch:
        return Vouch(
            vouch_id=row["vouch_id"],
            voucher_account_id=row["voucher_account_id"],
            target_account_id=row["target_account_id"],
            rationale=row["rationale"],
            created_at=datetime.fromisoformat(row["created_at"]),
            revoked_at=(datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None),
        )
