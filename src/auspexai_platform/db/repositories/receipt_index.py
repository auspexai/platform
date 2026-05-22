"""ReceiptIndexRepository — control-DB pointer to per-job receipt rows.

Populated by M7c's receipt-issuance hook (one index row per issued
receipt) so cross-experiment queries don't need to walk every per-job DB.
The full receipt content (COSE-Sign1 bytes + inner CBOR) still lives on
the per-job DB; this table just maps `receipt_id -> experiment_id` plus
denormalizes worker_id + worker_pubkey for fast filtering.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


class DuplicateReceiptIndexError(Exception):
    """Raised when the same receipt_id is indexed twice."""


@dataclass(frozen=True)
class ReceiptIndexEntry:
    """One row of the receipt_index table — points at where the receipt
    actually lives + carries the worker identity for scope checks."""

    receipt_id: str
    experiment_id: str  # coord-side exp- id (locates the per-job DB)
    worker_id: str
    worker_pubkey: str  # 64 lowercase hex
    issued_at: datetime


class ReceiptIndexRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def record(
        self,
        *,
        receipt_id: str,
        experiment_id: str,
        worker_id: str,
        worker_pubkey: str,
    ) -> ReceiptIndexEntry:
        """Index a newly-issued receipt. Raises DuplicateReceiptIndexError if
        receipt_id is already indexed (should not happen during normal
        operation — surfaces real bugs)."""
        worker_pubkey = worker_pubkey.lower()
        issued_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO receipt_index
                  (receipt_id, experiment_id, worker_id, worker_pubkey, issued_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (receipt_id, experiment_id, worker_id, worker_pubkey, issued_at),
            )
        except sqlite3.IntegrityError as e:
            # Distinguish duplicate-PK from FK-violation by inspecting the
            # sqlite error text. UNIQUE violations on receipt_id are
            # caller-recoverable (idempotent retries); FK violations are
            # bugs (worker_id doesn't exist) and bubble up unchanged.
            if "UNIQUE" in str(e):
                raise DuplicateReceiptIndexError(str(e)) from e
            raise
        got = self.get_by_id(receipt_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, receipt_id: str) -> ReceiptIndexEntry | None:
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE receipt_id = ?",
            (receipt_id,),
        )
        return self._row_to_entry(rows[0]) if rows else None

    def list_for_worker(self, worker_id: str) -> list[ReceiptIndexEntry]:
        """All receipts attributable to one worker_id, newest first."""
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE worker_id = ? ORDER BY issued_at DESC",
            (worker_id,),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_for_account(self, account_id: str) -> list[ReceiptIndexEntry]:
        """All receipts under any worker bound to one account_id, newest first.

        Joins receipt_index → workers via worker_id, filters on
        workers.account_id. Anonymous / T0 workers (account_id IS NULL) are
        not returned by this method — account-scoped listing only makes
        sense for accounts.
        """
        rows = self.db.execute(
            """
            SELECT ri.* FROM receipt_index ri
            INNER JOIN workers w ON w.worker_id = ri.worker_id
            WHERE w.account_id = ?
            ORDER BY ri.issued_at DESC
            """,
            (account_id,),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_for_pubkey(self, pubkey_hex: str) -> list[ReceiptIndexEntry]:
        """All receipts where the contributing worker had this pubkey.

        For Phase 1 a worker's pubkey is unique, so this overlaps heavily
        with `list_for_worker`. Once Phase 2's key rotation lands (or the
        retired_keys registry is consulted for verifying old receipts),
        pubkey-keyed lookups are the more stable cross-reference."""
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE worker_pubkey = ? ORDER BY issued_at DESC",
            (pubkey_hex.lower(),),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_all(self) -> list[ReceiptIndexEntry]:
        rows = self.db.execute("SELECT * FROM receipt_index ORDER BY issued_at DESC")
        return [self._row_to_entry(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ReceiptIndexEntry:
        return ReceiptIndexEntry(
            receipt_id=row["receipt_id"],
            experiment_id=row["experiment_id"],
            worker_id=row["worker_id"],
            worker_pubkey=row["worker_pubkey"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
        )
