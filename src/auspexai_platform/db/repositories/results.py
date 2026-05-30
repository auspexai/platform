"""ResultRepository — per-job DB results table.

Stores the SDK Result envelope verbatim plus coordinator-side metadata.
The `worker_signature` is stored as base64; v0 does not verify it (M7 is
where receipts ratify the body-level signature chain). The HTTP-level
RFC 9421 signature is the M6d acceptance check.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Result


class DuplicateResultError(Exception):
    """Raised when a result_id collides."""


class ResultRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        result_id: str,
        unit_id: str,
        worker_id: str,
        worker_pubkey_hex: str,
        exit_code: int,
        payload: dict[str, Any],
        worker_signature: str,
        completed_at: datetime,
    ) -> Result:
        received_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO results (
                    result_id, unit_id, worker_id, worker_pubkey_hex,
                    exit_code, payload_json, worker_signature,
                    completed_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    unit_id,
                    worker_id,
                    worker_pubkey_hex.lower(),
                    exit_code,
                    json.dumps(payload),
                    worker_signature,
                    completed_at.isoformat(),
                    received_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateResultError(str(e)) from e
        got = self.get_by_id(result_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, result_id: str) -> Result | None:
        rows = self.db.execute(
            "SELECT * FROM results WHERE result_id = ?",
            (result_id,),
        )
        return self._row_to_result(rows[0]) if rows else None

    def list_for_unit(self, unit_id: str) -> list[Result]:
        rows = self.db.execute(
            "SELECT * FROM results WHERE unit_id = ? ORDER BY received_at",
            (unit_id,),
        )
        return [self._row_to_result(r) for r in rows]

    def count_distinct_workers(self) -> int:
        """Number of distinct workers that have submitted >=1 result.

        Integer only — backs the anonymized active-contributor count; never
        exposes *which* workers (volunteer-anonymity rule)."""
        rows = self.db.execute("SELECT COUNT(DISTINCT worker_id) AS n FROM results")
        return int(rows[0]["n"]) if rows else 0

    def latest_received_at(self) -> datetime | None:
        """Most recent result `received_at` across the experiment, or None if no
        results have been submitted yet."""
        rows = self.db.execute("SELECT MAX(received_at) AS latest FROM results")
        latest = rows[0]["latest"] if rows else None
        return datetime.fromisoformat(latest) if latest else None

    # ---- helpers ----

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> Result:
        return Result(
            result_id=row["result_id"],
            unit_id=row["unit_id"],
            worker_id=row["worker_id"],
            worker_pubkey_hex=row["worker_pubkey_hex"],
            exit_code=row["exit_code"],
            payload=json.loads(row["payload_json"]),
            worker_signature=row["worker_signature"],
            completed_at=datetime.fromisoformat(row["completed_at"]),
            received_at=datetime.fromisoformat(row["received_at"]),
        )
