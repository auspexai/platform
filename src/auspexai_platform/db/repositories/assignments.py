"""AssignmentRepository — one row per (work_unit, worker) pair.

Constructed per-request bound to a specific per-job `Database` (same
pattern as `WorkUnitRepository`).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Assignment


class DuplicateAssignmentError(Exception):
    """Raised when (unit_id, worker_id) is already assigned."""


class AssignmentNotFoundError(Exception):
    """Raised when an assignment lookup misses."""


class AssignmentRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def create(
        self,
        *,
        assignment_id: str,
        unit_id: str,
        worker_id: str,
        worker_pubkey_hex: str,
    ) -> Assignment:
        assigned_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO assignments (
                    assignment_id, unit_id, worker_id, worker_pubkey_hex,
                    assigned_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    assignment_id,
                    unit_id,
                    worker_id,
                    worker_pubkey_hex.lower(),
                    assigned_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateAssignmentError(str(e)) from e
        got = self.get_by_id(assignment_id)
        assert got is not None
        return got

    def attach_result(self, assignment_id: str, result_id: str) -> Assignment:
        """Set the assignment's result_id. Raises AssignmentNotFoundError if
        the assignment_id is unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE assignments SET result_id = ? WHERE assignment_id = ?",
                (result_id, assignment_id),
            )
            if cur.rowcount == 0:
                raise AssignmentNotFoundError(assignment_id)
        got = self.get_by_id(assignment_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, assignment_id: str) -> Assignment | None:
        rows = self.db.execute(
            "SELECT * FROM assignments WHERE assignment_id = ?",
            (assignment_id,),
        )
        return self._row_to_assignment(rows[0]) if rows else None

    def get_for_unit_and_worker(self, unit_id: str, worker_id: str) -> Assignment | None:
        rows = self.db.execute(
            "SELECT * FROM assignments WHERE unit_id = ? AND worker_id = ?",
            (unit_id, worker_id),
        )
        return self._row_to_assignment(rows[0]) if rows else None

    def list_for_unit(self, unit_id: str) -> list[Assignment]:
        rows = self.db.execute(
            "SELECT * FROM assignments WHERE unit_id = ? ORDER BY assigned_at",
            (unit_id,),
        )
        return [self._row_to_assignment(r) for r in rows]

    def count_for_unit(self, unit_id: str) -> int:
        """Total assignments (both pending and result-attached) for a unit.

        Used by the scheduler to enforce replication_target — once this many
        workers are attached, no more assignments for this unit.
        """
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM assignments WHERE unit_id = ?",
            (unit_id,),
        )
        return int(rows[0]["n"]) if rows else 0

    def already_assigned(self, unit_id: str, worker_id: str) -> bool:
        return self.get_for_unit_and_worker(unit_id, worker_id) is not None

    # ---- helpers ----

    @staticmethod
    def _row_to_assignment(row: sqlite3.Row) -> Assignment:
        return Assignment(
            assignment_id=row["assignment_id"],
            unit_id=row["unit_id"],
            worker_id=row["worker_id"],
            worker_pubkey_hex=row["worker_pubkey_hex"],
            assigned_at=datetime.fromisoformat(row["assigned_at"]),
            result_id=row["result_id"],
        )
