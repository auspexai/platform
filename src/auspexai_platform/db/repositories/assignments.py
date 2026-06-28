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


class AssignmentAlreadyResolvedError(Exception):
    """Raised when mark_refused is called on an assignment that already has
    a result attached or has previously been refused."""


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

    def mark_refused(
        self,
        *,
        assignment_id: str,
        kind: str,
        reason: str,
    ) -> Assignment:
        """Mark an assignment as refused by the worker.

        Raises AssignmentNotFoundError if the assignment_id is unknown.
        Raises AssignmentAlreadyResolvedError if the assignment already has
        a result_id or has already been refused (idempotency: a
        double-refuse is a client bug worth surfacing).
        """
        existing = self.get_by_id(assignment_id)
        if existing is None:
            raise AssignmentNotFoundError(assignment_id)
        if existing.result_id is not None:
            raise AssignmentAlreadyResolvedError(
                f"assignment {assignment_id} already has result_id={existing.result_id!r}"
            )
        if existing.refused_at is not None:
            raise AssignmentAlreadyResolvedError(
                f"assignment {assignment_id} was already refused at {existing.refused_at}"
            )
        refused_at = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE assignments
                   SET refused_at = ?, refused_kind = ?, refused_reason = ?
                 WHERE assignment_id = ?
                """,
                (refused_at, kind, reason, assignment_id),
            )
        got = self.get_by_id(assignment_id)
        assert got is not None
        return got

    def reactivate(self, assignment_id: str) -> Assignment:
        """Re-arm a previously-refused assignment so the unit can be re-offered
        to the same worker (§2.1 #8 dispatch-retry).

        Clears the refusal fields, stamps a fresh `assigned_at`, and bumps
        `attempt_count`. Used only for *retryable* refusals (environmental /
        transient failures — runner crash, sandbox unavailable, thermal) that
        may succeed on a retry; terminal refusals (policy / capability) are
        never reactivated. Raises AssignmentNotFoundError if the id is unknown
        and AssignmentAlreadyResolvedError if the assignment has a result (a
        completed assignment is not re-offerable).
        """
        existing = self.get_by_id(assignment_id)
        if existing is None:
            raise AssignmentNotFoundError(assignment_id)
        if existing.result_id is not None:
            raise AssignmentAlreadyResolvedError(
                f"assignment {assignment_id} already has result_id={existing.result_id!r}"
            )
        reassigned_at = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE assignments
                   SET refused_at = NULL,
                       refused_kind = NULL,
                       refused_reason = NULL,
                       assigned_at = ?,
                       attempt_count = attempt_count + 1
                 WHERE assignment_id = ?
                """,
                (reassigned_at, assignment_id),
            )
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

    def count_active_for_unit(self, unit_id: str) -> int:
        """Like `count_for_unit` but excludes refused assignments.

        Used by the scheduler so refused offers don't permanently consume a
        replication slot. A unit with replication_target=3 and one refusal
        still needs three non-refused workers attached to satisfy
        replication.
        """
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM assignments WHERE unit_id = ? AND refused_at IS NULL",
            (unit_id,),
        )
        return int(rows[0]["n"]) if rows else 0

    def count_active_for_experiment(self) -> int:
        """Count all active (non-refused, no result yet) assignments across
        the entire per-job DB. Used for max_concurrent_assignments enforcement."""
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM assignments WHERE refused_at IS NULL AND result_id IS NULL",
        )
        return int(rows[0]["n"]) if rows else 0

    def active_worker_ids(self) -> set[str]:
        """Distinct workers holding an ACTIVE assignment (offered, not refused, no
        result yet) in this per-job DB — i.e. currently working this experiment.
        Unioned across experiments to derive the network 'busy worker' set (D12
        busy/idle index)."""
        rows = self.db.execute(
            "SELECT DISTINCT worker_id FROM assignments "
            "WHERE refused_at IS NULL AND result_id IS NULL",
        )
        return {r["worker_id"] for r in rows}

    def already_assigned(self, unit_id: str, worker_id: str) -> bool:
        return self.get_for_unit_and_worker(unit_id, worker_id) is not None

    # ---- helpers ----

    @staticmethod
    def _row_to_assignment(row: sqlite3.Row) -> Assignment:
        keys = row.keys()
        refused_at_raw = row["refused_at"] if "refused_at" in keys else None
        attempt_count_raw = row["attempt_count"] if "attempt_count" in keys else None
        return Assignment(
            assignment_id=row["assignment_id"],
            unit_id=row["unit_id"],
            worker_id=row["worker_id"],
            worker_pubkey_hex=row["worker_pubkey_hex"],
            assigned_at=datetime.fromisoformat(row["assigned_at"]),
            result_id=row["result_id"],
            refused_at=(datetime.fromisoformat(refused_at_raw) if refused_at_raw else None),
            refused_kind=row["refused_kind"] if "refused_kind" in keys else None,
            refused_reason=row["refused_reason"] if "refused_reason" in keys else None,
            attempt_count=int(attempt_count_raw) if attempt_count_raw is not None else 1,
        )
