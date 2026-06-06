"""WorkUnitRepository — per-experiment work_units table.

Constructed per-request bound to a specific per-job `Database` (from
`PerJobDatabaseFactory.get_or_create(experiment_id)`). Unlike the
control-DB repos (TenantRepository etc.) which take the shared control
DB, this one operates on a *single experiment's* DB — instances are
short-lived (one per request) since the underlying DB cache is held by
the factory.

M6c surface: submit_batch, get_by_unit_id, list_all. M6d will extend with
status-transition methods (mark_assigned, mark_completed, etc.) once the
scheduler exists.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import WorkUnit, WorkUnitStatus


class DuplicateWorkUnitError(Exception):
    """Raised when a unit_id collides with an existing row in this experiment's DB."""


# Default replication target on insert; M6d may revise downward per worker tier.
DEFAULT_REPLICATION_TARGET = 3


class WorkUnitRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def submit_batch(
        self,
        units: list[dict[str, Any]],
        *,
        replication_target: int = DEFAULT_REPLICATION_TARGET,
    ) -> list[WorkUnit]:
        """Insert a batch of work units atomically. Each item must have
        `unit_id` (str) + `payload` (dict). Raises DuplicateWorkUnitError
        if any unit_id collides; the whole batch is rolled back.

        Returns the persisted rows in submission order.
        """
        if not units:
            return []
        now = datetime.now(UTC).isoformat()
        rows: list[tuple] = []
        for u in units:
            rows.append(
                (
                    u["unit_id"],
                    json.dumps(u.get("payload", {})),
                    WorkUnitStatus.PENDING.value,
                    replication_target,
                    0,
                    now,
                )
            )
        try:
            with self.db.transaction() as cur:
                cur.executemany(
                    """
                    INSERT INTO work_units (
                        unit_id, payload_json, status, replication_target,
                        completions_so_far, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
        except sqlite3.IntegrityError as e:
            raise DuplicateWorkUnitError(str(e)) from e

        return [u for u in (self.get_by_unit_id(r[0]) for r in rows) if u is not None]

    def mark_in_progress(self, unit_id: str) -> None:
        """Transition pending → in_progress (idempotent: in_progress → in_progress
        is a no-op). Raises nothing if the unit doesn't exist — used in
        scheduler hot path where we already know the unit exists."""
        self.db.execute(
            "UPDATE work_units SET status = 'in_progress' WHERE unit_id = ? AND status = 'pending'",
            (unit_id,),
        )

    def pin(self, unit_id: str, worker_id: str | None) -> WorkUnit | None:
        """Set (or clear, with worker_id=None) the unit's pinned worker (M4-tail
        force-assign). A pinned unit is offered ONLY to that worker by the
        scheduler. Returns the updated unit, or None if the unit is unknown."""
        self.db.execute(
            "UPDATE work_units SET pinned_worker_id = ? WHERE unit_id = ?",
            (worker_id, unit_id),
        )
        return self.get_by_unit_id(unit_id)

    def increment_completions(self, unit_id: str) -> WorkUnit:
        """Bump completions_so_far by 1. If completions_so_far meets or
        exceeds replication_target, transition to 'completed'. Returns the
        updated row."""
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE work_units SET completions_so_far = completions_so_far + 1 "
                "WHERE unit_id = ?",
                (unit_id,),
            )
            cur.execute(
                "UPDATE work_units SET status = 'completed' "
                "WHERE unit_id = ? AND completions_so_far >= replication_target",
                (unit_id,),
            )
        got = self.get_by_unit_id(unit_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_unit_id(self, unit_id: str) -> WorkUnit | None:
        rows = self.db.execute(
            "SELECT * FROM work_units WHERE unit_id = ?",
            (unit_id,),
        )
        return self._row_to_unit(rows[0]) if rows else None

    def list_all(
        self,
        *,
        status: WorkUnitStatus | None = None,
    ) -> list[WorkUnit]:
        if status is None:
            rows = self.db.execute("SELECT * FROM work_units ORDER BY created_at, unit_id")
        else:
            rows = self.db.execute(
                "SELECT * FROM work_units WHERE status = ? ORDER BY created_at, unit_id",
                (status.value,),
            )
        return [self._row_to_unit(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        """Return {status: count} aggregating over all units. Useful for the
        experiment progress view."""
        rows = self.db.execute("SELECT status, COUNT(*) AS n FROM work_units GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def replication_totals(self) -> tuple[int, int]:
        """Return (completions_total, replication_target_total) summed across all
        work units — the experiment's replication fill."""
        rows = self.db.execute(
            "SELECT COALESCE(SUM(completions_so_far), 0) AS compl, "
            "COALESCE(SUM(replication_target), 0) AS target FROM work_units"
        )
        if not rows:
            return (0, 0)
        return (int(rows[0]["compl"]), int(rows[0]["target"]))

    # ---- helpers ----

    @staticmethod
    def _row_to_unit(row: sqlite3.Row) -> WorkUnit:
        keys = row.keys()
        pinned = row["pinned_worker_id"] if "pinned_worker_id" in keys else None
        return WorkUnit(
            unit_id=row["unit_id"],
            payload=json.loads(row["payload_json"]),
            status=WorkUnitStatus(row["status"]),
            replication_target=row["replication_target"],
            completions_so_far=row["completions_so_far"],
            created_at=datetime.fromisoformat(row["created_at"]),
            pinned_worker_id=pinned,
        )
