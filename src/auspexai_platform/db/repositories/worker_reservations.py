"""worker_reservations — the reservation table behind capacity-aware scheduling.

A worker is reserved to at most one experiment at a time (PK on worker_id). An
admitted experiment holds a set of reserved workers and runs uninterrupted on them;
contending experiments queue. The scheduler's `_reconcile` keeps this table in sync
with the live fleet — releasing reservations for departed workers or ended
experiments, topping up under-replicated runs, and admitting queued ones."""

from __future__ import annotations

from auspexai_platform.db.database import Database


class WorkerReservationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def reserve(self, worker_id: str, experiment_id: str, *, now: str) -> None:
        """Reserve `worker_id` to `experiment_id` (idempotent; re-points a worker if it
        was reserved elsewhere — a caller only does that after releasing)."""
        self.db.execute(
            """
            INSERT INTO worker_reservations (worker_id, experiment_id, reserved_at)
            VALUES (?, ?, ?)
            ON CONFLICT(worker_id) DO UPDATE SET
                experiment_id = excluded.experiment_id,
                reserved_at = excluded.reserved_at
            """,
            (worker_id, experiment_id, now),
        )

    def release_worker(self, worker_id: str) -> None:
        self.db.execute("DELETE FROM worker_reservations WHERE worker_id = ?", (worker_id,))

    def release_experiment(self, experiment_id: str) -> None:
        """Free every worker reserved to `experiment_id` (call when it ends)."""
        self.db.execute("DELETE FROM worker_reservations WHERE experiment_id = ?", (experiment_id,))

    def experiment_for_worker(self, worker_id: str) -> str | None:
        rows = self.db.execute(
            "SELECT experiment_id FROM worker_reservations WHERE worker_id = ?", (worker_id,)
        )
        return rows[0]["experiment_id"] if rows else None

    def all(self) -> list[tuple[str, str]]:
        """[(worker_id, experiment_id), …] — the whole reservation set, for reconcile."""
        rows = self.db.execute("SELECT worker_id, experiment_id FROM worker_reservations")
        return [(r["worker_id"], r["experiment_id"]) for r in rows]

    def counts_by_experiment(self) -> dict[str, int]:
        rows = self.db.execute(
            "SELECT experiment_id, COUNT(*) AS n FROM worker_reservations GROUP BY experiment_id"
        )
        return {r["experiment_id"]: int(r["n"]) for r in rows}
