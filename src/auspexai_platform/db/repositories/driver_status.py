"""DriverStatusRepository — the tenant driver's liveness, reported by the SDK
`run_until` loop (0059).

The driver runs off-coordinator, so its liveness is otherwise invisible here: a
dead/interrupted driver silently strands an APPROVED run. Each heartbeat upserts
the one row per experiment (the current/last driver), stamping `last_seen_at`.
A driver's silence (now - last_seen_at past a grace) is the "driver gone" signal
the run-phase uses to read `stalled` instead of `running`; `reason` records WHY
it exited when the driver managed a final report.
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class DriverStatus:
    experiment_id: str
    run_id: str | None
    status: str
    reason: str | None
    round: int | None
    last_seen_at: str
    updated_at: str


class DriverStatusRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        experiment_id: str,
        *,
        status: str,
        now: str,
        run_id: str | None = None,
        reason: str | None = None,
        round: int | None = None,
    ) -> None:
        """Upsert the driver's current liveness for `experiment_id`. Stamps
        `last_seen_at = now` on every heartbeat. Idempotent per (experiment)."""
        reason = reason[:500] if reason else None
        self.db.execute(
            """
            INSERT INTO driver_status
                (experiment_id, run_id, status, reason, round, last_seen_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(experiment_id) DO UPDATE SET
                run_id       = COALESCE(excluded.run_id, driver_status.run_id),
                status       = excluded.status,
                reason       = excluded.reason,
                round        = COALESCE(excluded.round, driver_status.round),
                last_seen_at = excluded.last_seen_at,
                updated_at   = excluded.updated_at
            """,
            (experiment_id, run_id, status, reason, round, now, now),
        )

    def get(self, experiment_id: str) -> DriverStatus | None:
        rows = self.db.execute(
            "SELECT * FROM driver_status WHERE experiment_id = ?", (experiment_id,)
        )
        if not rows:
            return None
        r = rows[0]
        return DriverStatus(
            experiment_id=r["experiment_id"],
            run_id=r["run_id"],
            status=r["status"],
            reason=r["reason"],
            round=r["round"],
            last_seen_at=r["last_seen_at"],
            updated_at=r["updated_at"],
        )
