"""ModelPrestageRepository — eager download conductor state (M3b, migration 0020).

One row per (model, worker) pre-stage directive. The conductor (or a maintainer
trigger-prestage override) creates `requested` rows; the worker drains them via
GET /workers/{id}/prestage and pulls the model (M3 auto-acquire); the coordinator
marks the row `acquired` once the model shows in the worker's heartbeat
inventory. Open rows + holders are counted against the replication need to bound
the pre-stage fan-out (no thundering herd). See `0020_model_prestage.sql`.
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


def _generate_prestage_id() -> str:
    return f"pst-{secrets.token_urlsafe(6)[:8]}"


class DuplicatePrestageError(Exception):
    """Raised when (model_id, worker_id) already has a prestage row."""


@dataclass(frozen=True)
class PrestageDirective:
    prestage_id: str
    model_id: str
    hf_repo: str
    hf_filename: str
    worker_id: str
    experiment_id: str | None
    requested_by: str
    requested_at: datetime
    acquired_at: datetime | None
    status: str  # requested | acquired | abandoned


class ModelPrestageRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        *,
        model_id: str,
        hf_repo: str,
        hf_filename: str,
        worker_id: str,
        requested_by: str,
        experiment_id: str | None = None,
    ) -> PrestageDirective:
        prestage_id = _generate_prestage_id()
        try:
            self.db.execute(
                """
                INSERT INTO model_prestage (
                    prestage_id, model_id, hf_repo, hf_filename, worker_id,
                    experiment_id, requested_by, requested_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'requested')
                """,
                (
                    prestage_id,
                    model_id,
                    hf_repo,
                    hf_filename,
                    worker_id,
                    experiment_id,
                    requested_by,
                    datetime.now(UTC).isoformat(),
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicatePrestageError(str(e)) from e
        got = self.get_by_id(prestage_id)
        assert got is not None
        return got

    def get_by_id(self, prestage_id: str) -> PrestageDirective | None:
        rows = self.db.execute("SELECT * FROM model_prestage WHERE prestage_id = ?", (prestage_id,))
        return self._row(rows[0]) if rows else None

    def list_open_for_worker(self, worker_id: str) -> list[PrestageDirective]:
        """`requested` (not yet acquired/abandoned) directives for a worker — what
        it should pull now."""
        rows = self.db.execute(
            "SELECT * FROM model_prestage WHERE worker_id = ? AND status = 'requested' "
            "ORDER BY requested_at",
            (worker_id,),
        )
        return [self._row(r) for r in rows]

    def count_open_for_model(self, model_id: str) -> int:
        """Open (requested) rows for a model — the in-flight pre-stage supply that
        the conductor counts alongside current holders to size the fan-out."""
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM model_prestage WHERE model_id = ? AND status = 'requested'",
            (model_id,),
        )
        return int(rows[0]["n"]) if rows else 0

    def has_open(self, *, model_id: str, worker_id: str) -> bool:
        rows = self.db.execute(
            "SELECT 1 FROM model_prestage WHERE model_id = ? AND worker_id = ? AND status = 'requested'",
            (model_id, worker_id),
        )
        return bool(rows)

    def mark_acquired(self, *, model_id: str, worker_id: str) -> None:
        """Mark a worker's open directive for `model_id` acquired (the model now
        appears in its heartbeat inventory). No-op if there's no open row."""
        self.db.execute(
            "UPDATE model_prestage SET status = 'acquired', acquired_at = ? "
            "WHERE model_id = ? AND worker_id = ? AND status = 'requested'",
            (datetime.now(UTC).isoformat(), model_id, worker_id),
        )

    def list_for_experiment(self, experiment_id: str) -> list[PrestageDirective]:
        rows = self.db.execute(
            "SELECT * FROM model_prestage WHERE experiment_id = ? ORDER BY requested_at DESC",
            (experiment_id,),
        )
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(row) -> PrestageDirective:
        return PrestageDirective(
            prestage_id=row["prestage_id"],
            model_id=row["model_id"],
            hf_repo=row["hf_repo"],
            hf_filename=row["hf_filename"],
            worker_id=row["worker_id"],
            experiment_id=row["experiment_id"],
            requested_by=row["requested_by"],
            requested_at=datetime.fromisoformat(row["requested_at"]),
            acquired_at=(
                datetime.fromisoformat(row["acquired_at"]) if row["acquired_at"] else None
            ),
            status=row["status"],
        )
