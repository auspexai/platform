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
    # D12 5c: latest in-flight download sample (worker-reported via heartbeat).
    # total may be None when HF metadata was unavailable → bytes-only, no %.
    download_bytes: int | None = None
    download_total_bytes: int | None = None


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

    def update_progress(
        self,
        *,
        model_id: str,
        worker_id: str,
        download_bytes: int,
        download_total_bytes: int | None,
    ) -> None:
        """Record the latest in-flight download sample (D12 5c) on the worker's
        OPEN (requested) directive for `model_id`. No-op when there's no open row
        (e.g. a stray report after the model was already acquired)."""
        self.db.execute(
            "UPDATE model_prestage SET download_bytes = ?, download_total_bytes = ? "
            "WHERE model_id = ? AND worker_id = ? AND status = 'requested'",
            (download_bytes, download_total_bytes, model_id, worker_id),
        )

    def progress_for_models(self, model_ids: list[str]) -> dict | None:
        """The furthest-along in-flight (requested) download among `model_ids` —
        `{model_id, bytes_downloaded, total_bytes, pct}` — or None if none is
        open. Powers the D12 download-% surfaced to a queued researcher; `pct` is
        None until a sample with a known total lands."""
        if not model_ids:
            return None
        placeholders = ",".join("?" for _ in model_ids)
        rows = self.db.execute(
            f"SELECT model_id, download_bytes, download_total_bytes FROM model_prestage "
            f"WHERE status = 'requested' AND model_id IN ({placeholders})",
            tuple(model_ids),
        )
        best: dict | None = None
        for r in rows:
            b = r["download_bytes"]
            t = r["download_total_bytes"]
            pct = round(b / t * 100, 1) if (b is not None and t) else None
            cand = {
                "model_id": r["model_id"],
                "bytes_downloaded": b,
                "total_bytes": t,
                "pct": pct,
            }
            if best is None or (cand["pct"] or -1) > (best["pct"] or -1):
                best = cand
        return best

    def abandon_stale_requested(self, *, older_than: datetime, apply: bool) -> int:
        """Flip `requested` directives requested before `older_than` to
        `abandoned` — so the worker STOPS re-polling a directive it can never
        fulfil (model gone from HF, too big, disk full). The `abandoned` status
        exists in the schema (0020) for exactly this and nothing set it before;
        this is the guard against the D22-B-shaped perpetual re-poll. Returns the
        count (accurate in dry-run and apply)."""
        where = "status = 'requested' AND requested_at < ?"
        if not apply:
            rows = self.db.execute(
                f"SELECT COUNT(*) AS n FROM model_prestage WHERE {where}",
                (older_than.isoformat(),),
            )
            return int(rows[0]["n"]) if rows else 0
        rows = self.db.execute(
            f"UPDATE model_prestage SET status = 'abandoned' WHERE {where} RETURNING prestage_id",
            (older_than.isoformat(),),
        )
        return len(rows)

    def reap_dead_worker_rows(self, *, heartbeat_cutoff: datetime, apply: bool) -> int:
        """DELETE prestage rows whose worker has not heartbeat since
        `heartbeat_cutoff` (or is gone from `workers` entirely) — reaps orphaned
        dead-weight rows AND unblocks re-staging (the `UNIQUE(model,worker)` row
        is what blocks a fresh `create`) if the worker ever returns. A worker with
        a recent heartbeat keeps all its rows. Returns the count."""
        where = "worker_id NOT IN (SELECT worker_id FROM workers WHERE last_heartbeat_at >= ?)"
        if not apply:
            rows = self.db.execute(
                f"SELECT COUNT(*) AS n FROM model_prestage WHERE {where}",
                (heartbeat_cutoff.isoformat(),),
            )
            return int(rows[0]["n"]) if rows else 0
        rows = self.db.execute(
            f"DELETE FROM model_prestage WHERE {where} RETURNING prestage_id",
            (heartbeat_cutoff.isoformat(),),
        )
        return len(rows)

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
            download_bytes=row["download_bytes"],
            download_total_bytes=row["download_total_bytes"],
        )
