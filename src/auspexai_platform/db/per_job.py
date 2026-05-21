"""Per-job database factory — one SQLite DB per experiment (§5.7).

Each experiment that receives work-unit submissions gets its own SQLite
file at `<jobs_dir>/<experiment_id>.db`. The factory lazily creates the
file (with parent dirs) and applies the per-job schema on first access,
then caches the open `Database` for the lifetime of the coordinator
process.

Why per-job DBs at all (per §5.7):
  - Control state stays small even as the network handles many experiments
  - Each per-job DB is an independent unit — can be moved, archived,
    sharded onto a different host later without coupling to control state
  - One experiment's hot writes don't lock another's reads
  - Foreclose the future-HA refactor — Phase 1 v0 is a single coordinator,
    but the data layout permits multi-coordinator sharding by experiment

Per-job DBs do not share migrations with the control DB; each is created
fresh from `PER_JOB_SCHEMA_SQL` and has exactly one schema version for v0.
Phase 2 may introduce per-job migration if the shape needs to evolve.

Closure: connections are closed via `close_all()` at app shutdown. Tests
isolate state through `state_dir` (a per-test temp dir) so each test gets
its own jobs/ tree.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from auspexai_platform.db.database import Database

# Per-job DB schema. M6c added `work_units`; M6d adds `assignments` and
# `results`. The constant is idempotent (CREATE TABLE IF NOT EXISTS) so
# adding tables here also extends existing per-job DBs on next-open.
PER_JOB_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS work_units (
    unit_id              TEXT    PRIMARY KEY,
    payload_json         TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'pending',
    replication_target   INTEGER NOT NULL DEFAULT 3,
    completions_so_far   INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS work_units_status_idx ON work_units(status);


CREATE TABLE IF NOT EXISTS assignments (
    assignment_id        TEXT    PRIMARY KEY,
    unit_id              TEXT    NOT NULL,
    worker_id            TEXT    NOT NULL,
    worker_pubkey_hex    TEXT    NOT NULL,
    assigned_at          TEXT    NOT NULL,
    result_id            TEXT,
    refused_at           TEXT,
    refused_kind         TEXT,
    refused_reason       TEXT,
    UNIQUE (unit_id, worker_id),
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);

CREATE INDEX IF NOT EXISTS assignments_unit_idx ON assignments(unit_id);
CREATE INDEX IF NOT EXISTS assignments_worker_idx ON assignments(worker_id);


CREATE TABLE IF NOT EXISTS results (
    result_id            TEXT    PRIMARY KEY,
    unit_id              TEXT    NOT NULL,
    worker_id            TEXT    NOT NULL,
    worker_pubkey_hex    TEXT    NOT NULL,
    exit_code            INTEGER NOT NULL,
    payload_json         TEXT    NOT NULL,
    worker_signature     TEXT    NOT NULL,
    completed_at         TEXT    NOT NULL,
    received_at          TEXT    NOT NULL,
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);

CREATE INDEX IF NOT EXISTS results_unit_idx ON results(unit_id);
CREATE INDEX IF NOT EXISTS results_worker_idx ON results(worker_id);
"""


class PerJobDatabaseFactory:
    """Lazily opens and caches one `Database` per experiment_id.

    Thread-safe: the internal cache is guarded by a lock so concurrent
    callers asking for the same experiment_id get back the same instance.
    """

    def __init__(self, jobs_dir: Path):
        self._jobs_dir = jobs_dir
        self._jobs_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Database] = {}
        self._lock = threading.Lock()

    def get_or_create(self, experiment_id: str) -> Database:
        """Return the per-job Database for `experiment_id`, creating the
        file and applying the schema if it doesn't exist yet."""
        with self._lock:
            cached = self._cache.get(experiment_id)
            if cached is not None:
                return cached
            db_path = self._path_for(experiment_id)
            db = Database(db_path)
            db.executescript(PER_JOB_SCHEMA_SQL)
            _ensure_assignments_refused_columns(db)
            self._cache[experiment_id] = db
            return db

    def get(self, experiment_id: str) -> Database | None:
        """Return the cached DB if it exists, else None. Does NOT create.

        Useful for read paths where the experiment may not yet have
        received work-unit submissions (no per-job DB exists yet).
        """
        with self._lock:
            cached = self._cache.get(experiment_id)
            if cached is not None:
                return cached
            db_path = self._path_for(experiment_id)
            if not db_path.exists():
                return None
            # On a fresh coordinator process, the file may exist on disk
            # but not be cached yet — load it. Apply post-M6d schema
            # additions idempotently so pre-Option-A per-job DBs work.
            db = Database(db_path)
            _ensure_assignments_refused_columns(db)
            self._cache[experiment_id] = db
            return db

    def close_all(self) -> None:
        with self._lock:
            for db in self._cache.values():
                db.close()
            self._cache.clear()

    def iter_cached_dbs(self) -> list[tuple[str, Database]]:
        """Return [(experiment_id, db), ...] for all cached per-job DBs.

        Used by route handlers that need to scan for a (unit_id, worker_id)
        assignment without knowing the experiment_id in advance. Hot DBs
        are by definition cached, so this covers normal worker flow; cold-
        load (post-restart) is handled by `get(experiment_id)` once the
        caller learns the experiment_id.
        """
        with self._lock:
            return list(self._cache.items())

    def _path_for(self, experiment_id: str) -> Path:
        return self._jobs_dir / f"{experiment_id}.db"


def _ensure_assignments_refused_columns(db: Database) -> None:
    """Idempotently add refused_at / refused_kind / refused_reason columns to
    the per-job `assignments` table. The columns are part of
    PER_JOB_SCHEMA_SQL for newly-created DBs, but existing pre-Option-A
    per-job DBs were created without them; ALTER TABLE ADD COLUMN is the
    cheap way to converge.
    """
    for column, sql_type in (
        ("refused_at", "TEXT"),
        ("refused_kind", "TEXT"),
        ("refused_reason", "TEXT"),
    ):
        try:
            db.executescript(f"ALTER TABLE assignments ADD COLUMN {column} {sql_type};")
        except sqlite3.OperationalError as exc:
            # "duplicate column name" — column already present, fine.
            if "duplicate column" not in str(exc).lower():
                raise
