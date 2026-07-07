"""D22-B — per-job work_units CHECK rebuild (adds the 'cancelled' status).

Existing per-job DBs baked the old 4-value status CHECK into the table
definition; SQLite can't alter a CHECK in place, so
`_ensure_work_units_cancelled_status` does a one-time table rebuild. These
tests exercise it directly against an OLD-schema DB (the factory can't produce
one — PER_JOB_SCHEMA_SQL already has the new CHECK), asserting the new value is
accepted, data + FK integrity survive, and the pass is idempotent.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from auspexai_platform.db.database import Database
from auspexai_platform.db.per_job import _ensure_work_units_cancelled_status

_OLD_SCHEMA = """
CREATE TABLE work_units (
    unit_id              TEXT    PRIMARY KEY,
    payload_json         TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'pending',
    replication_target   INTEGER NOT NULL DEFAULT 3,
    completions_so_far   INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    pinned_worker_id     TEXT,
    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'))
);
CREATE INDEX work_units_status_idx ON work_units(status);
CREATE TABLE assignments (
    assignment_id TEXT PRIMARY KEY,
    unit_id       TEXT NOT NULL,
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);
"""


def _old_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "job.db")
    db.executescript(_OLD_SCHEMA)
    db.execute(
        "INSERT INTO work_units (unit_id, payload_json, status, replication_target, "
        "completions_so_far, created_at, pinned_worker_id) "
        "VALUES ('u1', '{}', 'in_progress', 3, 1, '2026-01-01', 'wkr-x')"
    )
    db.execute("INSERT INTO assignments (assignment_id, unit_id) VALUES ('a1', 'u1')")
    return db


def test_old_check_rejects_cancelled(tmp_path: Path) -> None:
    db = _old_db(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("UPDATE work_units SET status = 'cancelled' WHERE unit_id = 'u1'")


def test_rebuild_accepts_cancelled_and_preserves_data_and_fks(tmp_path: Path) -> None:
    db = _old_db(tmp_path)

    _ensure_work_units_cancelled_status(db)

    # 'cancelled' now allowed.
    db.execute("UPDATE work_units SET status = 'cancelled' WHERE unit_id = 'u1'")
    row = db.execute("SELECT status, pinned_worker_id FROM work_units WHERE unit_id = 'u1'")[0]
    assert row["status"] == "cancelled"
    assert row["pinned_worker_id"] == "wkr-x"  # all columns copied

    # Child FK row + referential integrity preserved.
    assert db.execute("SELECT unit_id FROM assignments WHERE assignment_id = 'a1'")[0]["unit_id"] == "u1"
    assert db.execute("PRAGMA foreign_key_check") == []
    # foreign_keys re-enabled after the rebuild.
    assert db.execute("PRAGMA foreign_keys")[0][0] == 1
    # Status index recreated.
    assert db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'work_units_status_idx'"
    )


def test_rebuild_is_idempotent(tmp_path: Path) -> None:
    db = _old_db(tmp_path)
    _ensure_work_units_cancelled_status(db)
    sql_after_first = db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'work_units'"
    )[0]["sql"]
    # Second call is a no-op — no further rebuild, table def unchanged.
    _ensure_work_units_cancelled_status(db)
    sql_after_second = db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'work_units'"
    )[0]["sql"]
    assert sql_after_first == sql_after_second
    assert "'cancelled'" in sql_after_second
    # No stray work_units_new left behind.
    assert not db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'work_units_new'"
    )
