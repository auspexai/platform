"""Tests for the SQLite connection wrapper."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from auspexai_platform.db import Database


def _make_db(path: Path) -> Database:
    return Database(path / "test.db")


def test_database_creates_parent_dir(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "deeper" / "test.db"
    db = Database(db_path)
    assert db_path.parent.is_dir()
    db.close()


def test_execute_select_returns_rows(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    db.execute("CREATE TABLE t (a INTEGER, b TEXT)")
    db.execute("INSERT INTO t VALUES (1, 'one')")
    db.execute("INSERT INTO t VALUES (2, 'two')")
    rows = db.execute("SELECT * FROM t ORDER BY a")
    assert len(rows) == 2
    assert rows[0]["a"] == 1
    assert rows[1]["b"] == "two"
    db.close()


def test_execute_with_params(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    db.execute("CREATE TABLE t (a INTEGER)")
    db.execute("INSERT INTO t VALUES (?)", (42,))
    rows = db.execute("SELECT a FROM t WHERE a = ?", (42,))
    assert rows[0]["a"] == 42
    db.close()


def test_transaction_commits_on_success(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    db.execute("CREATE TABLE t (a INTEGER)")
    with db.transaction() as cur:
        cur.execute("INSERT INTO t VALUES (1)")
        cur.execute("INSERT INTO t VALUES (2)")
    rows = db.execute("SELECT a FROM t ORDER BY a")
    assert [r["a"] for r in rows] == [1, 2]
    db.close()


def test_transaction_rolls_back_on_exception(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    db.execute("CREATE TABLE t (a INTEGER UNIQUE)")
    db.execute("INSERT INTO t VALUES (1)")
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction() as cur:
            cur.execute("INSERT INTO t VALUES (2)")
            cur.execute("INSERT INTO t VALUES (1)")  # uniqueness violation
    rows = db.execute("SELECT a FROM t ORDER BY a")
    # Only the pre-existing row should survive — the in-transaction inserts both rolled back.
    assert [r["a"] for r in rows] == [1]
    db.close()


def test_executescript_handles_multiple_statements(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    db.executescript(
        """
        CREATE TABLE a (x INTEGER);
        CREATE TABLE b (y TEXT);
        INSERT INTO a VALUES (1);
        INSERT INTO b VALUES ('hi');
        """
    )
    assert db.execute("SELECT x FROM a")[0]["x"] == 1
    assert db.execute("SELECT y FROM b")[0]["y"] == "hi"
    db.close()


def test_pragmas_configured(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    journal = db.execute("PRAGMA journal_mode")[0]["journal_mode"]
    assert journal.lower() == "wal"
    fk = db.execute("PRAGMA foreign_keys")[0]["foreign_keys"]
    assert fk == 1
    db.close()
