"""Database connection management.

Holds one `sqlite3.Connection` per `Database` instance. Threading-safe via an
internal `threading.RLock`; `check_same_thread=False` lets the connection
move between FastAPI worker threads as routes do `asyncio.to_thread` calls
into the repository layer.

Two access patterns:

  - `db.execute(sql, params)` — one-statement read/write, auto-commit.
  - `with db.transaction() as cur:` — multi-statement transaction with
    explicit BEGIN/COMMIT/ROLLBACK.

For DDL scripts (migrations) use `db.executescript(sql)`; SQLite's
executescript() implicitly commits any pending transaction, so we don't wrap
it in our transaction context manager.

Pragmas set on connect:
  - `journal_mode = WAL` — concurrent readers + one writer.
  - `synchronous = NORMAL` — durability still within fsync semantics; faster
    than FULL with negligible safety loss for our usage shape.
  - `foreign_keys = ON` — SQLite defaults to off; required for FK enforcement.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class DatabaseError(Exception):
    """Raised on DB I/O or configuration errors that aren't sqlite3 errors."""


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            # autocommit-style: no implicit BEGIN before DML statements.
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure_pragmas()

    def _configure_pragmas(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            try:
                # journal_mode = WAL is durable across the file lifetime.
                cur.execute("PRAGMA journal_mode = WAL")
                cur.execute("PRAGMA synchronous = NORMAL")
                cur.execute("PRAGMA foreign_keys = ON")
            finally:
                cur.close()

    def execute(
        self,
        sql: str,
        params: tuple | dict | None = None,
    ) -> list[sqlite3.Row]:
        """Run one statement. Returns rows if it's a SELECT (or a DML with
        RETURNING); otherwise an empty list. Auto-commits inside the
        statement since `isolation_level=None`."""
        params = params or ()
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(sql, params)
                if cur.description:
                    return cur.fetchall()
                return []
            finally:
                cur.close()

    def executemany(self, sql: str, params_seq: list[tuple]) -> None:
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.executemany(sql, params_seq)
            finally:
                cur.close()

    def executescript(self, sql: str) -> None:
        """Run a multi-statement script (e.g., a migration). SQLite's
        `executescript` implicitly commits any pending transaction before
        running the script; do not wrap in `transaction()`."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.executescript(sql)
            finally:
                cur.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Yield a cursor inside an explicit transaction.

        Commits on context exit; rolls back on any exception.
        """
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                yield cur
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
