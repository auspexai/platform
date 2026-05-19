"""Migration runner.

Filesystem layout: `migrations_sql/NNNN_name.sql` (NNNN = 4+ digit version,
strictly sequential from 0001). Each file is a multi-statement SQL script.

Application order:
  1. Ensure `schema_migrations` exists.
  2. SELECT applied versions.
  3. Scan migrations_sql/; pick versions not in applied.
  4. For each, executescript() then INSERT into schema_migrations.

`executescript` is run outside an explicit transaction because SQLite's
implementation implicitly commits any pending transaction before executing
the script. Each migration is therefore application-atomic at the SQLite
level for DDL (DDL is implicitly transactional in SQLite). Recording into
schema_migrations is a separate single-statement INSERT that succeeds if
and only if the script completed without error.

If a migration partially fails (rare for DDL), the recording INSERT is
skipped, so on next startup the runner retries — but the partially-applied
state means the retry may fail again. Operator intervention is required in
that case; we don't try to invent rollback for arbitrary SQL.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from auspexai_platform.db.database import Database

MIGRATION_PATTERN = re.compile(r"^(\d{4,})_(.+)\.sql$")
DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations_sql"


class MigrationError(Exception):
    """Raised on malformed migration filenames, non-sequential versions, or
    missing-directory conditions."""


class MigrationRunner:
    def __init__(self, db: Database, migrations_dir: Path | None = None):
        self.db = db
        self.migrations_dir = migrations_dir or DEFAULT_MIGRATIONS_DIR

    # ---- public API ----

    def apply_all(self) -> list[int]:
        """Apply pending migrations. Returns the list of versions applied
        this call (empty if up-to-date)."""
        self._ensure_migrations_table()
        applied_set = set(self._applied_versions())
        applied_now: list[int] = []
        for version, name, sql in self._scan_migrations():
            if version in applied_set:
                continue
            self._apply_one(version, name, sql)
            applied_now.append(version)
        return applied_now

    def applied_versions(self) -> list[int]:
        """Sorted list of versions currently recorded as applied."""
        self._ensure_migrations_table()
        return self._applied_versions()

    def pending_versions(self) -> list[int]:
        """Sorted list of versions present on disk but not yet applied."""
        self._ensure_migrations_table()
        applied_set = set(self._applied_versions())
        return [v for v, _, _ in self._scan_migrations() if v not in applied_set]

    # ---- internals ----

    def _ensure_migrations_table(self) -> None:
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )

    def _applied_versions(self) -> list[int]:
        rows = self.db.execute("SELECT version FROM schema_migrations ORDER BY version")
        return [row["version"] for row in rows]

    def _scan_migrations(self) -> list[tuple[int, str, str]]:
        if not self.migrations_dir.is_dir():
            raise MigrationError(f"migrations directory not found: {self.migrations_dir}")
        migrations: list[tuple[int, str, str]] = []
        for path in sorted(self.migrations_dir.glob("*.sql")):
            match = MIGRATION_PATTERN.match(path.name)
            if not match:
                raise MigrationError(
                    f"migration filename {path.name!r} does not match the NNNN_name.sql pattern"
                )
            version = int(match.group(1))
            name = match.group(2)
            sql = path.read_text(encoding="utf-8")
            migrations.append((version, name, sql))
        # Validate sequential starting at 1.
        for i, (v, _, _) in enumerate(migrations):
            expected = i + 1
            if v != expected:
                raise MigrationError(
                    f"migrations must be sequential starting at 0001; "
                    f"expected {expected:04d} at position {i + 1} but got {v:04d}"
                )
        return migrations

    def _apply_one(self, version: int, name: str, sql: str) -> None:
        self.db.executescript(sql)
        self.db.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (version, name, datetime.now(UTC).isoformat()),
        )
