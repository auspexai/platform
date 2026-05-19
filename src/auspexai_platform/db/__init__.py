"""Storage layer.

SQLite control DB + repository pattern. Single shared connection with WAL
journaling. Threading: `check_same_thread=False` + an internal `threading.RLock`
serializes accesses, which is fine for Phase 1 lab load (single coordinator,
dozens of workers, few experiments) — async route handlers wrap DB calls in
`asyncio.to_thread` when the wait is non-trivial.

Per §5.7 "no premature distributed-systems sophistication": the per-job DB
pattern lands when the first job exists (M6 work units). The control DB and
audit log fit comfortably in one SQLite file.
"""

from auspexai_platform.db.database import Database, DatabaseError
from auspexai_platform.db.migrations import MigrationError, MigrationRunner

__all__ = [
    "Database",
    "DatabaseError",
    "MigrationError",
    "MigrationRunner",
]
