"""WorkerRepository — Ed25519-keyed worker daemons.

CRUD over the `workers` table. The auth-side `WorkerRegistry` delegates
its `get_worker_for_pubkey` lookup here; the rest of the surface is what
the M6b worker routes need (enroll, upgrade, heartbeat, retire, list).

`capabilities` is stored as JSON text in the column; this repo serializes/
deserializes via `json` on write / read. The dict is opaque to v0 — the
M6d scheduler parses specific keys but the repo doesn't validate the
shape.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import TrustTier, Worker


class DuplicateWorkerError(Exception):
    """Raised when a worker_id or pubkey_hex is already registered."""


class WorkerNotFoundError(Exception):
    """Raised when a worker_id is unknown."""


class WorkerRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def enroll(
        self,
        *,
        worker_id: str,
        pubkey_hex: str,
        capabilities: dict[str, Any] | None = None,
        trust_tier: TrustTier = TrustTier.T0_ANONYMOUS,
    ) -> Worker:
        """Insert a worker. Raises DuplicateWorkerError on PK or unique-pubkey conflict."""
        pubkey_hex = pubkey_hex.lower()
        capabilities_json = json.dumps(capabilities or {})
        registered_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO workers (
                    worker_id, pubkey_hex, account_id, trust_tier,
                    capabilities_json, registered_at
                ) VALUES (?, ?, NULL, ?, ?, ?)
                """,
                (
                    worker_id,
                    pubkey_hex,
                    int(trust_tier),
                    capabilities_json,
                    registered_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateWorkerError(str(e)) from e
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def bind_account(
        self,
        worker_id: str,
        *,
        account_id: str,
        trust_tier: TrustTier,
    ) -> Worker:
        """Bind a worker to an account and bump its trust tier (T0→T1 on M6a
        binding-token upgrade). Raises WorkerNotFoundError if no such worker."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET account_id = ?, trust_tier = ?
                WHERE worker_id = ? AND retired_at IS NULL
                """,
                (account_id, int(trust_tier), worker_id),
            )
            if cur.rowcount == 0:
                raise WorkerNotFoundError(worker_id)
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def record_heartbeat(
        self,
        worker_id: str,
        *,
        capabilities: dict[str, Any] | None = None,
    ) -> Worker:
        """Update last_heartbeat_at (and capabilities if supplied). Raises
        WorkerNotFoundError if no such worker or worker is retired."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            if capabilities is not None:
                cur.execute(
                    """
                    UPDATE workers
                    SET last_heartbeat_at = ?, capabilities_json = ?
                    WHERE worker_id = ? AND retired_at IS NULL
                    """,
                    (now, json.dumps(capabilities), worker_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE workers
                    SET last_heartbeat_at = ?
                    WHERE worker_id = ? AND retired_at IS NULL
                    """,
                    (now, worker_id),
                )
            if cur.rowcount == 0:
                raise WorkerNotFoundError(worker_id)
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def retire(self, worker_id: str) -> Worker:
        """Soft-delete a worker. Idempotent (re-retire is a no-op).
        Raises WorkerNotFoundError if the worker_id is unknown."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET retired_at = COALESCE(retired_at, ?)
                WHERE worker_id = ?
                """,
                (now, worker_id),
            )
            if cur.rowcount == 0:
                raise WorkerNotFoundError(worker_id)
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, worker_id: str) -> Worker | None:
        rows = self.db.execute(
            "SELECT * FROM workers WHERE worker_id = ?",
            (worker_id,),
        )
        return self._row_to_worker(rows[0]) if rows else None

    def get_by_pubkey(self, pubkey_hex: str) -> Worker | None:
        rows = self.db.execute(
            "SELECT * FROM workers WHERE pubkey_hex = ?",
            (pubkey_hex.lower(),),
        )
        return self._row_to_worker(rows[0]) if rows else None

    def list_for_account(self, account_id: str) -> list[Worker]:
        rows = self.db.execute(
            "SELECT * FROM workers WHERE account_id = ? ORDER BY registered_at",
            (account_id,),
        )
        return [self._row_to_worker(r) for r in rows]

    def list_all(self) -> list[Worker]:
        rows = self.db.execute("SELECT * FROM workers ORDER BY registered_at")
        return [self._row_to_worker(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_worker(row: sqlite3.Row) -> Worker:
        return Worker(
            worker_id=row["worker_id"],
            pubkey_hex=row["pubkey_hex"],
            account_id=row["account_id"],
            trust_tier=TrustTier(row["trust_tier"]),
            capabilities=json.loads(row["capabilities_json"]),
            registered_at=datetime.fromisoformat(row["registered_at"]),
            last_heartbeat_at=(
                datetime.fromisoformat(row["last_heartbeat_at"])
                if row["last_heartbeat_at"]
                else None
            ),
            retired_at=(datetime.fromisoformat(row["retired_at"]) if row["retired_at"] else None),
        )
