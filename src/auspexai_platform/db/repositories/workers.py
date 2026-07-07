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

    def unbind(self, worker_id: str) -> Worker:
        """Drop a worker's account binding (account_id -> NULL, trust_tier -> T0) WITHOUT
        retiring it: the worker keeps running, anonymous. The inverse of bind_account -- the
        worker logout. Receipts already issued stay credited to the account they were earned
        under (the account_id_at_issue snapshot, 0041). Raises WorkerNotFoundError if no such
        (non-retired) worker; idempotent on an already-anonymous worker."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET account_id = NULL, trust_tier = ?
                WHERE worker_id = ? AND retired_at IS NULL
                """,
                (int(TrustTier.T0_ANONYMOUS), worker_id),
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

    def quarantine(self, worker_id: str, reason: str | None = None) -> Worker:
        """Mark a worker as quarantined — they remain enrolled, can heartbeat,
        but the assignment endpoint refuses to give them work. Reversible
        via unquarantine. Idempotent on re-quarantine (timestamp preserved
        on first call; reason can be updated on subsequent calls).
        Raises WorkerNotFoundError if the worker_id is unknown.
        Raises ValueError if the worker is retired (retire is terminal;
        quarantine doesn't apply to a worker that's already left the
        network)."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET quarantined_at = COALESCE(quarantined_at, ?),
                    quarantine_reason = ?
                WHERE worker_id = ? AND retired_at IS NULL
                """,
                (now, reason, worker_id),
            )
            if cur.rowcount == 0:
                # Distinguish "no such worker" from "retired worker".
                existing = self.get_by_id(worker_id)
                if existing is None:
                    raise WorkerNotFoundError(worker_id)
                raise ValueError(f"worker {worker_id} is retired; quarantine does not apply")
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def unquarantine(self, worker_id: str) -> Worker:
        """Clear quarantine on a worker. Idempotent (no-op if not quarantined).
        Raises WorkerNotFoundError if the worker_id is unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET quarantined_at = NULL,
                    quarantine_reason = NULL
                WHERE worker_id = ?
                """,
                (worker_id,),
            )
            if cur.rowcount == 0:
                raise WorkerNotFoundError(worker_id)
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def pause(self, worker_id: str, reason: str | None = None) -> Worker:
        """Mark a worker as paused — an OPERATIONAL pause (stop assigning), not a
        fault. Reversible via unpause; idempotent (timestamp preserved, reason
        refreshed). The `reason` is surfaced to the worker via the /assignments
        423 (§2.1 #11 — transparent, no-fault). Raises WorkerNotFoundError if
        unknown, ValueError if retired."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE workers SET paused_at = COALESCE(paused_at, ?), pause_reason = ? "
                "WHERE worker_id = ? AND retired_at IS NULL",
                (now, reason, worker_id),
            )
            if cur.rowcount == 0:
                if self.get_by_id(worker_id) is None:
                    raise WorkerNotFoundError(worker_id)
                raise ValueError(f"worker {worker_id} is retired; pause does not apply")
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def unpause(self, worker_id: str) -> Worker:
        """Clear pause on a worker. Idempotent. Raises WorkerNotFoundError if unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE workers SET paused_at = NULL, pause_reason = NULL WHERE worker_id = ?",
                (worker_id,),
            )
            if cur.rowcount == 0:
                raise WorkerNotFoundError(worker_id)
        got = self.get_by_id(worker_id)
        assert got is not None
        return got

    def update_tier_for_account(
        self,
        account_id: str,
        *,
        trust_tier: TrustTier,
    ) -> list[str]:
        """Propagate a tier change to all active (non-retired) workers bound to
        an account. Returns the list of affected worker_ids."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers SET trust_tier = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (int(trust_tier), account_id),
            )
            cur.execute(
                """
                SELECT worker_id FROM workers
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (account_id,),
            )
            return [row["worker_id"] for row in cur.fetchall()]

    def quarantine_for_account(self, account_id: str, reason: str | None = None) -> list[str]:
        """Quarantine all active workers bound to an account atomically.
        Returns affected worker_ids."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET quarantined_at = COALESCE(quarantined_at, ?),
                    quarantine_reason = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (now, reason, account_id),
            )
            cur.execute(
                """
                SELECT worker_id FROM workers
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (account_id,),
            )
            return [row["worker_id"] for row in cur.fetchall()]

    def unquarantine_for_account(self, account_id: str) -> list[str]:
        """Clear quarantine on all workers bound to an account.
        Returns affected worker_ids."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE workers
                SET quarantined_at = NULL, quarantine_reason = NULL
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (account_id,),
            )
            cur.execute(
                """
                SELECT worker_id FROM workers
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (account_id,),
            )
            return [row["worker_id"] for row in cur.fetchall()]

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

    def count_active(self, *, heartbeat_cutoff: datetime) -> int:
        """Count workers that are 'active' network-wide: enrolled, not retired,
        not quarantined, and heartbeating since `heartbeat_cutoff`.

        Backs the network-size signal shown to researchers (activity rollup) and
        workers (health). The cutoff is supplied by the caller so the freshness
        window (`worker_status.STALE_HEARTBEAT_MINUTES`) stays in one place."""
        rows = self.db.execute(
            "SELECT COUNT(*) AS n FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        return int(rows[0]["n"]) if rows else 0

    def count_capable(self, *, required_models: list[str], heartbeat_cutoff: datetime) -> int:
        """Count active workers (same set as `count_active`) whose declared model
        inventory holds EVERY model in `required_models` (#30 / M1). Empty
        `required_models` ⇒ identical to `count_active`. The active-set SQL filter
        keeps it cheap; the capability check is in Python because `capabilities`
        is an opaque JSON blob. Backs the activity rollup's 'empty pool' signal."""
        need = set(required_models)
        rows = self.db.execute(
            "SELECT capabilities_json FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        if not need:
            return len(rows)
        n = 0
        for r in rows:
            caps = json.loads(r["capabilities_json"] or "{}")
            have = caps.get("models", [])
            if isinstance(have, list) and need <= set(have):
                n += 1
        return n

    def list_capable_ids(
        self, *, required_models: list[str], heartbeat_cutoff: datetime
    ) -> list[str]:
        """The worker_ids behind `count_capable` — active workers whose declared
        inventory holds every required model. Used to intersect with the
        currently-busy set (active-assignment holders) for the D12 'X of Y
        eligible workers busy' capacity signal."""
        need = set(required_models)
        rows = self.db.execute(
            "SELECT worker_id, capabilities_json FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        if not need:
            return [r["worker_id"] for r in rows]
        out: list[str] = []
        for r in rows:
            caps = json.loads(r["capabilities_json"] or "{}")
            have = caps.get("models", [])
            if isinstance(have, list) and need <= set(have):
                out.append(r["worker_id"])
        return out

    def active_capabilities(self, *, heartbeat_cutoff: datetime) -> list[dict]:
        """Parsed `capabilities` of every ACTIVE worker (same predicate as
        `count_active`) — the raw material for the top-down supported-models
        overlay (`GET /models/supported`): which supported models are served
        now (`models`), which the fleet could pull (`auto_acquire`), and whether
        a worker is big enough (`ram_total_gb`, often null — treat as unknown,
        never as 'too small'). Identity-free; returns the capability dicts only."""
        rows = self.db.execute(
            "SELECT capabilities_json FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        out: list[dict] = []
        for r in rows:
            caps = json.loads(r["capabilities_json"] or "{}")
            if isinstance(caps, dict):
                out.append(caps)
        return out

    def count_auto_acquire(self, *, heartbeat_cutoff: datetime) -> int:
        """Count active workers that have opted into M3 lazy auto-acquire — they
        can run ANY model whose manifest carries hf coords by pulling it in-line
        (#44, proven live). Backs the model-request triage: an acquirable model
        reads as `acquirable` rather than escalating to maintainer review."""
        rows = self.db.execute(
            "SELECT capabilities_json FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        return sum(
            1
            for r in rows
            if json.loads(r["capabilities_json"] or "{}").get("auto_acquire") is True
        )

    def model_inventory_counts(self, *, heartbeat_cutoff: datetime) -> dict[str, int]:
        """The network's bottom-up model catalog (M2): {model_id: how many active
        workers declare it}, aggregated across the active set (same predicate as
        `count_active`). Identity-free — backs `GET /models/catalog`."""
        rows = self.db.execute(
            "SELECT capabilities_json FROM workers "
            "WHERE retired_at IS NULL AND quarantined_at IS NULL AND paused_at IS NULL "
            "AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (heartbeat_cutoff.isoformat(),),
        )
        counts: dict[str, int] = {}
        for r in rows:
            caps = json.loads(r["capabilities_json"] or "{}")
            have = caps.get("models", [])
            if not isinstance(have, list):
                continue
            for mid in have:
                if isinstance(mid, str):
                    counts[mid] = counts.get(mid, 0) + 1
        return counts

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
            quarantined_at=(
                datetime.fromisoformat(row["quarantined_at"]) if row["quarantined_at"] else None
            ),
            quarantine_reason=row["quarantine_reason"],
            paused_at=(datetime.fromisoformat(row["paused_at"]) if row["paused_at"] else None),
            pause_reason=row["pause_reason"] if "pause_reason" in row.keys() else None,
        )
