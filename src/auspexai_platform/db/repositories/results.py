"""ResultRepository — per-job DB results table.

Stores the SDK Result envelope verbatim plus coordinator-side metadata.
The `worker_signature` is stored as base64; v0 does not verify it (M7 is
where receipts ratify the body-level signature chain). The HTTP-level
RFC 9421 signature is the M6d acceptance check.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Result
from auspexai_platform.hashing import semantic_hash


class DuplicateResultError(Exception):
    """Raised when a result_id collides."""


class ResultRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        result_id: str,
        unit_id: str,
        worker_id: str,
        worker_pubkey_hex: str,
        exit_code: int,
        payload: dict[str, Any],
        worker_signature: str,
        completed_at: datetime,
        environment: dict[str, Any] | None = None,
        schema_version: int | None = None,
        served_weights: dict[str, str] | None = None,
        ran_under: str | None = None,
    ) -> Result:
        received_at = datetime.now(UTC).isoformat()
        # M-Results: persist the semantic hash at insert so an aged-off row still
        # self-describes its content (the agreement reducer recomputes the same
        # value via the shared helper).
        sem_hash = semantic_hash(exit_code, payload)
        try:
            self.db.execute(
                """
                INSERT INTO results (
                    result_id, unit_id, worker_id, worker_pubkey_hex,
                    exit_code, payload_json, worker_signature,
                    completed_at, received_at, semantic_hash, environment_json,
                    schema_version, served_weights_json, ran_under
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    unit_id,
                    worker_id,
                    worker_pubkey_hex.lower(),
                    exit_code,
                    json.dumps(payload),
                    worker_signature,
                    completed_at.isoformat(),
                    received_at,
                    sem_hash,
                    # EB-1: coordinator-asserted serving-environment snapshot at
                    # submission (the reproducibility triple's environment leg).
                    json.dumps(environment) if environment else None,
                    # §9 #13a: the worker-signed schema version + attested
                    # served-weights digest (covered by worker_signature).
                    schema_version,
                    json.dumps(served_weights) if served_weights is not None else None,
                    # A2 #32: the worker-signed sandbox policy (covered by
                    # worker_signature). NULL for pre-v2 results.
                    ran_under,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateResultError(str(e)) from e
        got = self.get_by_id(result_id)
        assert got is not None
        return got

    def promote_consensus(self, unit_id: str, agreed_result_id: str) -> None:
        """Mark `agreed_result_id` as the unit's durable T-C consensus copy and
        unmark any others (idempotent). Called on quorum agreement — all of a
        unit's agreeing results are byte-identical, so any one is the consensus
        payload; the rest are T-X replicas that age off first."""
        self.db.execute(
            "UPDATE results SET is_consensus = CASE WHEN result_id = ? THEN 1 ELSE 0 END "
            "WHERE unit_id = ?",
            (agreed_result_id, unit_id),
        )

    def mark_delivered(self, result_ids: list[str]) -> None:
        """Stamp `delivered_at = now` on first delivery (never overwrites)."""
        if not result_ids:
            return
        now = datetime.now(UTC).isoformat()
        placeholders = ",".join("?" for _ in result_ids)
        self.db.execute(
            f"UPDATE results SET delivered_at = ? "
            f"WHERE result_id IN ({placeholders}) AND delivered_at IS NULL",
            (now, *result_ids),
        )

    def age_off(self, result_ids: list[str], *, expires_at: datetime | None = None) -> int:
        """Blank `payload_json` (to '') and stamp `payload_aged_off_at` for each
        result — the row, signature, pubkey, and semantic_hash survive so the
        receipt still verifies and provenance is intact. Returns rows changed.
        Never `DELETE`s. Idempotent (skips already-aged rows)."""
        if not result_ids:
            return 0
        now = datetime.now(UTC).isoformat()
        placeholders = ",".join("?" for _ in result_ids)
        rows = self.db.execute(
            f"UPDATE results SET payload_json = '', payload_aged_off_at = ?, "
            f"payload_expires_at = ? "
            f"WHERE result_id IN ({placeholders}) AND payload_aged_off_at IS NULL "
            f"RETURNING result_id",
            (now, expires_at.isoformat() if expires_at else None, *result_ids),
        )
        return len(rows)

    # ---- reads ----

    def get_by_id(self, result_id: str) -> Result | None:
        rows = self.db.execute(
            "SELECT * FROM results WHERE result_id = ?",
            (result_id,),
        )
        return self._row_to_result(rows[0]) if rows else None

    def list_for_unit(self, unit_id: str) -> list[Result]:
        rows = self.db.execute(
            "SELECT * FROM results WHERE unit_id = ? ORDER BY received_at",
            (unit_id,),
        )
        return [self._row_to_result(r) for r in rows]

    def count_distinct_workers(self) -> int:
        """Number of distinct workers that have submitted >=1 result.

        Integer only — backs the anonymized active-contributor count; never
        exposes *which* workers (volunteer-anonymity rule)."""
        rows = self.db.execute("SELECT COUNT(DISTINCT worker_id) AS n FROM results")
        return int(rows[0]["n"]) if rows else 0

    def latest_received_at(self) -> datetime | None:
        """Most recent result `received_at` across the experiment, or None if no
        results have been submitted yet."""
        rows = self.db.execute("SELECT MAX(received_at) AS latest FROM results")
        latest = rows[0]["latest"] if rows else None
        return datetime.fromisoformat(latest) if latest else None

    def per_worker_contributions(self) -> list[dict[str, Any]]:
        """One aggregate row per distinct contributing worker: its result count,
        pubkey, and last submission time.

        This per-job repository has no account knowledge — it returns *every*
        worker. The caller (the activity rollup) filters to the tenant's own
        account for R-D3 own-worker enrichment; third-party workers stay folded
        into the anonymized `active_contributor_count` and never surface here.
        """
        rows = self.db.execute(
            "SELECT worker_id, worker_pubkey_hex, COUNT(*) AS result_count, "
            "MAX(received_at) AS last_received_at "
            "FROM results GROUP BY worker_id, worker_pubkey_hex"
        )
        return [
            {
                "worker_id": r["worker_id"],
                "worker_pubkey_hex": r["worker_pubkey_hex"],
                "result_count": int(r["result_count"]),
                "last_received_at": (
                    datetime.fromisoformat(r["last_received_at"]) if r["last_received_at"] else None
                ),
            }
            for r in rows
        ]

    def list_consensus(
        self,
        *,
        limit: int,
        after_completed_at: str | None = None,
        after_result_id: str | None = None,
    ) -> list[Result]:
        """The durable T-C copies (one per completed unit), paginated by the
        (completed_at, result_id) cursor."""
        return self._list_paginated(
            where="is_consensus = 1",
            limit=limit,
            after_completed_at=after_completed_at,
            after_result_id=after_result_id,
        )

    def list_all(
        self,
        *,
        limit: int,
        after_completed_at: str | None = None,
        after_result_id: str | None = None,
    ) -> list[Result]:
        """All results incl. T-X replicas (`?include=raw`), paginated."""
        return self._list_paginated(
            where="1 = 1",
            limit=limit,
            after_completed_at=after_completed_at,
            after_result_id=after_result_id,
        )

    def list_active_payloads(self) -> list[Result]:
        """Every result that still holds its payload (not yet aged off) — the
        candidate set the age-off sweep computes horizons over."""
        rows = self.db.execute(
            "SELECT * FROM results WHERE payload_aged_off_at IS NULL "
            "ORDER BY completed_at, result_id"
        )
        return [self._row_to_result(r) for r in rows]

    def _list_paginated(
        self,
        *,
        where: str,
        limit: int,
        after_completed_at: str | None,
        after_result_id: str | None,
    ) -> list[Result]:
        params: list[Any] = []
        cursor_clause = ""
        if after_completed_at is not None and after_result_id is not None:
            # Row-value cursor: stable forward pagination over the composite key.
            cursor_clause = " AND (completed_at, result_id) > (?, ?)"
            params.extend([after_completed_at, after_result_id])
        params.append(limit)
        rows = self.db.execute(
            f"SELECT * FROM results WHERE {where}{cursor_clause} "
            f"ORDER BY completed_at, result_id LIMIT ?",
            tuple(params),
        )
        return [self._row_to_result(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> Result:
        def _dt(value: str | None) -> datetime | None:
            return datetime.fromisoformat(value) if value else None

        payload_json = row["payload_json"]
        return Result(
            result_id=row["result_id"],
            unit_id=row["unit_id"],
            worker_id=row["worker_id"],
            worker_pubkey_hex=row["worker_pubkey_hex"],
            exit_code=row["exit_code"],
            # Aged-off rows carry '' (payload blanked); surface as empty dict.
            payload=json.loads(payload_json) if payload_json else {},
            worker_signature=row["worker_signature"],
            completed_at=datetime.fromisoformat(row["completed_at"]),
            received_at=datetime.fromisoformat(row["received_at"]),
            semantic_hash=row["semantic_hash"],
            is_consensus=bool(row["is_consensus"]),
            delivered_at=_dt(row["delivered_at"]),
            payload_expires_at=_dt(row["payload_expires_at"]),
            payload_aged_off_at=_dt(row["payload_aged_off_at"]),
            environment=(json.loads(row["environment_json"]) if row["environment_json"] else None),
            # §9 #13a: worker-signed version + attested served-weights digest.
            schema_version=row["schema_version"],
            served_weights=(
                json.loads(row["served_weights_json"]) if row["served_weights_json"] else None
            ),
            # A2 #32: worker-signed sandbox policy (covered by worker_signature).
            ran_under=row["ran_under"],
        )
