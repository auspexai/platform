"""ReceiptRepository — receipts table on per-job DB.

Receipts live on the per-job DB rather than the control DB because they're
scoped to one experiment (per the receipt schema's `experiment_id` field).
Each experiment's receipts file at `<jobs_dir>/<experiment_id>.db`.

Per the M7b storage decision: each row carries both the canonical
COSE-Sign1 bytes (the wire form a verifier consumes) AND the inner CBOR
payload (handy for debugging / aggregation queries / future Rekor
anchoring). Storing both is a few hundred bytes per receipt — acceptable
overhead at Phase 1 lab scale.

For "list receipts that cover this unit_id" queries, the work_unit_ids
field is a JSON-encoded array in the receipts row. Linear scan is fine
at Phase 1 lab volumes; defer a junction table to Phase 2 if a tenant's
aggregation patterns demand it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


class DuplicateReceiptError(Exception):
    """Raised when the same receipt_id is inserted twice."""


@dataclass(frozen=True)
class ReceiptRecord:
    """A stored receipt — both the canonical COSE bytes and the inner CBOR.

    The schema-versioning policy (§11 Q20) commits to "honor any
    recognized version forever," so this row stays parseable indefinitely.
    """

    receipt_id: str
    work_unit_ids: list[str]
    cose_signed_blob: bytes
    receipt_body_cbor: bytes
    signing_key_pubkey_hex: str
    issued_at: datetime


class ReceiptRepository:
    """Per-job-DB receipt rows."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        receipt_id: str,
        work_unit_ids: list[str],
        cose_signed_blob: bytes,
        receipt_body_cbor: bytes,
        signing_key_pubkey_hex: str,
    ) -> ReceiptRecord:
        """Insert a newly-issued receipt. Raises DuplicateReceiptError if the
        receipt_id is already present."""
        issued_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO receipts (
                    receipt_id, work_unit_ids_json, cose_signed_blob,
                    receipt_body_cbor, signing_key_pubkey_hex, issued_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    json.dumps(work_unit_ids),
                    cose_signed_blob,
                    receipt_body_cbor,
                    signing_key_pubkey_hex.lower(),
                    issued_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateReceiptError(str(e)) from e
        got = self.get_by_id(receipt_id)
        assert got is not None
        return got

    # ---- reads ----

    def get_by_id(self, receipt_id: str) -> ReceiptRecord | None:
        rows = self.db.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        )
        return self._row_to_record(rows[0]) if rows else None

    def list_for_unit(self, unit_id: str) -> list[ReceiptRecord]:
        """Linear scan + JSON-membership test. Acceptable at Phase 1 lab volumes."""
        rows = self.db.execute("SELECT * FROM receipts ORDER BY issued_at")
        results = []
        for row in rows:
            ids = json.loads(row["work_unit_ids_json"])
            if unit_id in ids:
                results.append(self._row_to_record(row))
        return results

    def list_all(self) -> list[ReceiptRecord]:
        rows = self.db.execute("SELECT * FROM receipts ORDER BY issued_at DESC")
        return [self._row_to_record(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ReceiptRecord:
        return ReceiptRecord(
            receipt_id=row["receipt_id"],
            work_unit_ids=json.loads(row["work_unit_ids_json"]),
            cose_signed_blob=row["cose_signed_blob"],
            receipt_body_cbor=row["receipt_body_cbor"],
            signing_key_pubkey_hex=row["signing_key_pubkey_hex"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
        )
