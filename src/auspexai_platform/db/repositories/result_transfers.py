"""ResultTransferRepository — control-DB custody / proof-of-transfer record
(M-Results, migration 0016).

One row per offload event (export-bundle pull). Permanent and tiny: it proves
Auspex delivered exactly these results (`result_set_root` over the consensus
result hashes) to exactly this collector at this time. `coordinator_signature`
is Ed25519 over the canonical record (the §5.16 receipt-signing key), so the
record is tamper-evident on both sides — the researcher keeps a copy in the
bundle, Auspex keeps this row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class ResultTransfer:
    transfer_id: str
    experiment_id: str
    tenant_id: str
    collected_by_pubkey: str
    collected_at: datetime
    manifest_hash: str
    result_set_root: str
    receipt_count: int
    coordinator_signature: str


class ResultTransferRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        *,
        transfer_id: str,
        experiment_id: str,
        tenant_id: str,
        collected_by_pubkey: str,
        collected_at: datetime,
        manifest_hash: str,
        result_set_root: str,
        receipt_count: int,
        coordinator_signature: str,
    ) -> ResultTransfer:
        self.db.execute(
            """
            INSERT INTO result_transfers (
                transfer_id, experiment_id, tenant_id, collected_by_pubkey,
                collected_at, manifest_hash, result_set_root, receipt_count,
                coordinator_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transfer_id,
                experiment_id,
                tenant_id,
                collected_by_pubkey.lower(),
                collected_at.isoformat(),
                manifest_hash,
                result_set_root,
                receipt_count,
                coordinator_signature,
            ),
        )
        got = self.get_by_id(transfer_id)
        assert got is not None
        return got

    def get_by_id(self, transfer_id: str) -> ResultTransfer | None:
        rows = self.db.execute(
            "SELECT * FROM result_transfers WHERE transfer_id = ?", (transfer_id,)
        )
        return self._row(rows[0]) if rows else None

    def list_for_experiment(self, experiment_id: str) -> list[ResultTransfer]:
        rows = self.db.execute(
            "SELECT * FROM result_transfers WHERE experiment_id = ? ORDER BY collected_at DESC",
            (experiment_id,),
        )
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(row) -> ResultTransfer:
        return ResultTransfer(
            transfer_id=row["transfer_id"],
            experiment_id=row["experiment_id"],
            tenant_id=row["tenant_id"],
            collected_by_pubkey=row["collected_by_pubkey"],
            collected_at=datetime.fromisoformat(row["collected_at"]),
            manifest_hash=row["manifest_hash"],
            result_set_root=row["result_set_root"],
            receipt_count=row["receipt_count"],
            coordinator_signature=row["coordinator_signature"],
        )
