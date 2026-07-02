"""UnitConsensusRepository — per-job DB tolerance-consensus evidence (C7 Inc 4).

One row per work unit whose replicas agreed under the declared-envelope reducer
(`builtin_within_cell_tolerance`), written at issuance beside the consensus
promotion. Exact / process_only units have no row: their consensus hash IS a
replica's semantic hash, so there is nothing extra to evidence — and the absence
is load-bearing for backward compatibility (the attestation collector falls back
to the promoted replica's hash for row-less units, so pre-Inc-4 experiments
rebuild byte-identical roots).

Issuance-time persistence is the point (the Inc 2 deferral): raw replica
payloads age off, so the partition/representative/spread cannot be recomputed
later. Everything stored is §7-contained — the representative is composed of
DECLARED features only, the same containment boundary as the payloads.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class UnitConsensusRecord:
    """The persisted evidence for one tolerance-consensus unit."""

    unit_id: str
    method: str
    representative: dict[str, Any] | None
    representative_hash: str | None
    spread: dict[str, float] | None
    envelope: dict[str, Any] | None
    agreeing_workers: int
    outlier_count: int
    recorded_at: str

    def evidence_dict(self) -> dict[str, Any]:
        """The researcher-facing evidence block (attestation predicate / API /
        bundle shape) — one canonical serialization so every surface agrees."""
        return {
            "method": self.method,
            "representative": self.representative,
            "representative_hash": self.representative_hash,
            "spread": self.spread,
            "envelope": self.envelope,
            "agreeing_workers": self.agreeing_workers,
            "outlier_count": self.outlier_count,
        }


class UnitConsensusRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def record(
        self,
        *,
        unit_id: str,
        method: str,
        representative: dict[str, Any] | None,
        representative_hash: str | None,
        spread: dict[str, float] | None,
        envelope: dict[str, Any] | None,
        agreeing_workers: int,
        outlier_count: int,
    ) -> None:
        """Persist (idempotently — re-finalization replaces) the unit's
        tolerance-consensus evidence."""
        self.db.execute(
            """
            INSERT OR REPLACE INTO unit_consensus (
                unit_id, method, representative_json, representative_hash,
                spread_json, envelope_json, agreeing_workers, outlier_count,
                recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                unit_id,
                method,
                json.dumps(representative) if representative is not None else None,
                representative_hash,
                json.dumps(spread) if spread is not None else None,
                json.dumps(envelope) if envelope is not None else None,
                int(agreeing_workers),
                int(outlier_count),
                datetime.now(UTC).isoformat(),
            ),
        )

    # ---- reads ----

    def get(self, unit_id: str) -> UnitConsensusRecord | None:
        rows = self.db.execute("SELECT * FROM unit_consensus WHERE unit_id = ?", (unit_id,))
        return self._row_to_record(rows[0]) if rows else None

    def map_all(self) -> dict[str, UnitConsensusRecord]:
        """{unit_id: record} over the whole experiment — the attestation-build /
        export shape (one query, no per-unit round trips)."""
        rows = self.db.execute("SELECT * FROM unit_consensus ORDER BY unit_id")
        return {r["unit_id"]: self._row_to_record(r) for r in rows}

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row) -> UnitConsensusRecord:
        def _load(col: str):
            raw = row[col]
            return json.loads(raw) if raw else None

        return UnitConsensusRecord(
            unit_id=row["unit_id"],
            method=row["method"],
            representative=_load("representative_json"),
            representative_hash=row["representative_hash"],
            spread=_load("spread_json"),
            envelope=_load("envelope_json"),
            agreeing_workers=row["agreeing_workers"],
            outlier_count=row["outlier_count"],
            recorded_at=row["recorded_at"],
        )
