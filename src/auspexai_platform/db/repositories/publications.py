"""Publication records (G6+F4, ratified 2026-07-06) — the coordinator-side
memory of researcher publication actions: benchmark publications (R1+) and
DOI mints (R3). Written at authorization time; read by the console experiment
page and by the DOI prerequisite gate (benchmark-before-DOI, USER req #5)."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class PublicationRecord:
    record_id: str
    experiment_id: str
    kind: str  # 'benchmark' | 'doi'
    tenant_id: str
    publisher_pubkey: str
    standing_at_issue: int
    summary: dict[str, Any]  # researcher-signed CLAIM (never re-scored)
    obs_merkle_root: str | None
    obs_rekor_uuid: str | None
    ref_merkle_root: str | None
    ref_rekor_uuid: str | None
    doi: str | None
    created_at: str


class PublicationRepository:
    def __init__(self, db: Database):
        self.db = db

    def record(
        self,
        *,
        experiment_id: str,
        kind: str,
        tenant_id: str,
        publisher_pubkey: str,
        standing_at_issue: int,
        summary: dict[str, Any],
        obs_merkle_root: str | None = None,
        obs_rekor_uuid: str | None = None,
        ref_merkle_root: str | None = None,
        ref_rekor_uuid: str | None = None,
        doi: str | None = None,
    ) -> PublicationRecord:
        rid = f"pub-{secrets.token_urlsafe(9)}"
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO publication_records (
                record_id, experiment_id, kind, tenant_id, publisher_pubkey,
                standing_at_issue, summary_json, obs_merkle_root, obs_rekor_uuid,
                ref_merkle_root, ref_rekor_uuid, doi, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                experiment_id,
                kind,
                tenant_id,
                publisher_pubkey,
                int(standing_at_issue),
                json.dumps(summary),
                obs_merkle_root,
                obs_rekor_uuid,
                ref_merkle_root,
                ref_rekor_uuid,
                doi,
                now,
            ),
        )
        return self.get(rid)  # round-trip: return what was persisted

    def get(self, record_id: str) -> PublicationRecord:
        rows = self.db.execute(
            "SELECT * FROM publication_records WHERE record_id = ?", (record_id,)
        )
        return self._to_record(rows[0])

    def list_for_experiment(
        self, experiment_id: str, kind: str | None = None
    ) -> list[PublicationRecord]:
        if kind:
            rows = self.db.execute(
                "SELECT * FROM publication_records WHERE experiment_id = ? AND kind = ? "
                "ORDER BY created_at",
                (experiment_id, kind),
            )
        else:
            rows = self.db.execute(
                "SELECT * FROM publication_records WHERE experiment_id = ? ORDER BY created_at",
                (experiment_id,),
            )
        return [self._to_record(r) for r in rows]

    def has_benchmark_publication(self, experiment_id: str) -> bool:
        """The DOI prerequisite (benchmark-before-DOI): refused coordinator-side
        without at least one benchmark publication record."""
        return bool(self.list_for_experiment(experiment_id, kind="benchmark"))

    @staticmethod
    def _to_record(row) -> PublicationRecord:
        return PublicationRecord(
            record_id=row["record_id"],
            experiment_id=row["experiment_id"],
            kind=row["kind"],
            tenant_id=row["tenant_id"],
            publisher_pubkey=row["publisher_pubkey"],
            standing_at_issue=row["standing_at_issue"],
            summary=json.loads(row["summary_json"]),
            obs_merkle_root=row["obs_merkle_root"],
            obs_rekor_uuid=row["obs_rekor_uuid"],
            ref_merkle_root=row["ref_merkle_root"],
            ref_rekor_uuid=row["ref_rekor_uuid"],
            doi=row["doi"],
            created_at=row["created_at"],
        )
