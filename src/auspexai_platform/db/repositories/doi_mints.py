"""DoiMintRepository — crash-safe bookkeeping that makes the Zenodo DOI mint
idempotent + resumable (0060).

One row per experiment. `record_draft` is called the instant the Zenodo draft is
reserved — BEFORE the irreversible publish — so the record id + reserved DOI
survive a mid-mint crash. On retry the route reads `get(experiment_id)` and hands
the record id to the client, which reconciles against Zenodo rather than minting
anew: already published → return that DOI (no duplicate); still a draft → resume
it (no new orphan). `mark_published` records the terminal DOI once it lands.
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class DoiMint:
    experiment_id: str
    attestation_id: str
    record_id: str | None
    reserved_doi: str | None
    status: str  # draft | published
    doi: str | None
    record_url: str | None
    mode: str | None
    created_at: str
    updated_at: str


class DoiMintRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record_draft(
        self,
        experiment_id: str,
        *,
        attestation_id: str,
        record_id: str,
        reserved_doi: str | None,
        mode: str | None,
    ) -> None:
        """Persist the reserved Zenodo draft (status='draft') BEFORE publish, so a
        crashed mint is resumable. Idempotent per experiment — re-reserving simply
        refreshes the record id/reserved DOI (never downgrades a published row)."""
        self.db.execute(
            """
            INSERT INTO doi_mints
                (experiment_id, attestation_id, record_id, reserved_doi, status, mode, updated_at)
            VALUES (?, ?, ?, ?, 'draft', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(experiment_id) DO UPDATE SET
                attestation_id = excluded.attestation_id,
                record_id      = excluded.record_id,
                reserved_doi   = excluded.reserved_doi,
                mode           = excluded.mode,
                -- never walk a published mint back to draft
                status         = CASE WHEN doi_mints.status = 'published'
                                      THEN 'published' ELSE 'draft' END,
                updated_at     = CURRENT_TIMESTAMP
            """,
            (experiment_id, attestation_id, record_id, reserved_doi, mode),
        )

    def mark_published(
        self,
        experiment_id: str,
        *,
        doi: str,
        record_url: str | None,
        mode: str | None = None,
    ) -> None:
        """Record the terminal published DOI. Idempotent — a resumed mint that
        re-observes the same DOI just re-stamps it."""
        self.db.execute(
            """
            INSERT INTO doi_mints
                (experiment_id, attestation_id, status, doi, record_url, mode, updated_at)
            VALUES (?, '', 'published', ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(experiment_id) DO UPDATE SET
                status     = 'published',
                doi        = excluded.doi,
                record_url = excluded.record_url,
                mode       = COALESCE(excluded.mode, doi_mints.mode),
                updated_at = CURRENT_TIMESTAMP
            """,
            (experiment_id, doi, record_url, mode),
        )

    def get(self, experiment_id: str) -> DoiMint | None:
        rows = self.db.execute("SELECT * FROM doi_mints WHERE experiment_id = ?", (experiment_id,))
        if not rows:
            return None
        r = rows[0]
        return DoiMint(
            experiment_id=r["experiment_id"],
            attestation_id=r["attestation_id"],
            record_id=r["record_id"],
            reserved_doi=r["reserved_doi"],
            status=r["status"],
            doi=r["doi"],
            record_url=r["record_url"],
            mode=r["mode"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        )
