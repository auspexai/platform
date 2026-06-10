"""SoftwareRequestRepository — code-plane requirements queue (§9 #46, migration 0024).

The software analog of the model_requests demand board: a researcher's request
for a worker-baseline capability. Carries an assessment stage (dependencies /
security / alternatives, with a draft flag for unratified auto-drafts) ahead of
the audited approve/decline, and a release linkage stamped when a recorded
release fulfils it. See `0024_software_requests.sql` for the state model.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


def _generate_request_id() -> str:
    """Coordinator-side id: `swr-<random 8 chars>`."""
    return f"swr-{secrets.token_urlsafe(6)[:8]}"


@dataclass(frozen=True)
class SoftwareRequest:
    request_id: str
    tenant_id: str
    title: str
    description: str
    reason: str
    status: str  # pending | assessed | approved | declined | released
    created_at: datetime
    assessment_json: str | None
    assessment_draft: bool
    assessed_at: datetime | None
    assessed_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_reason: str | None
    release_version: str | None
    released_at: datetime | None


class SoftwareRequestRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self, *, tenant_id: str, title: str, description: str, reason: str
    ) -> SoftwareRequest:
        request_id = _generate_request_id()
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO software_requests (
                request_id, tenant_id, title, description, reason, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (request_id, tenant_id, title, description, reason, created_at),
        )
        got = self.get_by_id(request_id)
        assert got is not None
        return got

    def get_by_id(self, request_id: str) -> SoftwareRequest | None:
        rows = self.db.execute(
            "SELECT * FROM software_requests WHERE request_id = ?", (request_id,)
        )
        return self._row(rows[0]) if rows else None

    def list(
        self, *, status: str | None = None, tenant_id: str | None = None
    ) -> list[SoftwareRequest]:
        clauses: list[str] = []
        params: list[str] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.execute(
            f"SELECT * FROM software_requests{where} ORDER BY created_at DESC", tuple(params)
        )
        return [self._row(r) for r in rows]

    def attach_assessment(
        self, request_id: str, *, assessment_json: str, assessed_by: str, draft: bool
    ) -> SoftwareRequest | None:
        """Attach (or re-attach) the assessment; status moves to `assessed`.

        A ratification is just a re-attach with draft=False — the previous blob
        is overwritten; history lives in the audit log.
        """
        self.db.execute(
            """
            UPDATE software_requests
            SET assessment_json = ?, assessment_draft = ?, assessed_at = ?,
                assessed_by = ?, status = 'assessed'
            WHERE request_id = ?
            """,
            (
                assessment_json,
                1 if draft else 0,
                datetime.now(UTC).isoformat(),
                assessed_by,
                request_id,
            ),
        )
        return self.get_by_id(request_id)

    def resolve(
        self, request_id: str, *, status: str, resolved_by: str, reason: str
    ) -> SoftwareRequest | None:
        """Mark a request approved/declined with a mandatory reason + attribution."""
        self.db.execute(
            """
            UPDATE software_requests
            SET status = ?, resolved_at = ?, resolved_by = ?, resolution_reason = ?
            WHERE request_id = ?
            """,
            (status, datetime.now(UTC).isoformat(), resolved_by, reason, request_id),
        )
        return self.get_by_id(request_id)

    def mark_released(self, request_id: str, *, release_version: str) -> SoftwareRequest | None:
        self.db.execute(
            """
            UPDATE software_requests
            SET status = 'released', release_version = ?, released_at = ?
            WHERE request_id = ?
            """,
            (release_version, datetime.now(UTC).isoformat(), request_id),
        )
        return self.get_by_id(request_id)

    @staticmethod
    def _row(row) -> SoftwareRequest:
        return SoftwareRequest(
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            title=row["title"],
            description=row["description"],
            reason=row["reason"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            assessment_json=row["assessment_json"],
            assessment_draft=bool(row["assessment_draft"]),
            assessed_at=(
                datetime.fromisoformat(row["assessed_at"]) if row["assessed_at"] else None
            ),
            assessed_by=row["assessed_by"],
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None
            ),
            resolved_by=row["resolved_by"],
            resolution_reason=row["resolution_reason"],
            release_version=row["release_version"],
            released_at=(
                datetime.fromisoformat(row["released_at"]) if row["released_at"] else None
            ),
        )
