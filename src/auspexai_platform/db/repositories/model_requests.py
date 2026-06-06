"""ModelRequestRepository — control-DB demand-board (M2, migration 0018).

A researcher's request for a model (BYOM, §5.8 + §9 #32/#39). Every request is a
recorded demand signal; `status` distinguishes the maintainer review queue
(`pending`) from already-servable demand (`available`) and resolved requests
(`fulfilled` / `declined`). See `0018_model_requests.sql` for the state model.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


def _generate_request_id() -> str:
    """Coordinator-side id: `mrq-<random 8 chars>`."""
    return f"mrq-{secrets.token_urlsafe(6)[:8]}"


@dataclass(frozen=True)
class ModelRequest:
    request_id: str
    tenant_id: str
    model_id: str
    hf_repo: str | None
    reason: str
    status: str  # available | pending | fulfilled | declined
    created_at: datetime
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_reason: str | None


class ModelRequestRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        *,
        tenant_id: str,
        model_id: str,
        reason: str,
        status: str,
        hf_repo: str | None = None,
    ) -> ModelRequest:
        request_id = _generate_request_id()
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO model_requests (
                request_id, tenant_id, model_id, hf_repo, reason, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (request_id, tenant_id, model_id, hf_repo, reason, status, created_at),
        )
        got = self.get_by_id(request_id)
        assert got is not None
        return got

    def get_by_id(self, request_id: str) -> ModelRequest | None:
        rows = self.db.execute("SELECT * FROM model_requests WHERE request_id = ?", (request_id,))
        return self._row(rows[0]) if rows else None

    def list(
        self, *, status: str | None = None, tenant_id: str | None = None
    ) -> list[ModelRequest]:
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
            f"SELECT * FROM model_requests{where} ORDER BY created_at DESC", tuple(params)
        )
        return [self._row(r) for r in rows]

    def resolve(
        self, request_id: str, *, status: str, resolved_by: str, reason: str
    ) -> ModelRequest | None:
        """Mark a request fulfilled/declined with a mandatory reason + attribution."""
        self.db.execute(
            """
            UPDATE model_requests
            SET status = ?, resolved_at = ?, resolved_by = ?, resolution_reason = ?
            WHERE request_id = ?
            """,
            (status, datetime.now(UTC).isoformat(), resolved_by, reason, request_id),
        )
        return self.get_by_id(request_id)

    @staticmethod
    def _row(row) -> ModelRequest:
        return ModelRequest(
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            model_id=row["model_id"],
            hf_repo=row["hf_repo"],
            reason=row["reason"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None
            ),
            resolved_by=row["resolved_by"],
            resolution_reason=row["resolution_reason"],
        )
