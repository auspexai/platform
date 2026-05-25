"""AuditRepository — append-only operator + researcher actions.

M4 writes via `append()`. M8 adds list/filter queries for the operator console
audit-log view. The schema (in 0001_init.sql) carries enough fields to support
filtering by actor, action, resource, and time without further migration.

Audit invariants:
  - Append-only. No `update()` or `delete()` methods on this repository.
  - Every mutation in the M5+ resource routes writes one entry before returning.
  - The `payload` column stores arbitrary structured detail as JSON text; the
    repository serializes/deserializes via `json` on append / fetch.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.auth.credential import CredentialClass
from auspexai_platform.db.database import Database
from auspexai_platform.db.models import AuditEntry


class AuditRepository:
    def __init__(self, db: Database):
        self.db = db

    def append(
        self,
        *,
        actor_class: CredentialClass,
        actor_identifier: str | None = None,
        actor_tenant_id: str | None = None,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append an audit entry; return the persisted row."""
        if not action:
            raise ValueError("audit `action` must be non-empty")
        occurred_at = datetime.now(UTC).isoformat()
        payload_json = json.dumps(payload) if payload is not None else None
        rows = self.db.execute(
            """
            INSERT INTO audit_log (
                occurred_at, actor_class, actor_identifier, actor_tenant_id,
                action, resource_type, resource_id, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                occurred_at,
                str(actor_class),
                actor_identifier,
                actor_tenant_id,
                action,
                resource_type,
                resource_id,
                payload_json,
            ),
        )
        return AuditEntry(
            id=rows[0]["id"],
            occurred_at=datetime.fromisoformat(occurred_at),
            actor_class=actor_class,
            actor_identifier=actor_identifier,
            actor_tenant_id=actor_tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
        )

    def list(
        self,
        *,
        action: str | None = None,
        actor_class: str | None = None,
        resource_type: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> tuple[list[AuditEntry], int]:
        """Return filtered audit entries, most recent first.

        Returns a (entries, total) tuple where *total* is the count of rows
        matching the filters (before LIMIT) and *entries* is the capped
        result set ordered by id DESC.
        """
        limit = max(1, min(limit, 500))

        clauses: list[str] = []
        params: list[str | int] = []

        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if actor_class is not None:
            clauses.append("actor_class = ?")
            params.append(actor_class)
        if resource_type is not None:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if since is not None:
            clauses.append("occurred_at > ?")
            params.append(since)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        count_rows = self.db.execute(
            f"SELECT COUNT(*) AS cnt FROM audit_log{where}",
            tuple(params),
        )
        total = count_rows[0]["cnt"]

        rows = self.db.execute(
            f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        )
        return [self._row_to_entry(r) for r in rows], total

    def latest(self, *, limit: int = 50) -> list[AuditEntry]:
        """Return the most recent audit entries. M8 replaces this with a
        proper filterable list endpoint; v0 keeps it just for test + debug
        purposes."""
        if limit <= 0:
            return []
        rows = self.db.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [self._row_to_entry(r) for r in rows]

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        payload_raw = row["payload"]
        payload = json.loads(payload_raw) if payload_raw is not None else None
        return AuditEntry(
            id=row["id"],
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            actor_class=CredentialClass(row["actor_class"]),
            actor_identifier=row["actor_identifier"],
            actor_tenant_id=row["actor_tenant_id"],
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            payload=payload,
        )
