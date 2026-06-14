"""TenantRepository — pubkey-bound research tenants.

CRUD over the `tenants` table. The auth-side `TenantRegistry` from M2 will
delegate to this in M5 (replacing the in-memory implementation); the
narrow `get_tenant_for_pubkey` lookup that the auth dependency uses is
covered here by `get_by_pubkey`.

The Pydantic `Tenant` model in `db/models.py` is the canonical row shape;
this repository converts to/from `sqlite3.Row`.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Tenant


class DuplicateTenantError(Exception):
    """Raised when a tenant_id or maintainer_pubkey is already bound."""


class TenantRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- writes ----

    def register(
        self,
        *,
        tenant_id: str,
        maintainer_pubkey: str,
        display_name: str | None = None,
        contact_email: str | None = None,
        contact_public: str | None = None,
        description: str | None = None,
        account_id: str | None = None,
    ) -> Tenant:
        """Insert a tenant. Raises DuplicateTenantError on PK or unique-pubkey conflict."""
        maintainer_pubkey = maintainer_pubkey.lower()
        registered_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO tenants (
                    tenant_id, maintainer_pubkey, display_name,
                    contact_email, contact_public, description,
                    account_id, registered_at, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    tenant_id,
                    maintainer_pubkey,
                    display_name,
                    contact_email,
                    contact_public,
                    description,
                    account_id,
                    registered_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateTenantError(str(e)) from e
        # Re-read to capture the canonical row (including the DB-side defaults).
        got = self.get_by_id(tenant_id)
        assert got is not None
        return got

    def unregister(self, tenant_id: str) -> bool:
        """Delete a tenant. Returns True if a row was removed."""
        with self.db.transaction() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
            return cur.rowcount > 0

    def set_account(self, tenant_id: str, account_id: str | None) -> Tenant | None:
        """Link (or unlink, `account_id=None`) an EXISTING tenant to an account —
        the post-registration linkage the trust model depends on (the tier floor
        for A' replication, own-worker enrichment, promotion). `account_id` is
        NOT validated here (the route checks the account exists). Returns the
        updated Tenant, or None if the tenant_id is unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE tenants SET account_id = ?, revision = revision + 1 WHERE tenant_id = ?",
                (account_id, tenant_id),
            )
            if cur.rowcount == 0:
                return None
        return self.get_by_id(tenant_id)

    # ---- reads ----

    def get_by_id(self, tenant_id: str) -> Tenant | None:
        rows = self.db.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        )
        return self._row_to_tenant(rows[0]) if rows else None

    def get_by_pubkey(self, maintainer_pubkey: str) -> Tenant | None:
        rows = self.db.execute(
            "SELECT * FROM tenants WHERE maintainer_pubkey = ?",
            (maintainer_pubkey.lower(),),
        )
        return self._row_to_tenant(rows[0]) if rows else None

    def list_all(self) -> list[Tenant]:
        rows = self.db.execute("SELECT * FROM tenants ORDER BY registered_at")
        return [self._row_to_tenant(r) for r in rows]

    def list_for_account(self, account_id: str) -> list[Tenant]:
        """All tenants linked to an account (D2 review context). Excludes
        nothing — suspended/legacy state is the caller's concern."""
        rows = self.db.execute(
            "SELECT * FROM tenants WHERE account_id = ? ORDER BY registered_at",
            (account_id,),
        )
        return [self._row_to_tenant(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_tenant(row: sqlite3.Row) -> Tenant:
        return Tenant(
            tenant_id=row["tenant_id"],
            maintainer_pubkey=row["maintainer_pubkey"],
            display_name=row["display_name"],
            contact_email=row["contact_email"],
            contact_public=row["contact_public"],
            description=row["description"],
            account_id=row["account_id"],
            registered_at=datetime.fromisoformat(row["registered_at"]),
            revision=row["revision"],
        )
