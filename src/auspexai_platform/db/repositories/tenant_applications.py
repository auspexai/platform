"""TenantApplicationRepository — researcher-onboarding queue (Option D, migration 0028).

The onboarding analog of the software_requests demand board: an aspiring
researcher's application to become a tenant, bound to a verified GitHub
account and to the Ed25519 key that signed the application (proof of
possession). Approval is ATOMIC with tenant creation: one transaction marks
the application approved AND inserts the tenants row with the applying key
bound as maintainer_pubkey and tenants.account_id linked — so a tenant-id
collision (409) leaves the application pending and retryable with an
override. See `0028_tenant_applications.sql` for the state model.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories.tenants import DuplicateTenantError


class ApplicationNotPendingError(Exception):
    """Raised when an approve/decline targets an application that is not pending."""


def _generate_application_id() -> str:
    """Coordinator-side id: `tapp-<random 8 chars>`."""
    return f"tapp-{secrets.token_urlsafe(6)[:8]}"


@dataclass(frozen=True)
class TenantApplication:
    application_id: str
    account_id: str
    github_login: str | None
    requested_tenant_id: str
    contact_name: str
    affiliation: str
    research_summary: str
    pubkey_hex: str
    status: str  # pending | approved | declined
    created_at: datetime
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_reason: str | None
    created_tenant_id: str | None
    # Validated §11 research-class ids (migration 0029). NULL in the DB
    # (pre-0029 rows / summary-only applications) surfaces as [].
    research_classes: list[str] = field(default_factory=list)


class TenantApplicationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        *,
        account_id: str,
        github_login: str | None,
        requested_tenant_id: str,
        contact_name: str,
        affiliation: str,
        research_summary: str,
        pubkey_hex: str,
        research_classes: list[str] | None = None,
    ) -> TenantApplication:
        application_id = _generate_application_id()
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO tenant_applications (
                application_id, account_id, github_login, requested_tenant_id,
                contact_name, affiliation, research_summary, pubkey_hex,
                status, created_at, research_classes_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                application_id,
                account_id,
                github_login,
                requested_tenant_id,
                contact_name,
                affiliation,
                research_summary,
                pubkey_hex.lower(),
                created_at,
                json.dumps(research_classes) if research_classes else None,
            ),
        )
        got = self.get_by_id(application_id)
        assert got is not None
        return got

    def get_by_id(self, application_id: str) -> TenantApplication | None:
        rows = self.db.execute(
            "SELECT * FROM tenant_applications WHERE application_id = ?", (application_id,)
        )
        return self._row(rows[0]) if rows else None

    def list(
        self,
        *,
        status: str | None = None,
        account_id: str | None = None,
        pubkey_hex: str | None = None,
    ) -> list[TenantApplication]:
        clauses: list[str] = []
        params: list[str] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if pubkey_hex is not None:
            clauses.append("pubkey_hex = ?")
            params.append(pubkey_hex.lower())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.execute(
            f"SELECT * FROM tenant_applications{where} ORDER BY created_at DESC", tuple(params)
        )
        return [self._row(r) for r in rows]

    def has_pending_for_account(self, account_id: str) -> bool:
        """One pending application per account at a time (submit-side 409)."""
        rows = self.db.execute(
            "SELECT 1 FROM tenant_applications WHERE account_id = ? AND status = 'pending'",
            (account_id,),
        )
        return bool(rows)

    def approve(
        self, application_id: str, *, tenant_id: str, resolved_by: str
    ) -> TenantApplication:
        """Approve atomically: mark approved AND create the tenant in one
        transaction.

        The tenants INSERT mirrors `TenantRepository.register` (same columns,
        revision=1) but runs inside this transaction so a tenant-id /
        maintainer-pubkey collision rolls everything back — the application
        stays pending and the maintainer can retry with `tenant_id_override`.

        Raises:
            ApplicationNotPendingError — application missing or already resolved.
            DuplicateTenantError — tenant_id taken or pubkey already bound.
        """
        application = self.get_by_id(application_id)
        if application is None or application.status != "pending":
            raise ApplicationNotPendingError(application_id)
        now = datetime.now(UTC).isoformat()
        try:
            with self.db.transaction() as cur:
                cur.execute(
                    """
                    UPDATE tenant_applications
                    SET status = 'approved', resolved_at = ?, resolved_by = ?,
                        created_tenant_id = ?
                    WHERE application_id = ? AND status = 'pending'
                    """,
                    (now, resolved_by, tenant_id, application_id),
                )
                if cur.rowcount == 0:
                    raise ApplicationNotPendingError(application_id)
                # Carry the application's metadata into the tenant record —
                # the applicant already said who they are; discarding it left
                # operators staring at placeholder rows (researcher-#0 finding,
                # 2026-06-12). contact_email stays NULL (never collected); the
                # GitHub login is the public contact handle.
                description_parts = []
                if application.research_classes:
                    description_parts.append(
                        "Research classes: " + ", ".join(application.research_classes) + "."
                    )
                if application.research_summary:
                    description_parts.append(application.research_summary)
                display_name = application.contact_name
                if application.affiliation and application.affiliation != application.contact_name:
                    display_name = f"{application.contact_name} ({application.affiliation})"
                cur.execute(
                    """
                    INSERT INTO tenants (
                        tenant_id, maintainer_pubkey, display_name,
                        contact_email, contact_public, description,
                        account_id, registered_at, revision
                    ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 1)
                    """,
                    (
                        tenant_id,
                        application.pubkey_hex.lower(),
                        display_name or None,
                        f"github:{application.github_login}" if application.github_login else None,
                        " ".join(description_parts) or None,
                        application.account_id,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as e:
            raise DuplicateTenantError(str(e)) from e
        got = self.get_by_id(application_id)
        assert got is not None
        return got

    def decline(self, application_id: str, *, resolved_by: str, reason: str) -> TenantApplication:
        """Decline with a mandatory reason + attribution.

        Raises ApplicationNotPendingError if the application is missing or
        already resolved.
        """
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE tenant_applications
                SET status = 'declined', resolved_at = ?, resolved_by = ?,
                    resolution_reason = ?
                WHERE application_id = ? AND status = 'pending'
                """,
                (datetime.now(UTC).isoformat(), resolved_by, reason, application_id),
            )
            if cur.rowcount == 0:
                raise ApplicationNotPendingError(application_id)
        got = self.get_by_id(application_id)
        assert got is not None
        return got

    @staticmethod
    def _row(row) -> TenantApplication:
        return TenantApplication(
            application_id=row["application_id"],
            account_id=row["account_id"],
            github_login=row["github_login"],
            requested_tenant_id=row["requested_tenant_id"],
            contact_name=row["contact_name"],
            affiliation=row["affiliation"],
            research_summary=row["research_summary"],
            pubkey_hex=row["pubkey_hex"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None
            ),
            resolved_by=row["resolved_by"],
            resolution_reason=row["resolution_reason"],
            created_tenant_id=row["created_tenant_id"],
            research_classes=(
                json.loads(row["research_classes_json"]) if row["research_classes_json"] else []
            ),
        )
