"""CertifiedProfileRepository — control-DB store of promotion-gate certifications.

A certification (RFC 0001 / Research Ethics Policy §6.7) is a signed, content-bound
attestation that a specific RELEASED starter profile is safe to expose to
unverified researchers. The registry is keyed by the content-addressed executor
`package_sha256` (a tenant cannot alter the executor/reducer/probe-set without
changing the digest) and is maintainer-written only. The COSE-signed blob is the
verifiable artifact; the locked-envelope columns are denormalized for the
submit-time match (§6.7.3) and the floor exemption. Mirrors the receipt_index /
attestations (0022) control-DB precedent. See migration 0042.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database

# Not-yet-anchored sentinel for the transparency log (mirrors the attestation
# backfill). NULL rekor_log_index = never anchored; the backfill sweep fills it.


class DuplicateCertificationError(Exception):
    """A certification already exists for this package digest (the PRIMARY KEY).
    Re-certifying the SAME content is a no-op; a new RELEASE has a new digest →
    a new row."""


@dataclass(frozen=True)
class CertifiedProfileRecord:
    """One certification. `cose_signed_blob` is the verifiable artifact; the rest
    is denormalized for the submit-time locked-field match (§6.7.3)."""

    package_sha256: str
    snapshot_version: str
    tenant_id: str
    profile_name: str
    research_class: str | None
    sensitive_content_flags: list[str]
    model_ids: list[str]
    replication_floor: int
    max_units_ceiling: int | None
    duration_hours_ceiling: float | None
    cose_signed_blob: bytes
    signing_key_pubkey_hex: str
    certified_by: str
    advisor: str | None
    rekor_log_index: int | None
    certified_at: datetime
    status: str
    revoked_at: datetime | None
    revoked_reason: str | None

    @property
    def is_active(self) -> bool:
        return self.status == "certified"


class CertifiedProfileRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        package_sha256: str,
        snapshot_version: str,
        tenant_id: str,
        profile_name: str,
        research_class: str | None,
        sensitive_content_flags: list[str],
        model_ids: list[str],
        replication_floor: int,
        max_units_ceiling: int | None,
        duration_hours_ceiling: float | None,
        cose_signed_blob: bytes,
        signing_key_pubkey_hex: str,
        certified_by: str,
        advisor: str | None = None,
    ) -> CertifiedProfileRecord:
        """Register a certification. Raises DuplicateCertificationError if this
        exact package digest is already certified."""
        certified_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO certified_profiles
                  (package_sha256, snapshot_version, tenant_id, profile_name,
                   research_class, sensitive_content_flags, model_ids,
                   replication_floor, max_units_ceiling, duration_hours_ceiling,
                   cose_signed_blob, signing_key_pubkey_hex, certified_by, advisor,
                   certified_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'certified')
                """,
                (
                    package_sha256,
                    snapshot_version,
                    tenant_id,
                    profile_name,
                    research_class,
                    json.dumps(list(sensitive_content_flags)),
                    json.dumps(list(model_ids)),
                    int(replication_floor),
                    max_units_ceiling,
                    duration_hours_ceiling,
                    cose_signed_blob,
                    signing_key_pubkey_hex,
                    certified_by,
                    advisor,
                    certified_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateCertificationError(str(e)) from e
        got = self.get_by_package(package_sha256)
        assert got is not None
        return got

    def revoke(self, package_sha256: str, *, reason: str) -> None:
        """§6.7.6 — remove a certification's standing approval. Runs of that
        profile revert to requiring a §6.1 application. Idempotent."""
        self.db.execute(
            "UPDATE certified_profiles SET status = 'revoked', revoked_at = ?, "
            "revoked_reason = ? WHERE package_sha256 = ? AND status != 'revoked'",
            (datetime.now(UTC).isoformat(), reason, package_sha256),
        )

    def supersede_others(self, *, tenant_id: str, profile_name: str, keep_package: str) -> None:
        """When a new release of a profile is certified, mark the tenant's other
        ACTIVE certifications of the same profile 'superseded' so only the newest
        version auto-clears. The kept (new) row is untouched."""
        self.db.execute(
            "UPDATE certified_profiles SET status = 'superseded' "
            "WHERE tenant_id = ? AND profile_name = ? AND package_sha256 != ? "
            "AND status = 'certified'",
            (tenant_id, profile_name, keep_package),
        )

    def set_rekor(self, package_sha256: str, *, log_index: int) -> None:
        """Stamp the transparency-log anchor onto a certification (the publish
        step, or the backfill sweep)."""
        self.db.execute(
            "UPDATE certified_profiles SET rekor_log_index = ? WHERE package_sha256 = ?",
            (log_index, package_sha256),
        )

    # ---- reads ----

    def get_by_package(self, package_sha256: str) -> CertifiedProfileRecord | None:
        """The submit-time hot path: resolve a submission's executor digest to its
        certification (any status — callers check `is_active`)."""
        rows = self.db.execute(
            "SELECT * FROM certified_profiles WHERE package_sha256 = ?",
            (package_sha256,),
        )
        return self._row_to_record(rows[0]) if rows else None

    def get_active(self, *, tenant_id: str, profile_name: str) -> CertifiedProfileRecord | None:
        """The currently-certified version of a tenant's profile, if any."""
        rows = self.db.execute(
            "SELECT * FROM certified_profiles WHERE tenant_id = ? AND profile_name = ? "
            "AND status = 'certified' ORDER BY certified_at DESC LIMIT 1",
            (tenant_id, profile_name),
        )
        return self._row_to_record(rows[0]) if rows else None

    def list_unanchored(self) -> list[CertifiedProfileRecord]:
        """Certifications not yet anchored in the transparency log (backfill)."""
        rows = self.db.execute(
            "SELECT * FROM certified_profiles WHERE rekor_log_index IS NULL ORDER BY certified_at"
        )
        return [self._row_to_record(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CertifiedProfileRecord:
        return CertifiedProfileRecord(
            package_sha256=row["package_sha256"],
            snapshot_version=row["snapshot_version"],
            tenant_id=row["tenant_id"],
            profile_name=row["profile_name"],
            research_class=row["research_class"],
            sensitive_content_flags=json.loads(row["sensitive_content_flags"] or "[]"),
            model_ids=json.loads(row["model_ids"] or "[]"),
            replication_floor=row["replication_floor"],
            max_units_ceiling=row["max_units_ceiling"],
            duration_hours_ceiling=row["duration_hours_ceiling"],
            cose_signed_blob=bytes(row["cose_signed_blob"]),
            signing_key_pubkey_hex=row["signing_key_pubkey_hex"],
            certified_by=row["certified_by"],
            advisor=row["advisor"],
            rekor_log_index=row["rekor_log_index"],
            certified_at=datetime.fromisoformat(row["certified_at"]),
            status=row["status"],
            revoked_at=(datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None),
            revoked_reason=row["revoked_reason"],
        )
