"""AttestationRepository — control-DB store of canonical result-set attestations.

The per-experiment result-set attestation (#34 §6.3) is written here once an
experiment reaches COMPLETED (eager, from either completion path) or lazily on
first GET. Persisting it makes the attestation CANONICAL (a stable
attestation_id + COSE bytes + Rekor anchor instead of a fresh recompute per
call) and DURABLE past per-job DB deletion — mirrors the receipt_index
control-DB precedent (0007). Only FINAL (partial=0) attestations are stored;
checkpoints stay on demand. The COSE-signed blob is the canonical artifact;
merkle_root / rekor anchor / doi are denormalized for fast serving.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database

# The not-yet-anchored sentinel. Defined here (the db layer) rather than imported
# from receipts.rekor to avoid a circular import (receipts/__init__ → issuance →
# db.repositories). It is the DEFAULT of the rekor_entry_uuid column in
# 0022_attestations.sql and what list_unanchored() filters on; a test asserts it
# stays equal to receipts.rekor.REKOR_PLACEHOLDER_UUID.
REKOR_PLACEHOLDER_UUID = "lab-mode-no-rekor"


class DuplicateAttestationError(Exception):
    """Raised when a final attestation already exists for the experiment — the
    partial-unique index makes this race-safe; callers treat it as 'already
    canonical' and serve the existing row."""


@dataclass(frozen=True)
class AttestationRecord:
    """One persisted canonical attestation. `cose_signed_blob` is the artifact a
    verifier consumes; everything else is denormalized for serving/lookup."""

    attestation_id: str
    experiment_id: str  # coord-side exp- id (locates the per-job DB)
    tenant_id: str
    tenant_experiment_label: str  # the tenant-facing label (receipt convention)
    merkle_root: str
    algorithm: str
    unit_count: int
    cose_signed_blob: bytes
    signing_key_pubkey_hex: str
    rekor_log_index: int
    rekor_entry_uuid: str
    partial: bool
    doi: str | None
    issued_at: datetime
    # EB-1 (§9 #47, migration 0027): the Rekor inclusion proof captured at
    # anchor time (create-entry response verification.inclusionProof JSON) so
    # the evidence bundle verifies offline forever. None = anchored pre-EB-1
    # or not yet anchored — the SDK falls back to the online check.
    rekor_inclusion_proof_json: str | None = None


class AttestationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        attestation_id: str,
        experiment_id: str,
        tenant_id: str,
        tenant_experiment_label: str,
        merkle_root: str,
        algorithm: str,
        unit_count: int,
        cose_signed_blob: bytes,
        signing_key_pubkey_hex: str,
        rekor_log_index: int = 0,
        rekor_entry_uuid: str = "lab-mode-no-rekor",
        partial: bool = False,
        rekor_inclusion_proof_json: str | None = None,
    ) -> AttestationRecord:
        """Persist the canonical (final) attestation for an experiment. Raises
        DuplicateAttestationError if a final attestation already exists (the
        partial-unique index enforces one-per-experiment, so concurrent emit
        paths race safely: the first wins, the rest catch and serve it)."""
        issued_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO attestations
                  (attestation_id, experiment_id, tenant_id, tenant_experiment_label,
                   merkle_root, algorithm, unit_count, cose_signed_blob,
                   signing_key_pubkey_hex, rekor_log_index, rekor_entry_uuid,
                   partial, issued_at, rekor_inclusion_proof_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attestation_id,
                    experiment_id,
                    tenant_id,
                    tenant_experiment_label,
                    merkle_root,
                    algorithm,
                    unit_count,
                    cose_signed_blob,
                    signing_key_pubkey_hex,
                    rekor_log_index,
                    rekor_entry_uuid,
                    int(partial),
                    issued_at,
                    rekor_inclusion_proof_json,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateAttestationError(str(e)) from e
        got = self.get_by_id(attestation_id)
        assert got is not None
        return got

    def set_rekor(
        self,
        attestation_id: str,
        *,
        log_index: int,
        entry_uuid: str,
        inclusion_proof_json: str | None = None,
    ) -> None:
        """A2 hook — stamp the Rekor anchor onto a persisted attestation (the
        emit path once it has the entry, or the `backfill-rekor` sweep). EB-1:
        also persists the inclusion proof when the anchor response carried one,
        so the evidence bundle can verify inclusion offline."""
        self.db.execute(
            "UPDATE attestations SET rekor_log_index = ?, rekor_entry_uuid = ?, "
            "rekor_inclusion_proof_json = COALESCE(?, rekor_inclusion_proof_json) "
            "WHERE attestation_id = ?",
            (log_index, entry_uuid, inclusion_proof_json, attestation_id),
        )

    def set_doi(self, attestation_id: str, doi: str) -> None:
        """Workstream-D hook — record the minted Zenodo DOI for a published
        attestation."""
        self.db.execute(
            "UPDATE attestations SET doi = ? WHERE attestation_id = ?",
            (doi, attestation_id),
        )

    # ---- reads ----

    def get_by_id(self, attestation_id: str) -> AttestationRecord | None:
        rows = self.db.execute(
            "SELECT * FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        )
        return self._row_to_record(rows[0]) if rows else None

    def get_final(self, experiment_id: str) -> AttestationRecord | None:
        """The canonical (partial=0) attestation for an experiment, or None."""
        rows = self.db.execute(
            "SELECT * FROM attestations WHERE experiment_id = ? AND partial = 0",
            (experiment_id,),
        )
        return self._row_to_record(rows[0]) if rows else None

    def list_unanchored(self) -> list[AttestationRecord]:
        """A2 backfill — persisted attestations still carrying the NoOp Rekor
        placeholder (never anchored). Keyed on the entry_uuid sentinel rather
        than log_index=0, since a real Rekor logIndex could legitimately be 0."""
        rows = self.db.execute(
            "SELECT * FROM attestations WHERE rekor_entry_uuid = ? ORDER BY issued_at",
            (REKOR_PLACEHOLDER_UUID,),
        )
        return [self._row_to_record(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AttestationRecord:
        return AttestationRecord(
            attestation_id=row["attestation_id"],
            experiment_id=row["experiment_id"],
            tenant_id=row["tenant_id"],
            tenant_experiment_label=row["tenant_experiment_label"],
            merkle_root=row["merkle_root"],
            algorithm=row["algorithm"],
            unit_count=row["unit_count"],
            cose_signed_blob=bytes(row["cose_signed_blob"]),
            signing_key_pubkey_hex=row["signing_key_pubkey_hex"],
            rekor_log_index=row["rekor_log_index"],
            rekor_entry_uuid=row["rekor_entry_uuid"],
            partial=bool(row["partial"]),
            doi=row["doi"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
            rekor_inclusion_proof_json=(
                row["rekor_inclusion_proof_json"]
                if "rekor_inclusion_proof_json" in row.keys()
                else None
            ),
        )
