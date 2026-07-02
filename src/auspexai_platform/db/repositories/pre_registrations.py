"""PreRegistrationRepository — control-DB store of submit-time pre-registration
anchors (D16.2, migration 0054).

One row per experiment whose signed manifest declared a `pre_registration`
block, written at submit with the not-yet-anchored placeholder; the hourly
Rekor backfill anchors it. The COSE blob is the canonical artifact; the anchor
columns are denormalized for serving. Mirrors the attestations repository
(0022) conventions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from auspexai_platform.db.database import Database

# The not-yet-anchored placeholder (mirrors attestations / receipts).
NOT_ANCHORED_LOG_INDEX = 0
NOT_ANCHORED_ENTRY_UUID = "lab-mode-no-rekor"


@dataclass(frozen=True)
class PreRegistrationRecord:
    experiment_id: str
    tenant_id: str
    tenant_experiment_label: str
    manifest_hash: str
    cose_signed_blob: bytes
    signing_key_pubkey_hex: str
    submitted_at: str
    rekor_log_index: int
    rekor_entry_uuid: str
    rekor_inclusion_proof: dict | None

    @property
    def anchored(self) -> bool:
        return self.rekor_entry_uuid != NOT_ANCHORED_ENTRY_UUID

    def predicate_ref(self) -> dict:
        """The compact reference other surfaces carry (the result attestation's
        predicate, the evidence bundle): enough for a verifier to locate and
        order the anchor without the full blob."""
        return {
            "manifest_hash": self.manifest_hash,
            "rekor_log_index": self.rekor_log_index,
            "rekor_entry_uuid": self.rekor_entry_uuid,
            "submitted_at": self.submitted_at,
        }


class PreRegistrationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def insert(
        self,
        *,
        experiment_id: str,
        tenant_id: str,
        tenant_experiment_label: str,
        manifest_hash: str,
        cose_signed_blob: bytes,
        signing_key_pubkey_hex: str,
        submitted_at: str,
    ) -> PreRegistrationRecord:
        """Record the submit-time anchor row (placeholder Rekor sentinels; the
        backfill anchors). INSERT OR IGNORE — one immutable row per experiment
        (a pre-registration is never edited; deviations are separate records)."""
        self.db.execute(
            """
            INSERT OR IGNORE INTO pre_registrations
              (experiment_id, tenant_id, tenant_experiment_label, manifest_hash,
               cose_signed_blob, signing_key_pubkey_hex, submitted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                experiment_id,
                tenant_id,
                tenant_experiment_label,
                manifest_hash,
                cose_signed_blob,
                signing_key_pubkey_hex,
                submitted_at,
            ),
        )
        got = self.get(experiment_id)
        assert got is not None
        return got

    def set_rekor(
        self,
        experiment_id: str,
        *,
        log_index: int,
        entry_uuid: str,
        inclusion_proof: dict | None = None,
    ) -> None:
        """Stamp the transparency-log anchor (the backfill sweep)."""
        self.db.execute(
            "UPDATE pre_registrations SET rekor_log_index = ?, rekor_entry_uuid = ?, "
            "rekor_inclusion_proof_json = ? WHERE experiment_id = ?",
            (
                log_index,
                entry_uuid,
                json.dumps(inclusion_proof) if inclusion_proof is not None else None,
                experiment_id,
            ),
        )

    # ---- reads ----

    def get(self, experiment_id: str) -> PreRegistrationRecord | None:
        rows = self.db.execute(
            "SELECT * FROM pre_registrations WHERE experiment_id = ?", (experiment_id,)
        )
        return self._row_to_record(rows[0]) if rows else None

    def list_unanchored(self) -> list[PreRegistrationRecord]:
        """Rows still carrying the placeholder anchor (the backfill sweep's
        candidates). Keyed on the entry_uuid sentinel, mirroring attestations."""
        rows = self.db.execute(
            "SELECT * FROM pre_registrations WHERE rekor_entry_uuid = ? ORDER BY submitted_at",
            (NOT_ANCHORED_ENTRY_UUID,),
        )
        return [self._row_to_record(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row) -> PreRegistrationRecord:
        proof = row["rekor_inclusion_proof_json"]
        return PreRegistrationRecord(
            experiment_id=row["experiment_id"],
            tenant_id=row["tenant_id"],
            tenant_experiment_label=row["tenant_experiment_label"],
            manifest_hash=row["manifest_hash"],
            cose_signed_blob=bytes(row["cose_signed_blob"]),
            signing_key_pubkey_hex=row["signing_key_pubkey_hex"],
            submitted_at=row["submitted_at"],
            rekor_log_index=row["rekor_log_index"],
            rekor_entry_uuid=row["rekor_entry_uuid"],
            rekor_inclusion_proof=json.loads(proof) if proof else None,
        )
