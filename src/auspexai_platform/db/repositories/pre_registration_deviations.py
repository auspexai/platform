"""PreRegistrationDeviationRepository — append-only deviation records
(D16.2-D, migration 0055, preregistration_design.md §5).

A deviation is a new, separately-timestamped, signed record referencing the
original pre-registration — never an edit. No UPDATE path exists here by
design; each declaration is its own row + its own Rekor anchor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories.pre_registrations import NOT_ANCHORED_ENTRY_UUID


@dataclass(frozen=True)
class DeviationRecord:
    deviation_id: str
    experiment_id: str
    tenant_id: str
    manifest_hash: str
    what_changed: str
    why: str
    tenant_pubkey_hex: str
    tenant_signature_b64: str
    cose_signed_blob: bytes
    signing_key_pubkey_hex: str
    declared_at: str
    rekor_log_index: int
    rekor_entry_uuid: str
    rekor_inclusion_proof: dict | None

    @property
    def anchored(self) -> bool:
        return self.rekor_entry_uuid != NOT_ANCHORED_ENTRY_UUID

    def bundle_dict(self) -> dict:
        """The evidence-bundle / API shape — everything an OFFLINE verifier
        needs: the declaration + the declarer's signature + the coordinator
        anchor. One canonical serialization so every surface agrees."""
        from base64 import b64encode

        return {
            "deviation_id": self.deviation_id,
            "manifest_hash": self.manifest_hash,
            "what_changed": self.what_changed,
            "why": self.why,
            "tenant_pubkey_hex": self.tenant_pubkey_hex,
            "tenant_signature_b64": self.tenant_signature_b64,
            "declared_at": self.declared_at,
            "cose_b64": b64encode(self.cose_signed_blob).decode(),
            "signing_key_pubkey_hex": self.signing_key_pubkey_hex,
            "rekor_log_index": self.rekor_log_index,
            "rekor_entry_uuid": self.rekor_entry_uuid,
            "rekor_inclusion_proof": self.rekor_inclusion_proof,
        }


class PreRegistrationDeviationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes (append-only: insert + anchor-stamp; no update, no delete) ----

    def insert(
        self,
        *,
        deviation_id: str,
        experiment_id: str,
        tenant_id: str,
        manifest_hash: str,
        what_changed: str,
        why: str,
        tenant_pubkey_hex: str,
        tenant_signature_b64: str,
        cose_signed_blob: bytes,
        signing_key_pubkey_hex: str,
        declared_at: str,
    ) -> DeviationRecord:
        self.db.execute(
            """
            INSERT INTO pre_registration_deviations
              (deviation_id, experiment_id, tenant_id, manifest_hash, what_changed,
               why, tenant_pubkey_hex, tenant_signature_b64, cose_signed_blob,
               signing_key_pubkey_hex, declared_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                deviation_id,
                experiment_id,
                tenant_id,
                manifest_hash,
                what_changed,
                why,
                tenant_pubkey_hex,
                tenant_signature_b64,
                cose_signed_blob,
                signing_key_pubkey_hex,
                declared_at,
            ),
        )
        got = self.get(deviation_id)
        assert got is not None
        return got

    def set_rekor(
        self,
        deviation_id: str,
        *,
        log_index: int,
        entry_uuid: str,
        inclusion_proof: dict | None = None,
    ) -> None:
        self.db.execute(
            "UPDATE pre_registration_deviations SET rekor_log_index = ?, "
            "rekor_entry_uuid = ?, rekor_inclusion_proof_json = ? WHERE deviation_id = ?",
            (
                log_index,
                entry_uuid,
                json.dumps(inclusion_proof) if inclusion_proof is not None else None,
                deviation_id,
            ),
        )

    # ---- reads ----

    def get(self, deviation_id: str) -> DeviationRecord | None:
        rows = self.db.execute(
            "SELECT * FROM pre_registration_deviations WHERE deviation_id = ?", (deviation_id,)
        )
        return self._row_to_record(rows[0]) if rows else None

    def list_for_experiment(self, experiment_id: str) -> list[DeviationRecord]:
        rows = self.db.execute(
            "SELECT * FROM pre_registration_deviations WHERE experiment_id = ? "
            "ORDER BY declared_at, deviation_id",
            (experiment_id,),
        )
        return [self._row_to_record(r) for r in rows]

    def list_unanchored(self) -> list[DeviationRecord]:
        rows = self.db.execute(
            "SELECT * FROM pre_registration_deviations WHERE rekor_entry_uuid = ? "
            "ORDER BY declared_at",
            (NOT_ANCHORED_ENTRY_UUID,),
        )
        return [self._row_to_record(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_record(row) -> DeviationRecord:
        proof = row["rekor_inclusion_proof_json"]
        return DeviationRecord(
            deviation_id=row["deviation_id"],
            experiment_id=row["experiment_id"],
            tenant_id=row["tenant_id"],
            manifest_hash=row["manifest_hash"],
            what_changed=row["what_changed"],
            why=row["why"],
            tenant_pubkey_hex=row["tenant_pubkey_hex"],
            tenant_signature_b64=row["tenant_signature_b64"],
            cose_signed_blob=bytes(row["cose_signed_blob"]),
            signing_key_pubkey_hex=row["signing_key_pubkey_hex"],
            declared_at=row["declared_at"],
            rekor_log_index=row["rekor_log_index"],
            rekor_entry_uuid=row["rekor_entry_uuid"],
            rekor_inclusion_proof=json.loads(proof) if proof else None,
        )
