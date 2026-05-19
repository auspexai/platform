"""ManifestRepository — content-addressed manifest storage.

Manifests are stored opaquely as JSON blobs. The primary key is the SHA-256
hash of the canonical manifest JSON, which the repository computes on insert.
Two tenants uploading identical manifest content would collide — that's the
content-addressing property (and very unlikely in practice given identifying
fields like tenant_id are inside the manifest).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import Manifest


class DuplicateManifestError(Exception):
    """Raised when a manifest_hash already exists."""


class ManifestRepository:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def hash_manifest(manifest_json: dict[str, Any]) -> str:
        """Compute the canonical hash of a manifest dict.

        Canonicalization: JSON with sorted keys, no extra whitespace, UTF-8
        encoded. Stable across runs and Python versions.
        """
        canonical = json.dumps(manifest_json, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def insert(
        self,
        *,
        tenant_id: str,
        manifest_json: dict[str, Any],
        signature_json: dict[str, Any],
    ) -> Manifest:
        """Compute the hash + insert. Raises DuplicateManifestError if the
        same manifest hash is already stored."""
        manifest_hash = self.hash_manifest(manifest_json)
        uploaded_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO manifests (
                    manifest_hash, tenant_id, manifest_json,
                    signature_json, uploaded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    manifest_hash,
                    tenant_id,
                    json.dumps(manifest_json),
                    json.dumps(signature_json),
                    uploaded_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateManifestError(str(e)) from e
        return self.get(manifest_hash)  # type: ignore[return-value]

    def get(self, manifest_hash: str) -> Manifest | None:
        rows = self.db.execute(
            "SELECT * FROM manifests WHERE manifest_hash = ?",
            (manifest_hash.lower(),),
        )
        return self._row_to_manifest(rows[0]) if rows else None

    def list_for_tenant(self, tenant_id: str) -> list[Manifest]:
        rows = self.db.execute(
            "SELECT * FROM manifests WHERE tenant_id = ? ORDER BY uploaded_at",
            (tenant_id,),
        )
        return [self._row_to_manifest(r) for r in rows]

    @staticmethod
    def _row_to_manifest(row: sqlite3.Row) -> Manifest:
        return Manifest(
            manifest_hash=row["manifest_hash"],
            tenant_id=row["tenant_id"],
            manifest_json=json.loads(row["manifest_json"]),
            signature_json=json.loads(row["signature_json"]),
            uploaded_at=datetime.fromisoformat(row["uploaded_at"]),
        )
