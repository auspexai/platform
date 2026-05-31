"""Canonical content hashing, shared across the reduce/receipt path and the
result store.

Kept dependency-free (no `db`/`receipts` imports) so any layer can call it
without a circular import — in particular `db.repositories.results` persists the
semantic hash at insert time (M-Results) and `receipts.issuance` uses it to
decide agreement.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any


def semantic_hash(exit_code: int, payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical ``{exit_code, payload}`` — the parts workers
    must agree on.

    The agreement reducer compares these across a unit's workers; the result
    store persists it on every result row so that an aged-off row (payload
    blanked) still self-describes its content and can be matched to its receipt.
    """
    canonical = json.dumps(
        {"exit_code": exit_code, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()
