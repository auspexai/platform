"""Shared test helper: produce a VALID worker result signature (§9 #13a).

Now that the coordinator verifies the body signature at submit, HTTP-route
submit tests must send real signatures (placeholders are correctly rejected).
This mirrors the worker's signing via the shared canonical encoding."""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.result_signature import canonical_result_bytes


def sign_result_body(
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    *,
    unit_id: str,
    completed_at: datetime | str,
    exit_code: int,
    payload: dict[str, Any],
    schema_version: int | None = 0,
    served_weights: dict[str, str] | None = None,
    ran_under: str | None = None,
    generation_options: list[dict[str, Any]] | None = None,
) -> str:
    """Base64 Ed25519 signature over the canonical result body (v0 through v3)."""
    sig = privkey.sign(
        canonical_result_bytes(
            unit_id=unit_id,
            worker_pubkey=pubkey_hex,
            completed_at=completed_at,
            exit_code=exit_code,
            payload=payload,
            schema_version=schema_version,
            generation_options=generation_options,
            served_weights=served_weights,
            ran_under=ran_under,
        )
    )
    return base64.b64encode(sig).decode("ascii")
