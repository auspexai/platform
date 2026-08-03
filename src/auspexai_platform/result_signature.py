"""§9 #13a: reconstruct + verify the worker's canonical result signature.

Byte-for-byte mirror of the worker's
`auspexai_worker.signing.result.canonical_result_bytes` (the platform cannot
import the worker package, so the canonical encoding is duplicated — the
cross-checked known-vector tests on both sides guard against drift).

v0 = the legacy five-field body. v1 (§9 #13a) additionally signs
`schema_version` + `served_weights` ({model_id: gguf_sha256}), so the
served-weights digest is worker-ATTESTED, not coordinator-asserted. v2 (A2 flip
activation, #32) additionally signs `ran_under` (the sandbox policy the worker
actually ran under), so the equal-trust containment guard is worker-ATTESTED +
accountable instead of heartbeat-self-reported. The coordinator reconstructs per
the worker-declared `schema_version`, so a v2 signature (binding ran_under)
verifies, a v1 stays byte-identical, and a v0 (un-rolled fleet) stays
byte-identical — no flag day. Schema versions are cumulative: v2 carries the v1
fields too.

This is the first place the body-level `worker_signature` is actually VERIFIED
(historically it was stored-but-not-verified until receipt issuance). Verifying
at submit keeps an unauthentic result out of the consensus set entirely.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_result_bytes(
    *,
    unit_id: str,
    worker_pubkey: str,
    completed_at: datetime | str,
    exit_code: int,
    payload: dict[str, Any],
    schema_version: int | None = 0,
    served_weights: dict[str, str] | None = None,
    ran_under: str | None = None,
    generation_options: list[dict[str, Any]] | None = None,
) -> bytes:
    """The canonical bytes the worker signed. `schema_version` 0/None reproduces
    the legacy five-field encoding byte-for-byte; >= 1 adds the signed
    `schema_version` + `served_weights` (digests normalized to lower hex); >= 2
    adds `ran_under` (the sandbox policy, lower-cased); >= 3 adds
    `generation_options` — the distinct sampler chains the worker daemon actually
    emitted to the backend for this unit, first-seen order. Versions are
    cumulative.

    WIRE CONTRACT: this is a byte-for-byte mirror of the worker's
    `auspexai_worker.signing.result.canonical_result_bytes`. Any change here MUST
    land identically on the worker side; the known-vector tests on both sides
    guard against drift."""
    ts = completed_at.isoformat() if isinstance(completed_at, datetime) else completed_at
    body: dict[str, Any] = {
        "unit_id": unit_id,
        "worker_pubkey": worker_pubkey.lower(),
        "completed_at": ts,
        "exit_code": int(exit_code),
        "payload": payload,
    }
    if schema_version and schema_version >= 1:
        body["schema_version"] = int(schema_version)
        body["served_weights"] = {str(k): str(v).lower() for k, v in (served_weights or {}).items()}
    if schema_version and schema_version >= 2:
        body["ran_under"] = str(ran_under or "").lower()
    if schema_version and schema_version >= 3:
        body["generation_options"] = [dict(o) for o in (generation_options or [])]
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_result_signature(
    *,
    worker_pubkey: str,
    signature_b64: str,
    unit_id: str,
    completed_at: datetime | str,
    exit_code: int,
    payload: dict[str, Any],
    schema_version: int | None = 0,
    served_weights: dict[str, str] | None = None,
    ran_under: str | None = None,
    generation_options: list[dict[str, Any]] | None = None,
) -> bool:
    """True iff `signature_b64` is a valid Ed25519 signature by `worker_pubkey`
    over the canonical body for the declared `schema_version`. Malformed pubkey
    / signature ⇒ False (never raises)."""
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(worker_pubkey.lower()))
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    sig_input = canonical_result_bytes(
        unit_id=unit_id,
        worker_pubkey=worker_pubkey,
        completed_at=completed_at,
        exit_code=exit_code,
        payload=payload,
        schema_version=schema_version,
        served_weights=served_weights,
        ran_under=ran_under,
        generation_options=generation_options,
    )
    try:
        pubkey.verify(signature, sig_input)
        return True
    except InvalidSignature:
        return False


def canonical_raw_bytes(*, unit_id: str, worker_pubkey: str, raw_response: str) -> bytes:
    """AUD-26: the DETACHED raw-content signature body. Byte-for-byte mirror of the
    worker's `auspexai_worker.signing.result.canonical_raw_bytes` — binds
    `sha256(raw_response)` to the unit + worker so the coordinator authenticates
    D20 raw text at ingest WITHOUT it ever entering the signed/stored result
    payload (keeping the result signature verifiable on export)."""
    body = {
        "unit_id": unit_id,
        "worker_pubkey": worker_pubkey.lower(),
        "raw_response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_raw_signature(
    *, worker_pubkey: str, signature_b64: str, unit_id: str, raw_response: str
) -> bool:
    """True iff `signature_b64` is a valid Ed25519 signature by `worker_pubkey`
    over the detached raw-content body for `raw_response`. Malformed input ⇒ False
    (never raises)."""
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(worker_pubkey.lower()))
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    try:
        pubkey.verify(
            signature,
            canonical_raw_bytes(
                unit_id=unit_id, worker_pubkey=worker_pubkey, raw_response=raw_response
            ),
        )
        return True
    except InvalidSignature:
        return False
