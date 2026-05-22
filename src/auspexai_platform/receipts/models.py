"""Receipt Pydantic models + CBOR codec.

Mirrors `tenant-sdk/src/auspexai_tenant/receipts.py` so the coordinator
emits exactly the bytes the SDK reader expects. The CDDL at
`tenant-sdk/cddl/receipt_v0_1.cddl` is the canonical contract; both
implementations validate against it.

Why not import from the SDK directly: the platform is AGPL-3.0 and the
SDK is Apache-2.0; the cleanest architecture per Q16 is one-way data
flow through the published contract (CDDL), not in-process import. Two
implementations converge on the same wire format by virtue of testing
against shared schema fixtures.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

import cbor2
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class TimeWindow(BaseModel):
    """Receipt time-window — start and end of the work attested."""

    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime


class QuorumAgreement(BaseModel):
    """Quorum-agreement metadata for the receipt."""

    model_config = ConfigDict(extra="forbid")

    replication_factor: Annotated[int, Field(gt=0)]
    agreeing_workers: Annotated[int, Field(gt=0)]
    method: str


class ResultHashAnchor(BaseModel):
    """A Rekor anchor for one of the agreeing results.

    M7b note: until §5.16 signing infrastructure ships, receipts are issued
    without real Rekor entries — `rekor_log_index` and `rekor_entry_uuid`
    carry placeholder values (`0` and `"lab-mode-no-rekor"` respectively).
    The `result_sha256` field is always real (computed from the canonical
    result payload). Verifiers in dev mode are expected to ignore Rekor
    fields per the `[receipts] mode` config; verifiers in operational mode
    require real Rekor anchoring.
    """

    model_config = ConfigDict(extra="forbid")

    rekor_log_index: Annotated[int, Field(ge=0)]
    rekor_entry_uuid: str
    result_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class Receipt(BaseModel):
    """An AuspexAI contribution receipt.

    Mirrors the SDK Receipt model field-for-field. The wire format is
    CBOR-encoded then COSE-Sign1-signed; see `signing.py` for the signing
    layer.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal["0.1"]
    tenant_id: str
    experiment_id: str
    worker_pubkey: Annotated[bytes, Field(min_length=32, max_length=32)]
    work_unit_ids: Annotated[list[str], Field(min_length=1)]
    time_window: TimeWindow
    quorum_agreement: QuorumAgreement
    result_hash_anchors: Annotated[list[ResultHashAnchor], Field(min_length=1)]

    @field_validator("worker_pubkey", mode="before")
    @classmethod
    def _decode_worker_pubkey(cls, v: Any) -> bytes:
        """Accept raw bytes (from CBOR) or lowercase-hex string (from JSON)."""
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    @field_serializer("worker_pubkey", when_used="json")
    def _serialize_worker_pubkey(self, v: bytes) -> str:
        """JSON form: lowercase hex. CBOR/python form uses raw bytes directly."""
        return v.hex()


# ---- CBOR encode / decode ----------------------------------------------------


def encode_cbor(receipt: Receipt) -> bytes:
    """Encode a Receipt to canonical CBOR bytes (per receipt_v0_1.cddl).

    Datetime fields encode as CBOR Tag 0 (RFC 3339 string). The 32-byte
    `worker_pubkey` encodes as native CBOR bytes. Output is the predicate
    body that gets COSE-Sign1-wrapped by `signing.cose_sign1_encode`.
    """
    return cbor2.dumps(receipt.model_dump(mode="python"), canonical=True)


def decode_cbor(data: bytes) -> Receipt:
    """Decode raw CBOR bytes to a Receipt. Pydantic-validates the result."""
    raw = cbor2.loads(data)
    return Receipt.model_validate(raw)
