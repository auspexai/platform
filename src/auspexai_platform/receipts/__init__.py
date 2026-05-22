"""Contribution receipts — issuance, signing, storage.

Per Principles & Scope §6.8.1 + §5.16: the coordinator issues a signed
receipt for every work unit that reaches its replication target with
agreeing results. Receipts are CBOR-encoded (per
`tenant-sdk/cddl/receipt_v0_1.cddl`), COSE-Sign1-signed (RFC 9052) by
the coordinator's receipt-signing key, and stored on the per-job DB.

M7b ships the foundation: receipt models, COSE Sign1 encoder/decoder,
persistent receipt-signing key, per-job storage table, and the
ReceiptRepository. M7c wires in the issuance trigger; M7d adds the
public /receipts/verify endpoint.

**Signing posture per 2026-05-22 design discussion:**

The receipt-signing key is **persistent**, generated on the coordinator's
first startup and reused across restarts (lives at
`<state_dir>/coordinator_receipt_signing_key.pem` at `0600`). Receipts
issued by a "dev mode" coordinator carry the same wire format as those
issued by an "operational mode" coordinator — the distinction lives at
the deployment / `AUTHORIZED_SIGNERS.md` layer, not in the receipt body
itself. When the §5.16 Fulcio attestation ceremony runs, the same
persistent key gets promoted (Path A) or the dev key gets archived and
a fresh attested key takes over (Path B). Either way, no `is_lab_mode`
field in the wire format — the wire format is immutable per §11 Q20.

**What M7b does NOT ship:**

- Receipt issuance trigger (M7c)
- Custom-reducer dispatch (M7c-tail or M8)
- Public verifier endpoint (M7d)
- In-toto v1 Statement envelope wrapping + Rekor recording (§5.16 work
  promoted to launch prerequisite — until then, the COSE-Sign1 bytes are
  the canonical wire format and the in-toto wrapping comes later as a
  pure additive layer)
"""

from __future__ import annotations

from auspexai_platform.receipts.models import (
    QuorumAgreement,
    Receipt,
    ResultHashAnchor,
    TimeWindow,
    decode_cbor,
    encode_cbor,
)
from auspexai_platform.receipts.repository import (
    ReceiptRecord,
    ReceiptRepository,
)
from auspexai_platform.receipts.signing import (
    CoseDecodeError,
    CoseVerificationError,
    SigningKey,
    cose_sign1_decode,
    cose_sign1_encode,
    load_or_generate_signing_key,
)

__all__ = [
    "CoseDecodeError",
    "CoseVerificationError",
    "QuorumAgreement",
    "Receipt",
    "ReceiptRecord",
    "ReceiptRepository",
    "ResultHashAnchor",
    "SigningKey",
    "TimeWindow",
    "cose_sign1_decode",
    "cose_sign1_encode",
    "decode_cbor",
    "encode_cbor",
    "load_or_generate_signing_key",
]
