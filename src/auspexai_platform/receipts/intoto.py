"""In-toto v1 Statement envelope for AuspexAI receipts.

Per §5.16 + §9 Q20: receipts are wrapped in an in-toto v1 Statement
with predicate type `https://auspexai.network/receipt/v0`. The CBOR-
encoded receipt body is the predicate content. The Statement is then
COSE-Sign1-signed and recorded in Rekor.

We build the Statement as a plain dict and CBOR-encode it (not JSON)
because the outer COSE wrapper expects bytes payload. The in-toto v1
spec permits any encoding for the Statement; CBOR keeps the entire
chain in one encoding.
"""

from __future__ import annotations

import hashlib

import cbor2

INTOTO_STATEMENT_TYPE = "https://www.in-toto.io/Statement/v1"
AUSPEXAI_RECEIPT_PREDICATE_TYPE = "https://auspexai.network/receipt/v0"
# #34 §6.3 — experiment-level result-set completion attestation.
AUSPEXAI_RESULT_SET_PREDICATE_TYPE = "https://auspexai.network/result-set/v0"
# EB-1 (§9 #47) — v1 adds the reproducibility-triple input leg: leaves bind
# unit_payload_sha256; predicate units carry coordinator-asserted environment.
AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1 = "https://auspexai.network/result-set/v1"

# D16.2: the submit-time pre-registration anchor's predicate type.
AUSPEXAI_PRE_REGISTRATION_PREDICATE_TYPE = "https://auspexai.network/pre-registration/v0"
# D16.2-D: a deviation record's anchor (append-only; §5).
AUSPEXAI_DEVIATION_PREDICATE_TYPE = "https://auspexai.network/pre-registration-deviation/v0"


def build_statement(
    *,
    receipt_cbor: bytes,
    receipt_id: str,
) -> bytes:
    """Build an in-toto v1 Statement wrapping a CBOR-encoded receipt.

    The subject identifies the receipt by ID and includes a SHA-256
    digest of the CBOR receipt body for content-binding.

    Returns canonical CBOR-encoded Statement bytes ready for COSE signing.
    """
    receipt_digest = hashlib.sha256(receipt_cbor).hexdigest()
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": f"auspexai:receipt/{receipt_id}",
                "digest": {"sha256": receipt_digest},
            }
        ],
        "predicateType": AUSPEXAI_RECEIPT_PREDICATE_TYPE,
        "predicate": receipt_cbor,
    }
    return cbor2.dumps(statement, canonical=True)


def build_result_set_statement(
    *,
    predicate_cbor: bytes,
    attestation_id: str,
    predicate_type: str = AUSPEXAI_RESULT_SET_PREDICATE_TYPE,
) -> bytes:
    """Build an in-toto v1 Statement wrapping a CBOR-encoded result-set
    attestation predicate (#34 §6.3). Mirrors `build_statement` but with the
    result-set predicate type; the subject binds the attestation id + a SHA-256
    digest of the predicate body. Returns canonical CBOR ready for COSE signing.
    `predicate_type` defaults to v0 so pre-EB-1 callers/tests are unchanged;
    the v1 builder passes AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1."""
    predicate_digest = hashlib.sha256(predicate_cbor).hexdigest()
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": f"auspexai:result-set/{attestation_id}",
                "digest": {"sha256": predicate_digest},
            }
        ],
        "predicateType": predicate_type,
        "predicate": predicate_cbor,
    }
    return cbor2.dumps(statement, canonical=True)


def build_pre_registration_statement(
    *,
    predicate_cbor: bytes,
    experiment_id: str,
) -> bytes:
    """Build an in-toto v1 Statement wrapping a pre-registration predicate
    (D16.2, preregistration_design.md §4). Mirrors `build_result_set_statement`
    with the pre-registration predicate type; the subject binds the experiment
    id + a SHA-256 digest of the predicate body. COSE-signed at SUBMIT and
    Rekor-anchored (the hourly backfill), so its anchor timestamp precedes the
    result attestation's — `design ≺ data`, publicly provable."""
    predicate_digest = hashlib.sha256(predicate_cbor).hexdigest()
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": f"auspexai:pre-registration/{experiment_id}",
                "digest": {"sha256": predicate_digest},
            }
        ],
        "predicateType": AUSPEXAI_PRE_REGISTRATION_PREDICATE_TYPE,
        "predicate": predicate_cbor,
    }
    return cbor2.dumps(statement, canonical=True)


def build_deviation_statement(
    *,
    predicate_cbor: bytes,
    deviation_id: str,
) -> bytes:
    """Build an in-toto v1 Statement wrapping a deviation predicate (D16.2-D §5).
    COSE-signed at declaration and Rekor-anchored by the same sweep as the
    pre-registration anchors — the deviation's own `declared_at` becomes
    publicly provable, never a silent edit of the original."""
    predicate_digest = hashlib.sha256(predicate_cbor).hexdigest()
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": f"auspexai:pre-registration-deviation/{deviation_id}",
                "digest": {"sha256": predicate_digest},
            }
        ],
        "predicateType": AUSPEXAI_DEVIATION_PREDICATE_TYPE,
        "predicate": predicate_cbor,
    }
    return cbor2.dumps(statement, canonical=True)


def unwrap_statement(statement_cbor: bytes) -> bytes:
    """Extract the receipt CBOR from an in-toto v1 Statement.

    If the input is already raw receipt CBOR (no Statement wrapper),
    returns it unchanged for backward compatibility with pre-in-toto
    receipts.
    """
    try:
        parsed = cbor2.loads(statement_cbor)
    except Exception:
        return statement_cbor
    if isinstance(parsed, dict) and parsed.get("_type") == INTOTO_STATEMENT_TYPE:
        predicate = parsed.get("predicate", b"")
        return predicate if isinstance(predicate, bytes) else statement_cbor
    return statement_cbor
