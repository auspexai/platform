"""Receipt verification endpoint (M7d).

  POST /api/v0/receipts/verify  — anonymous-public; verify a COSE-Sign1
                                  receipt blob.

Verification at M7d is schema-only:

  1. Base64-decode the supplied blob.
  2. Parse the outer COSE_Sign1 (RFC 9052 §4.1).
  3. Verify the signature against the kid in the protected header
     (the kid IS the signer's pubkey hex per our convention).
  4. CBOR-decode the inner payload.
  5. Pydantic-validate against receipt_v0_1.cddl.

What M7d does NOT do (deferred to §5.16 signing infrastructure when it
ships as a launch prerequisite):

  - Look up the kid in Rekor for the Fulcio attestation chain.
  - Check the attestation chain's GitHub OIDC identity against
    `auspexai/.github/security/AUTHORIZED_SIGNERS.md`.
  - Distinguish "the signature mathematically verifies" from "this
    signer is authorized to attest on AuspexAI's behalf."

Until those land, the response includes `coordinator_mode` (from
runtime config, `dev` or `operational`) and `authorized_signer` (always
`null` for M7d, with an explanation in `authorized_signer_note`) so
external verifiers can see the trust posture without needing to consult
docs.

This endpoint is anonymous-public because the COSE signature is itself
the unforgeable proof: bad receipts produce verdicts of "signature
invalid"; well-formed receipts identify their own signer via the kid.
No coordinator-side credential is required to interpret a receipt — the
trust chain lives in the bytes (and, post-§5.16, in Rekor).
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from auspexai_platform.exposure import ExposureTag
from auspexai_platform.receipts import (
    CoseDecodeError,
    CoseVerificationError,
    Receipt,
    cose_sign1_decode,
    decode_cbor,
)

logger = logging.getLogger(__name__)


# ---- request / response models --------------------------------------------


class ReceiptVerifyRequest(BaseModel):
    """Body shape for POST /receipts/verify.

    `receipt_cose_b64` is the base64-encoded COSE_Sign1 receipt bytes —
    the exact bytes the coordinator produced via `cose_sign1_encode` and
    persisted in `submitted_results.cose_signed_blob` (worker side) /
    `receipts.cose_signed_blob` (coord side).
    """

    receipt_cose_b64: str = Field(
        min_length=1,
        max_length=131072,  # 128 KiB — generous for v0 receipts
        description=(
            "Base64-encoded COSE_Sign1 receipt bytes. Accepts standard "
            "base64 with or without padding."
        ),
    )


class ReceiptVerifyResponse(BaseModel):
    """Structured trust-posture verdict for a single receipt.

    `signature_valid` and `schema_valid` are independent: a structurally
    valid receipt can have a bad signature, and a well-signed blob can
    contain a CBOR payload that doesn't validate against the receipt
    schema. Verifiers should require both `true` to trust the receipt's
    content.

    `authorized_signer` is the §5.16-deferred field. M7d always returns
    `null` with an explanation in `authorized_signer_note`. When §5.16
    ships, this becomes `true`/`false` based on the Fulcio attestation
    chain + `AUTHORIZED_SIGNERS.md` roster.
    """

    signature_valid: Annotated[bool | None, ExposureTag.PUBLIC] = None
    schema_valid: Annotated[bool | None, ExposureTag.PUBLIC] = None
    signer_kid: Annotated[str | None, ExposureTag.PUBLIC] = None
    coordinator_mode: Annotated[str | None, ExposureTag.PUBLIC] = None
    authorized_signer: Annotated[bool | None, ExposureTag.PUBLIC] = None
    authorized_signer_note: Annotated[str | None, ExposureTag.PUBLIC] = None
    receipt: Annotated[Receipt | None, ExposureTag.PUBLIC] = None
    errors: Annotated[list[str] | None, ExposureTag.PUBLIC] = None


# ---- router ---------------------------------------------------------------


_AUTHORIZED_SIGNER_NOTE_M7D = (
    "Authoritative roster verification arrives with §5.16 signing "
    "infrastructure (one-time Maintainer Fulcio attestation + "
    "auspexai/.github/security/AUTHORIZED_SIGNERS.md). Until then, this "
    "field is null even when the signature mathematically verifies — "
    "the signer's identity has not yet been chained to AuspexAI's "
    "authoritative roster."
)


def build_router(*, coordinator_mode: str) -> APIRouter:
    """Build the /receipts/verify router.

    Args:
        coordinator_mode: `Config.receipts_mode` value — either `"dev"` or
            `"operational"`. Surfaces in every response so callers can see
            the trust posture without consulting docs.
    """
    router = APIRouter()

    @router.post(
        "/receipts/verify",
        response_model=ReceiptVerifyResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_200_OK,
    )
    async def verify_receipt(body: ReceiptVerifyRequest) -> ReceiptVerifyResponse:
        # 1. Base64-decode. Malformed base64 is the only condition that
        #    earns a 4xx — every other failure is a "well-formed request
        #    but the receipt is invalid" 200 verdict.
        try:
            cose_bytes = base64.b64decode(body.receipt_cose_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": "invalid_base64",
                        "message": f"receipt_cose_b64 is not valid base64: {exc}",
                    }
                },
            ) from exc

        errors: list[str] = []

        # 2-3. COSE_Sign1 outer decode + signature verification against
        # the kid declared in the protected header.
        signature_valid = False
        signer_kid: str | None = None
        payload_bytes: bytes | None = None
        try:
            # First decode without verification to extract the kid.
            payload_bytes, signer_kid = cose_sign1_decode(cose_bytes)
        except CoseDecodeError as exc:
            errors.append(f"cose_decode: {exc}")
            return ReceiptVerifyResponse(
                signature_valid=False,
                schema_valid=False,
                signer_kid=None,
                coordinator_mode=coordinator_mode,
                authorized_signer=None,
                authorized_signer_note=_AUTHORIZED_SIGNER_NOTE_M7D,
                receipt=None,
                errors=errors,
            )

        try:
            kid_bytes = bytes.fromhex(signer_kid)
            if len(kid_bytes) != 32:
                raise ValueError(f"kid is not a 32-byte hex string (got {len(kid_bytes)} bytes)")
            pubkey = Ed25519PublicKey.from_public_bytes(kid_bytes)
        except (ValueError, Exception) as exc:
            errors.append(f"kid_invalid: {exc}")
            return ReceiptVerifyResponse(
                signature_valid=False,
                schema_valid=False,
                signer_kid=signer_kid,
                coordinator_mode=coordinator_mode,
                authorized_signer=None,
                authorized_signer_note=_AUTHORIZED_SIGNER_NOTE_M7D,
                receipt=None,
                errors=errors,
            )

        try:
            cose_sign1_decode(cose_bytes, expected_pubkey=pubkey)
            signature_valid = True
        except CoseVerificationError as exc:
            errors.append(f"signature: {exc}")
        except CoseDecodeError as exc:
            # Shouldn't hit this on the second decode if the first succeeded,
            # but guard anyway.
            errors.append(f"cose_decode_verify: {exc}")

        # 4-5. CBOR-decode the inner payload and Pydantic-validate.
        receipt: Receipt | None = None
        schema_valid = False
        try:
            receipt = decode_cbor(payload_bytes)
            schema_valid = True
        except Exception as exc:
            errors.append(f"schema: {exc}")

        return ReceiptVerifyResponse(
            signature_valid=signature_valid,
            schema_valid=schema_valid,
            signer_kid=signer_kid,
            coordinator_mode=coordinator_mode,
            authorized_signer=None,
            authorized_signer_note=_AUTHORIZED_SIGNER_NOTE_M7D,
            receipt=receipt,
            errors=errors or None,
        )

    return router
