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
from datetime import datetime
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    ReceiptIndexRepository,
    WorkerRepository,
)
from auspexai_platform.eligibility import (
    EligibilityThresholds,
    compute_receipt_stats,
)
from auspexai_platform.exposure import ExposureTag
from auspexai_platform.rate_limit import limiter
from auspexai_platform.receipts import (
    CoseDecodeError,
    CoseVerificationError,
    Receipt,
    ReceiptRepository,
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


class ReceiptSummary(BaseModel):
    """Summary row for receipt-list endpoints. Just enough to identify and
    locate the receipt; the full COSE bytes + body come from
    GET /receipts/{receipt_id}."""

    receipt_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    worker_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    worker_pubkey: Annotated[str | None, ExposureTag.PUBLIC] = None
    issued_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None


class ReceiptListResponse(BaseModel):
    receipts: Annotated[list[ReceiptSummary] | None, ExposureTag.PUBLIC] = None


class TierEligibilityResponse(BaseModel):
    """One row of `ReceiptStatsResponse.eligibility_by_tier` — automated-gate
    state for one future tier. The `_pending` flags signal that the §6.1
    identity gate or vouching gate still needs human review; they NEVER
    flip to False from automatic computation (M7f is read-only)."""

    tier: Annotated[int | None, ExposureTag.PUBLIC] = None
    tier_name: Annotated[str | None, ExposureTag.PUBLIC] = None
    receipt_threshold_met: Annotated[bool | None, ExposureTag.PUBLIC] = None
    distinct_experiments_threshold_met: Annotated[bool | None, ExposureTag.PUBLIC] = None
    thresholds: Annotated[dict[str, int] | None, ExposureTag.PUBLIC] = None
    actuals: Annotated[dict[str, int] | None, ExposureTag.PUBLIC] = None
    identity_check_pending: Annotated[bool | None, ExposureTag.PUBLIC] = None
    vouching_pending: Annotated[bool | None, ExposureTag.PUBLIC] = None
    ready_for_human_review: Annotated[bool | None, ExposureTag.PUBLIC] = None


class ReceiptStatsResponse(BaseModel):
    """Account-level receipt-history aggregate + per-tier eligibility readout
    (M7f). Account-self + maintainer only.

    The `eligibility_by_tier` field implements §6.2's "tier promotion logic
    [that] inspects receipt history at thresholds" — as a passive signal,
    not as an automatic promotion. Per §6.1, T2+ promotions require a
    real-identity check OR vouching by an existing T2+ plus human review;
    the actual tier-bump endpoint lives in a future milestone bundled with
    that work.
    """

    account_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    current_tier: Annotated[int | None, ExposureTag.PUBLIC] = None
    current_tier_name: Annotated[str | None, ExposureTag.PUBLIC] = None
    total_receipts: Annotated[int | None, ExposureTag.PUBLIC] = None
    distinct_experiments: Annotated[int | None, ExposureTag.PUBLIC] = None
    distinct_tenants: Annotated[int | None, ExposureTag.PUBLIC] = None
    first_receipt_at: Annotated[str | None, ExposureTag.PUBLIC] = None
    last_receipt_at: Annotated[str | None, ExposureTag.PUBLIC] = None
    eligibility_by_tier: Annotated[list[TierEligibilityResponse] | None, ExposureTag.PUBLIC] = None


class ReceiptFetchResponse(BaseModel):
    """Full receipt content for `GET /receipts/{receipt_id}` (anonymous-public).

    The `cose_signed_blob_b64` field is the canonical wire bytes — what
    a verifier feeds into `POST /receipts/verify`. The `receipt` field
    is the Pydantic-decoded body for convenience; verifiers should not
    trust it without the COSE signature check.
    """

    receipt_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    issued_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    signing_key_pubkey_hex: Annotated[str | None, ExposureTag.PUBLIC] = None
    cose_signed_blob_b64: Annotated[str | None, ExposureTag.PUBLIC] = None
    receipt: Annotated[Receipt | None, ExposureTag.PUBLIC] = None


def build_router(
    *,
    coordinator_mode: str,
    credential_dep=None,
    receipt_index_repository: ReceiptIndexRepository | None = None,
    worker_repository: WorkerRepository | None = None,
    account_repository: AccountRepository | None = None,
    per_job_factory: PerJobDatabaseFactory | None = None,
    eligibility_thresholds: EligibilityThresholds | None = None,
) -> APIRouter:
    """Build the receipts router.

    Args:
        coordinator_mode: `Config.receipts_mode` value — surfaces in
            verify responses so callers can see trust posture.
        credential_dep: FastAPI dependency for the auth-credential.
            Required for the M7e list/fetch endpoints; left optional for
            backward compatibility with the M7d-only build (verify is
            anonymous-public and doesn't need a credential).
        receipt_index_repository / worker_repository / account_repository /
        per_job_factory: required for M7e endpoints. The verify endpoint
            (M7d) doesn't need them.
    """
    router = APIRouter()

    @router.post(
        "/receipts/verify",
        response_model=ReceiptVerifyResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit("60/minute")
    async def verify_receipt(request: Request, body: ReceiptVerifyRequest) -> ReceiptVerifyResponse:
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

    # ---- M7e endpoints ----------------------------------------------------
    #
    # These three are only mounted when their dependencies were provided.
    # The verify endpoint above stays anonymous-public; these three add
    # receipt-by-id (anonymous-public, DOI-analogue), account-listing
    # (account-self + maintainer), and worker-listing (worker-self +
    # maintainer).

    if (
        credential_dep is None
        or receipt_index_repository is None
        or worker_repository is None
        or account_repository is None
        or per_job_factory is None
    ):
        return router

    @router.get(
        "/receipts/{receipt_id}",
        response_model=ReceiptFetchResponse,
        response_model_exclude_none=True,
    )
    async def get_receipt(receipt_id: str) -> ReceiptFetchResponse:
        """Anonymous-public. Fetch a receipt by its ID.

        Per §6.8.1 DOI-analogue framing: receipts are cite-by-ID artifacts.
        Receipt IDs are unguessable (~72 bits of entropy), so enumeration
        attacks aren't viable; the caller must already know the ID, and
        knowing the ID implies someone shared it.

        Note: the returned receipt body contains worker_pubkey by design
        (it's the receipt's identity binding per §6.8.1 + the
        receipt_v0_1.cddl comment). This endpoint does NOT leak the
        worker_pubkey→account_id mapping; that mapping is operator-only.
        """
        entry = receipt_index_repository.get_by_id(receipt_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_not_found",
                        "message": f"no receipt with id {receipt_id!r}",
                    }
                },
            )
        per_job_db = per_job_factory.get(entry.experiment_id)
        if per_job_db is None:
            # Index pointed at an experiment whose per-job DB no longer
            # exists. Shouldn't happen at Phase 1 lab altitude.
            logger.warning(
                "receipt_index has %s but per-job DB for %s is missing",
                receipt_id,
                entry.experiment_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_storage_missing",
                        "message": (
                            "receipt index entry exists but the per-job DB "
                            "is unreachable — likely a coordinator bug"
                        ),
                    }
                },
            )
        record = ReceiptRepository(per_job_db).get_by_id(receipt_id)
        if record is None:
            # Same kind of inconsistency — index exists but per-job row
            # was deleted. Shouldn't happen.
            logger.warning(
                "receipt_index has %s but per-job receipts row is missing",
                receipt_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_storage_missing",
                        "message": (
                            "receipt index entry exists but the per-job row "
                            "is missing — likely a coordinator bug"
                        ),
                    }
                },
            )
        # Decode the inner CBOR for convenience. Best-effort: if the
        # inner payload is somehow malformed at storage time, still return
        # the COSE bytes — verifier can paste them into /receipts/verify
        # and get a structured error there.
        try:
            receipt_body = decode_cbor(record.receipt_body_cbor)
        except Exception:
            receipt_body = None
        return ReceiptFetchResponse(
            receipt_id=record.receipt_id,
            experiment_id=entry.experiment_id,
            issued_at=record.issued_at,
            signing_key_pubkey_hex=record.signing_key_pubkey_hex,
            cose_signed_blob_b64=base64.b64encode(record.cose_signed_blob).decode("ascii"),
            receipt=receipt_body,
        )

    @router.get(
        "/accounts/{account_id}/receipts",
        response_model=ReceiptListResponse,
        response_model_exclude_none=True,
    )
    async def list_account_receipts(
        account_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ReceiptListResponse:
        """List all receipts attributable to one account. Account-self +
        maintainer only.

        Account-self check: the credential is a worker bound to this
        account_id. Anonymous + T0 workers (no account binding) cannot
        list account receipts — they have no account.
        """
        _require_account_self_or_maintainer(credential, account_id, account_repository)

        entries = receipt_index_repository.list_for_account(account_id)
        return ReceiptListResponse(receipts=[_entry_to_summary(e) for e in entries])

    @router.get(
        "/workers/{worker_id}/receipts",
        response_model=ReceiptListResponse,
        response_model_exclude_none=True,
    )
    async def list_worker_receipts(
        worker_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ReceiptListResponse:
        """List all receipts attributable to one worker. Worker-self +
        maintainer only."""
        _require_worker_self_or_maintainer(credential, worker_id)

        entries = receipt_index_repository.list_for_worker(worker_id)
        return ReceiptListResponse(receipts=[_entry_to_summary(e) for e in entries])

    # ---- M7-tail: GET /workers/{id}/results/{result_id}/canonical-receipt ----

    @router.get(
        "/workers/{worker_id}/results/{result_id}/canonical-receipt",
        response_model=ReceiptFetchResponse,
        response_model_exclude_none=True,
    )
    async def get_canonical_receipt_for_result(
        worker_id: str,
        result_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ReceiptFetchResponse:
        """Worker-self + maintainer. Fetch the canonical COSE-Sign1 receipt
        bytes for one of this worker's submitted results.

        Used by the worker's background fetch loop (M7-tail) to populate its
        local `submitted_results.canonical_blob` cache, which `auspexai-worker
        receipts show <id>` then serves instead of the M5 placeholder.

        404 if no receipt exists for this (worker, result) pair — most
        commonly because the unit's quorum disagreed and no receipts were
        issued, or the request raced ahead of M7c's issuance hook.
        """
        _require_worker_self_or_maintainer(credential, worker_id)

        entry = receipt_index_repository.get_for_worker_result(
            worker_id=worker_id, result_id=result_id
        )
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_not_issued",
                        "message": (
                            f"no receipt issued for worker={worker_id} "
                            f"result={result_id} — likely the unit's quorum "
                            f"disagreed, or M7c issuance hasn't fired yet"
                        ),
                    }
                },
            )

        per_job_db = per_job_factory.get(entry.experiment_id)
        if per_job_db is None:
            logger.warning(
                "receipt_index has %s but per-job DB for %s is missing",
                entry.receipt_id,
                entry.experiment_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_storage_missing",
                        "message": (
                            "receipt index entry exists but the per-job DB "
                            "is unreachable — likely a coordinator bug"
                        ),
                    }
                },
            )
        record = ReceiptRepository(per_job_db).get_by_id(entry.receipt_id)
        if record is None:
            logger.warning(
                "receipt_index has %s but per-job row is missing",
                entry.receipt_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "receipt_storage_missing",
                        "message": (
                            "receipt index entry exists but the per-job row "
                            "is missing — likely a coordinator bug"
                        ),
                    }
                },
            )
        try:
            receipt_body = decode_cbor(record.receipt_body_cbor)
        except Exception:
            receipt_body = None
        return ReceiptFetchResponse(
            receipt_id=record.receipt_id,
            experiment_id=entry.experiment_id,
            issued_at=record.issued_at,
            signing_key_pubkey_hex=record.signing_key_pubkey_hex,
            cose_signed_blob_b64=base64.b64encode(record.cose_signed_blob).decode("ascii"),
            receipt=receipt_body,
        )

    # ---- M7f: GET /accounts/{account_id}/receipt-stats ------------------

    if eligibility_thresholds is not None:

        @router.get(
            "/accounts/{account_id}/receipt-stats",
            response_model=ReceiptStatsResponse,
            response_model_exclude_none=True,
        )
        async def get_receipt_stats(
            account_id: str,
            credential: Credential = Depends(credential_dep),  # noqa: B008
        ) -> ReceiptStatsResponse:
            """Account-level receipt-history aggregates + per-tier eligibility
            readout (M7f). Account-self + maintainer only.

            Per §6.2 this is "tier promotion logic [that] inspects receipt
            history at thresholds" — rendered as a passive signal. Per §6.1
            the actual T2+ promotion requires real-identity verification OR
            vouching by an existing T2+ plus human review; the tier-bump
            endpoint itself is a future milestone.
            """
            _require_account_self_or_maintainer(credential, account_id, account_repository)

            account = account_repository.get_by_id(account_id)
            if account is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": {
                            "code": "account_not_found",
                            "message": f"no account with id {account_id!r}",
                        }
                    },
                )

            stats = compute_receipt_stats(
                account_id=account_id,
                current_tier=int(account.trust_tier),
                receipt_index_repository=receipt_index_repository,
                thresholds=eligibility_thresholds,
            )
            return ReceiptStatsResponse(
                account_id=stats.account_id,
                current_tier=stats.current_tier,
                current_tier_name=stats.current_tier_name,
                total_receipts=stats.total_receipts,
                distinct_experiments=stats.distinct_experiments,
                distinct_tenants=stats.distinct_tenants,
                first_receipt_at=stats.first_receipt_at,
                last_receipt_at=stats.last_receipt_at,
                eligibility_by_tier=[
                    TierEligibilityResponse(
                        tier=e.tier,
                        tier_name=e.tier_name,
                        receipt_threshold_met=e.receipt_threshold_met,
                        distinct_experiments_threshold_met=e.distinct_experiments_threshold_met,
                        thresholds=e.thresholds,
                        actuals=e.actuals,
                        identity_check_pending=e.identity_check_pending,
                        vouching_pending=e.vouching_pending,
                        ready_for_human_review=e.ready_for_human_review,
                    )
                    for e in stats.eligibility_by_tier
                ],
            )

    return router


def _entry_to_summary(entry) -> ReceiptSummary:
    return ReceiptSummary(
        receipt_id=entry.receipt_id,
        experiment_id=entry.experiment_id,
        worker_id=entry.worker_id,
        worker_pubkey=entry.worker_pubkey,
        issued_at=entry.issued_at,
    )


def _require_account_self_or_maintainer(
    credential: Credential,
    url_account_id: str,
    account_repository: AccountRepository,
) -> None:
    """403 unless the credential is bound to `url_account_id` OR a maintainer."""
    if credential.kind == CredentialClass.MAINTAINER:
        return
    if credential.account_id is not None and credential.account_id == url_account_id:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "account_self_or_maintainer_required",
                "message": (
                    "this endpoint requires a worker credential bound to "
                    "the requested account_id OR a maintainer credential"
                ),
                "details": {
                    "credential_class": credential.kind.value,
                    "credential_account_id": credential.account_id,
                    "url_account_id": url_account_id,
                },
            }
        },
    )


def _require_worker_self_or_maintainer(credential: Credential, url_worker_id: str) -> None:
    """403 unless the credential is the worker itself OR a maintainer."""
    if credential.kind == CredentialClass.MAINTAINER:
        return
    if credential.worker_id is not None and credential.worker_id == url_worker_id:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "worker_self_or_maintainer_required",
                "message": (
                    "this endpoint requires the worker credential whose "
                    "worker_id matches the URL OR a maintainer credential"
                ),
                "details": {
                    "credential_class": credential.kind.value,
                    "credential_worker_id": credential.worker_id,
                    "url_worker_id": url_worker_id,
                },
            }
        },
    )
