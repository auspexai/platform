"""Receipt issuance — built-in hash_agreement reducer + receipt construction.

Called from the M6d submit_result endpoint when a work unit transitions
to `completed` (i.e., its replication_target is met). The flow:

  1. Run the hash_agreement reducer over the unit's collected results.
  2. If the workers' semantic payloads all match → "agree": issue one
     receipt per agreeing worker, each attesting to that worker's
     contribution + the quorum metadata about the others.
  3. If they disagree → no receipts; the unit stays `completed` (per the
     M6d schema) but no signed attestations are produced. Operator
     handles disagreement out-of-band for Phase 1 lab.

Custom reducers (tenant-supplied subprocess reducers per the SDK's
`reducer_decision_v0_1.cddl`) are deferred to a later milestone (M7c-tail
or M8) — the synthetic test tenant and the planned first AuspexAI tenant
don't need them yet, and custom-reducer subprocess sandboxing is real
work.

"Semantic hash" vs "result hash":
  - **Semantic hash**: SHA-256 of canonical `{exit_code, payload}`. The
    parts workers should agree on. The reducer compares these to decide
    agree/disagree.
  - **Result hash**: SHA-256 of the full canonical worker-signing input
    (unit_id, worker_pubkey, completed_at, exit_code, payload). Goes
    into `result_hash_anchors` so each receipt anchors a specific
    worker's signed result. Different across workers even when their
    semantic payloads agree.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from hashlib import sha256

from auspexai_platform.db.models import Experiment, Result, WorkUnit
from auspexai_platform.db.repositories import ReceiptIndexRepository
from auspexai_platform.receipts.intoto import build_statement
from auspexai_platform.receipts.models import (
    QuorumAgreement,
    Receipt,
    ResultHashAnchor,
    TimeWindow,
    encode_cbor,
)
from auspexai_platform.receipts.rekor import NoOpRekorClient, RekorClient
from auspexai_platform.receipts.repository import ReceiptRecord, ReceiptRepository
from auspexai_platform.receipts.signing import SigningKey, cose_sign1_encode

logger = logging.getLogger(__name__)


HASH_AGREEMENT_METHOD = "builtin_hash_agreement"


@dataclass(frozen=True)
class AgreementOutcome:
    """Result of running a reducer over a unit's collected results."""

    agreed: bool
    method: str  # 'builtin_hash_agreement' or 'custom:<name>' (M7c-tail+)
    agreeing_workers: int  # 0 on disagreement
    semantic_hash: str | None  # the hash all agreeing results share, None on disagree


@dataclass(frozen=True)
class ReceiptIssuanceOutcome:
    """What `issue_receipts_for_completed_unit` returns to the caller."""

    issued_receipt_ids: list[str]
    agreement: AgreementOutcome


def _semantic_hash(result: Result) -> str:
    """SHA-256 of the canonical `{exit_code, payload}`. Used by the agreement
    reducer to compare results from different workers."""
    canonical = json.dumps(
        {"exit_code": result.exit_code, "payload": result.payload},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _result_hash(result: Result) -> str:
    """SHA-256 of the full canonical worker-signed form. Used for the
    `result_hash_anchors` field of the receipt — each anchor identifies
    a specific worker's specific result."""
    completed_at = result.completed_at
    if hasattr(completed_at, "isoformat"):
        completed_at = completed_at.isoformat()
    canonical = json.dumps(
        {
            "unit_id": result.unit_id,
            "worker_pubkey": result.worker_pubkey_hex.lower(),
            "completed_at": completed_at,
            "exit_code": result.exit_code,
            "payload": result.payload,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def hash_agreement_reducer(results: list[Result]) -> AgreementOutcome:
    """Built-in reducer: agree iff all results share the same semantic hash.

    Empty results list returns `agreed=False, agreeing_workers=0` — this
    is a defensive guard against the (shouldn't-happen) case where the
    issuance hook fires with no results to reduce.
    """
    if not results:
        return AgreementOutcome(
            agreed=False,
            method=HASH_AGREEMENT_METHOD,
            agreeing_workers=0,
            semantic_hash=None,
        )
    hashes = [_semantic_hash(r) for r in results]
    if all(h == hashes[0] for h in hashes):
        return AgreementOutcome(
            agreed=True,
            method=HASH_AGREEMENT_METHOD,
            agreeing_workers=len(results),
            semantic_hash=hashes[0],
        )
    return AgreementOutcome(
        agreed=False,
        method=HASH_AGREEMENT_METHOD,
        agreeing_workers=0,
        semantic_hash=None,
    )


def _generate_receipt_id() -> str:
    return f"rcpt-{secrets.token_urlsafe(9)}"


def issue_receipts_for_completed_unit(
    *,
    work_unit: WorkUnit,
    experiment: Experiment,
    results: list[Result],
    receipt_repo: ReceiptRepository,
    signing_key: SigningKey,
    receipt_index_repo: ReceiptIndexRepository | None = None,
    rekor_client: RekorClient | NoOpRekorClient | None = None,
) -> ReceiptIssuanceOutcome:
    """Build, sign, and persist one receipt per agreeing worker.

    Returns the list of issued receipt_ids and the reducer's agreement
    outcome. On disagreement, no receipts are issued (empty list) — the
    operator handles disagreement out-of-band.

    Errors during signing or persistence raise upward. The caller
    (submit_result route) catches and logs but does NOT roll back the
    unit-completion — the unit is genuinely done from a scheduling
    standpoint; missing receipts can be re-issued by a sweep job later
    if needed.
    """
    outcome = hash_agreement_reducer(results)
    if not outcome.agreed:
        logger.warning(
            "unit %s: results did not agree under %s — no receipts issued "
            "(replication_factor=%d, results_seen=%d)",
            work_unit.unit_id,
            outcome.method,
            work_unit.replication_target,
            len(results),
        )
        return ReceiptIssuanceOutcome(issued_receipt_ids=[], agreement=outcome)

    # All results have the same semantic hash. Build hash anchors covering
    # each agreeing result (one per worker). Anchors are identical content
    # across all receipts in this batch.
    anchors = [
        ResultHashAnchor(
            rekor_log_index=0,  # placeholder until §5.16 Rekor integration
            rekor_entry_uuid="lab-mode-no-rekor",
            result_sha256=_result_hash(r),
        )
        for r in results
    ]
    time_window_start = min(r.completed_at for r in results)
    time_window_end = max(r.completed_at for r in results)

    _rekor = rekor_client or NoOpRekorClient()

    issued: list[str] = []
    for result in results:
        receipt_id = _generate_receipt_id()
        receipt = Receipt(
            version="0.1",
            tenant_id=experiment.tenant_id,
            experiment_id=experiment.tenant_experiment_label,
            worker_pubkey=bytes.fromhex(result.worker_pubkey_hex.lower()),
            work_unit_ids=[work_unit.unit_id],
            time_window=TimeWindow(start=time_window_start, end=time_window_end),
            quorum_agreement=QuorumAgreement(
                replication_factor=work_unit.replication_target,
                agreeing_workers=outcome.agreeing_workers,
                method=outcome.method,
            ),
            result_hash_anchors=anchors,
        )
        cbor_payload = encode_cbor(receipt)

        statement_cbor = build_statement(
            receipt_cbor=cbor_payload,
            receipt_id=receipt_id,
        )
        cose_blob = cose_sign1_encode(payload=statement_cbor, signing_key=signing_key)

        try:
            rekor_entry = _rekor.record(cose_blob)
        except Exception:
            logger.exception(
                "rekor recording failed for receipt %s; using placeholder anchors",
                receipt_id,
            )
            rekor_entry = NoOpRekorClient().record(cose_blob)

        if rekor_entry.log_index != 0 or rekor_entry.entry_uuid != "lab-mode-no-rekor":
            receipt = receipt.model_copy(
                update={
                    "result_hash_anchors": [
                        ResultHashAnchor(
                            rekor_log_index=rekor_entry.log_index,
                            rekor_entry_uuid=rekor_entry.entry_uuid,
                            result_sha256=a.result_sha256,
                        )
                        for a in anchors
                    ]
                }
            )
            cbor_payload = encode_cbor(receipt)
            statement_cbor = build_statement(
                receipt_cbor=cbor_payload,
                receipt_id=receipt_id,
            )
            cose_blob = cose_sign1_encode(payload=statement_cbor, signing_key=signing_key)

        record: ReceiptRecord = receipt_repo.insert(
            receipt_id=receipt_id,
            work_unit_ids=[work_unit.unit_id],
            cose_signed_blob=cose_blob,
            receipt_body_cbor=cbor_payload,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
        )
        issued.append(record.receipt_id)
        # M7e: index the receipt on the control DB so cross-experiment
        # lookups (receipt-by-id, list-for-account, list-for-worker) don't
        # need to walk every per-job DB. Best-effort: if the index write
        # fails for some reason, the per-job receipt row is the source of
        # truth and a sweep can rebuild the index later.
        if receipt_index_repo is not None:
            try:
                receipt_index_repo.record(
                    receipt_id=record.receipt_id,
                    experiment_id=experiment.experiment_id,
                    worker_id=result.worker_id,
                    worker_pubkey=result.worker_pubkey_hex,
                    result_id=result.result_id,
                )
            except Exception:
                logger.exception(
                    "receipt_index insert failed for %s; per-job row is "
                    "intact and the index can be rebuilt by a sweep",
                    record.receipt_id,
                )
        logger.info(
            "issued receipt %s for unit %s worker %s (agreement=%s, agreeing=%d/%d)",
            record.receipt_id,
            work_unit.unit_id,
            result.worker_pubkey_hex[:16],
            outcome.method,
            outcome.agreeing_workers,
            work_unit.replication_target,
        )

    return ReceiptIssuanceOutcome(issued_receipt_ids=issued, agreement=outcome)
