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

import logging
import secrets
from dataclasses import dataclass, field
from hashlib import sha256

from auspexai_platform.db.models import Experiment, Result, WorkUnit
from auspexai_platform.db.repositories import ReceiptIndexRepository
from auspexai_platform.hashing import semantic_hash
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
from auspexai_platform.receipts.tolerance import predicate_features, tolerance_agreement
from auspexai_platform.result_signature import canonical_result_bytes

logger = logging.getLogger(__name__)


HASH_AGREEMENT_METHOD = "builtin_hash_agreement"
TOLERANCE_METHOD = "builtin_within_cell_tolerance"
# C17 / manifest v0.6 (process_only_reducer_and_provenance_v0_6_design.md,
# RATIFIED 2026-07-03): the OBSERVE-ONLY collection mode — no cross-replica
# agreement is ever claimed; every replica is an independent observation.
PROCESS_ONLY_METHOD = "builtin_process_only"


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
    # Result rows that formed the consensus (the agreeing subset). For
    # hash-agreement that is every result; for within_cell_tolerance only the
    # workers inside the envelope. The caller promotes one of THESE (never an
    # outlier) as the durable consensus copy.
    agreeing_result_ids: list[int] = field(default_factory=list)
    # C7 Inc 4: the tolerance-consensus evidence to persist at issuance —
    # representative / representative_hash / per-feature spread / the envelope in
    # force / counts. None for exact hash-agreement (nothing beyond the shared
    # hash to evidence) and for a non-agreed unit (no consensus to evidence; the
    # divergence index carries the outliers). The caller writes it to the per-job
    # `unit_consensus` table beside the consensus promotion — raw replicas age
    # off, so this is the durable record of HOW the unit agreed.
    tolerance_evidence: dict | None = None


def _semantic_hash(result: Result) -> str:
    """SHA-256 of the canonical `{exit_code, payload}`. Used by the agreement
    reducer to compare results from different workers. Delegates to the shared
    `auspexai_platform.hashing.semantic_hash` so the result store (M-Results)
    persists byte-identical hashes."""
    return semantic_hash(result.exit_code, result.payload)


def _result_hash(result: Result) -> str:
    """SHA-256 of the full canonical worker-signed form. Used for the
    `result_hash_anchors` field of the receipt — each anchor identifies a
    specific worker's specific result. §9 #13a: reconstructs the v0 or v1
    canonical body per the result's `schema_version`, so the anchor matches the
    exact bytes the worker signed (a v1 result binds its served-weights digest)."""
    return sha256(
        canonical_result_bytes(
            unit_id=result.unit_id,
            worker_pubkey=result.worker_pubkey_hex,
            completed_at=result.completed_at,
            exit_code=result.exit_code,
            payload=result.payload,
            schema_version=result.schema_version,
            served_weights=result.served_weights,
        )
    ).hexdigest()


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


def _reduce_unit(
    results: list[Result],
    *,
    experiment: Experiment,
    manifest: dict | None,
) -> tuple[AgreementOutcome, list[Result], list[Result], dict | None]:
    """Dispatch on the manifest's reducer kind; return the agreement outcome, the
    partition (agreeing results that earn receipts, outliers recorded as
    divergence), and — for an AGREED tolerance unit — the Inc 4 evidence dict
    (representative / spread / envelope-in-force / counts) the caller persists.
    `within_cell_tolerance` reads the feature_schema envelope; the default — and
    any unknown kind, defensively — is exact hash-agreement.

    C7 swaps ONLY the agreement predicate. The C14 count/floor logic that decides
    WHEN a unit settles is untouched (the floor is read here as the corroboration
    threshold, not re-implemented)."""
    reducer = (manifest or {}).get("reducer") or {}
    if reducer.get("kind") == PROCESS_ONLY_METHOD:
        # C17 observe-only: every collected replica is a valid, independent
        # OBSERVATION — all earn receipts, none is ever an outlier, nothing is
        # ever `diverged` (no comparison is made). Each receipt records
        # agreeing_workers=1 (a replica corroborates only itself — the honest
        # count), so the existing basis classifier yields `process_only` at ANY
        # replica count, untouched. The evidence row binds a DETERMINISTIC
        # representative (lexicographic-first observation hash — ratified Q3;
        # explicitly NOT a consensus claim) as the attestation leaf; the
        # observation count rides the evidence row and every observation's hash
        # is durably anchored in the receipts' result_hash_anchors.
        if not results:
            outcome = AgreementOutcome(
                agreed=False,
                method=PROCESS_ONLY_METHOD,
                agreeing_workers=0,
                semantic_hash=None,
            )
            return outcome, [], [], None
        representative_hash = min(_semantic_hash(r) for r in results)
        outcome = AgreementOutcome(
            agreed=True,
            method=PROCESS_ONLY_METHOD,
            agreeing_workers=1,
            semantic_hash=representative_hash,
        )
        evidence = {
            "method": PROCESS_ONLY_METHOD,
            "representative": None,  # there is no consensus value, by design
            "representative_hash": representative_hash,
            "spread": None,
            "envelope": None,
            # Evidence-only observation count (basis reads the RECEIPTS' honest
            # agreeing_workers=1, never this row).
            "agreeing_workers": len(results),
            "outlier_count": 0,
        }
        return outcome, results, [], evidence
    if reducer.get("kind") == TOLERANCE_METHOD:
        feature_schema = (manifest or {}).get("feature_schema") or {}
        tolerance_features = reducer.get("tolerance_features")
        part = tolerance_agreement(
            results,
            feature_schema=feature_schema,
            tolerance_features=tolerance_features,
            floor=getattr(experiment, "replication_floor", None) or 1,
        )
        outcome = AgreementOutcome(
            agreed=part.agreed,
            method=TOLERANCE_METHOD,
            agreeing_workers=len(part.agreeing_indices) if part.agreed else 0,
            semantic_hash=part.representative_hash,
        )
        if part.agreed:
            # The envelope IN FORCE at issuance: the per-feature comparison rules
            # the predicate actually evaluated (the calibrated numbers a reviewer
            # checks the spread against).
            envelope = {
                path: feature_schema[path]["comparison"]
                for path in predicate_features(feature_schema, tolerance_features)
            }
            evidence = {
                "method": TOLERANCE_METHOD,
                "representative": part.representative,
                "representative_hash": part.representative_hash,
                "spread": part.per_feature_spread,
                "envelope": envelope,
                "agreeing_workers": len(part.agreeing_indices),
                "outlier_count": len(part.outlier_indices),
                # D19: anchor the outliers' hashes in the durable evidence (and
                # thence the signed predicate) — without this an outlier payload
                # can never be exported (anchor-or-omit).
                "outlier_result_hashes": sorted(
                    {_semantic_hash(results[i]) for i in part.outlier_indices}
                )
                or None,
            }
            return (
                outcome,
                [results[i] for i in part.agreeing_indices],
                [results[i] for i in part.outlier_indices],
                evidence,
            )
        return outcome, [], results, None

    outcome = hash_agreement_reducer(results)
    return (outcome, results, [], None) if outcome.agreed else (outcome, [], results, None)


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
    containment_resolver=None,  # Callable[[Result], bool] | None: result -> ran-under-STRICT
    attribution_resolver=None,  # Callable[[Result], bool] | None: result -> account opted-in @ issue
    manifest: dict | None = None,  # C7: resolved manifest_json — selects the reducer (None ⇒ hash)
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
    # Defense-in-depth (audit 2026-06-12): one voice per worker. The API path
    # already makes duplicates unreachable (assignments UNIQUE(unit_id,
    # worker_id) + result_already_submitted 409), but `agreeing_workers` is a
    # signed quorum claim — never let a duplicated row (direct DB write, future
    # regression) double-count a worker or mint it two receipts.
    seen_workers: set[str] = set()
    deduped: list[Result] = []
    for r in sorted(results, key=lambda r: (r.completed_at, r.result_id)):
        key = r.worker_pubkey_hex.lower()
        if key in seen_workers:
            logger.warning(
                "unit %s: duplicate result %s from worker %s ignored for quorum",
                work_unit.unit_id,
                r.result_id,
                key[:16],
            )
            continue
        seen_workers.add(key)
        deduped.append(r)
    results = deduped

    outcome, agreeing, outliers, tolerance_evidence = _reduce_unit(
        results, experiment=experiment, manifest=manifest
    )

    # Firewall #1 (A2): index every OUTLIER's honest work in the divergence
    # trust-index — evidentiary now, counted only once the equal-trust flip is
    # ON (D7 §11: divergence is NOT a Receipt object). For exact hash-agreement
    # the outliers are the whole set on disagreement; for within_cell_tolerance
    # they are the workers OUTSIDE the envelope — the unit can still AGREE on the
    # floor-many inside it (the C15 fix). Best-effort: never blocks completion.
    if outliers and receipt_index_repo is not None:
        for r in outliers:
            try:
                receipt_index_repo.record_divergence(
                    experiment_id=experiment.experiment_id,
                    worker_id=r.worker_id,
                    worker_pubkey=r.worker_pubkey_hex,
                    unit_id=work_unit.unit_id,
                    ran_under_strict=(
                        bool(containment_resolver(r)) if containment_resolver else False
                    ),
                )
            except Exception:
                logger.exception(
                    "divergence_index record failed for unit %s worker %s",
                    work_unit.unit_id,
                    r.worker_id,
                )

    if not outcome.agreed:
        logger.warning(
            "unit %s: no consensus under %s — no receipts issued "
            "(replication_factor=%d, results_seen=%d, agreeing=0)",
            work_unit.unit_id,
            outcome.method,
            work_unit.replication_target,
            len(results),
        )
        return ReceiptIssuanceOutcome(
            issued_receipt_ids=[], agreement=outcome, agreeing_result_ids=[]
        )

    # Consensus formed. Build hash anchors covering each AGREEING result (one per
    # worker). Anchors are identical content across all receipts in this batch.
    anchors = [
        ResultHashAnchor(
            rekor_log_index=0,  # placeholder until §5.16 Rekor integration
            rekor_entry_uuid="lab-mode-no-rekor",
            result_sha256=_result_hash(r),
        )
        for r in agreeing
    ]
    time_window_start = min(r.completed_at for r in agreeing)
    time_window_end = max(r.completed_at for r in agreeing)

    _rekor = rekor_client or NoOpRekorClient()

    issued: list[str] = []
    for result in agreeing:
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
                    unit_id=work_unit.unit_id,  # A4: per-account-per-unit trust
                    ran_under_strict=(  # A2: STRICT-containment gate for the flip
                        bool(containment_resolver(result)) if containment_resolver else False
                    ),
                    public_attribution_at_issue=(  # System B: opt-in snapshot at issue
                        bool(attribution_resolver(result)) if attribution_resolver else False
                    ),
                )
            except Exception:
                logger.exception(
                    "receipt_index insert failed for %s; per-job row is intact — "
                    "rebuild with `auspexai-coordinator receipts rebuild-index "
                    "--apply`. NB the index is a display cache only: attestation "
                    "and bundle membership derive from the per-job tables",
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

    return ReceiptIssuanceOutcome(
        issued_receipt_ids=issued,
        agreement=outcome,
        agreeing_result_ids=[r.result_id for r in agreeing],
        tolerance_evidence=tolerance_evidence,
    )
