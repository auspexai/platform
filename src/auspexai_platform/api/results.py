"""Results delivery routes (M-Results, principles §9 #28).

Gives a researcher their **actual computed outputs** back — the gap left by the
receipts route (which proves *that* work ran, not *what* it produced). Mirrors
the receipts route precedent: tenant-scoped (own-tenant researcher or
maintainer), field-exposure-tagged, `response_model_exclude_none=True`.

Three routes:
  - GET .../results            — paginated; default = T-C consensus (one per unit),
                                 `?include=raw` adds T-X replicas. Sets delivered_at.
  - GET .../results/{id}       — single result.
  - GET .../results/export     — the offload bundle: consensus payloads + receipts +
                                 manifest + a signed proof-of-transfer (custody record).
                                 Stamps results_collected_at → arms collection-anchored
                                 age-off. On collection, custody/legal responsibility for
                                 the data passes to the researcher (Terms of Participation).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from base64 import b64encode
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import ExperimentStatus, Result
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AttestationRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    ResultRepository,
    ResultTransferRepository,
)
from auspexai_platform.db.repositories.attestations import (
    AttestationRecord,
    DuplicateAttestationError,
)
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.receipts.attestation import (
    RESULT_SET_ALGORITHM,
    ResultSetEntry,
    build_result_set_attestation,
    collect_result_set_entries,
)
from auspexai_platform.receipts.repository import ReceiptRepository
from auspexai_platform.receipts.signing import SigningKey

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500


class ResultItem(BaseModel):
    """One result in the delivery view. The science (`payload`, `semantic_hash`,
    `worker_signature`) is TENANT_SCOPED; worker identity is ACCOUNT_SCOPED
    (stripped for the researcher in Phase 1, visible to the maintainer)."""

    result_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    completed_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    receipt_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    is_consensus: Annotated[bool | None, ExposureTag.PUBLIC] = None
    aged_off: Annotated[bool | None, ExposureTag.PUBLIC] = None
    payload_aged_off_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    semantic_hash: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    payload: Annotated[dict[str, Any] | None, ExposureTag.TENANT_SCOPED] = None
    worker_signature: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    worker_id: Annotated[str | None, ExposureTag.ACCOUNT_SCOPED] = None
    worker_pubkey_hex: Annotated[str | None, ExposureTag.ACCOUNT_SCOPED] = None


class ResultListResponse(BaseModel):
    results: Annotated[list[ResultItem] | None, ExposureTag.PUBLIC] = None
    next_cursor: Annotated[str | None, ExposureTag.PUBLIC] = None


class AttestationUnit(BaseModel):
    unit_id: str
    consensus_result_hash: str
    receipt_id: str


class ResultSetAttestationResponse(BaseModel):
    """#34 §6.3 result-set completion attestation. The endpoint is already
    tenant-gated (own-tenant researcher or maintainer), and the attestation is
    designed to be *published* by the tenant, so the fields are PUBLIC within
    that gate. `cose_b64` is the canonical artifact; `units` lets a verifier
    recompute `merkle_root` without re-pulling (though re-pulling + recomputing
    is the stronger check)."""

    attestation_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    tenant_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    merkle_root: Annotated[str | None, ExposureTag.PUBLIC] = None
    algorithm: Annotated[str | None, ExposureTag.PUBLIC] = None
    unit_count: Annotated[int | None, ExposureTag.PUBLIC] = None
    units: Annotated[list[AttestationUnit] | None, ExposureTag.PUBLIC] = None
    cose_b64: Annotated[str | None, ExposureTag.PUBLIC] = None
    signing_key_pubkey_hex: Annotated[str | None, ExposureTag.PUBLIC] = None
    rekor_log_index: Annotated[int | None, ExposureTag.PUBLIC] = None
    rekor_entry_uuid: Annotated[str | None, ExposureTag.PUBLIC] = None
    # M9 leg 2: True when this is a checkpoint over a not-yet-COMPLETED experiment
    # (consensus-so-far). Always present so the tenant can branch on it; the same
    # flag lives in the COSE-signed predicate.
    partial: Annotated[bool | None, ExposureTag.PUBLIC] = None


def _require_researcher_own_tenant_or_maintainer(
    credential: Credential, experiment_tenant_id: str
) -> None:
    """403 unless the credential is a researcher scoped to the experiment's
    tenant, OR a maintainer (mirrors the receipts/lifecycle authz)."""
    if credential.kind == CredentialClass.MAINTAINER:
        return
    if (
        credential.is_researcher()
        and credential.tenant_id is not None
        and credential.tenant_id == experiment_tenant_id
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "researcher_own_tenant_or_maintainer_required",
                "message": (
                    "this endpoint requires a researcher credential scoped to "
                    "the experiment's tenant OR a maintainer credential"
                ),
            }
        },
    )


def _generate_attestation_id() -> str:
    return f"att-{secrets.token_urlsafe(9)}"


def _experiment_not_found(experiment_id: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": {
                "code": "experiment_not_found",
                "message": f"no experiment with id {experiment_id!r}",
            }
        },
    )


def _to_item(result: Result, receipt_id: str | None) -> ResultItem:
    aged = result.payload_aged_off_at is not None
    return ResultItem(
        result_id=result.result_id,
        unit_id=result.unit_id,
        completed_at=result.completed_at,
        receipt_id=receipt_id,
        is_consensus=result.is_consensus,
        aged_off=aged or None,  # omit when False (response_model_exclude_none)
        payload_aged_off_at=result.payload_aged_off_at,
        semantic_hash=result.semantic_hash,
        # Aged-off rows have no payload to return; the receipt + semantic_hash
        # still prove the unit ran. None → dropped by exclude_none.
        payload=None if aged else result.payload,
        worker_signature=result.worker_signature,
        worker_id=result.worker_id,
        worker_pubkey_hex=result.worker_pubkey_hex,
    )


def _result_set_root(consensus_results: list[Result]) -> str:
    """A deterministic root over the delivered consensus result hashes — the
    custody anchor. Sorted (unit_id, semantic_hash) → canonical JSON → sha256."""
    items = sorted((r.unit_id, r.semantic_hash or "") for r in consensus_results)
    return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()


def _drain_consensus(per_job_db) -> list[Result]:
    """EVERY consensus row, paged to exhaustion. The export bundle must never
    be built from one capped page: the proof-of-transfer signs the result-set
    root, and a root signed over a truncated set is a valid-looking custody
    proof of an incomplete dataset (D1, researcher_data_custody_and_analysis
    design §2). Reuses the list route's (completed_at, result_id) row-value
    cursor convention."""
    repo = ResultRepository(per_job_db)
    rows: list[Result] = []
    after_completed_at: str | None = None
    after_result_id: str | None = None
    while True:
        page = repo.list_consensus(
            limit=MAX_PAGE_SIZE,
            after_completed_at=after_completed_at,
            after_result_id=after_result_id,
        )
        rows.extend(page)
        if len(page) < MAX_PAGE_SIZE:
            return rows
        after_completed_at = page[-1].completed_at.isoformat()
        after_result_id = page[-1].result_id


def build_router(
    *,
    credential_dep,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository: ReceiptIndexRepository,
    manifest_repository: ManifestRepository,
    result_transfer_repository: ResultTransferRepository,
    signing_key: SigningKey,
    audit_repository,
    attestation_repository: AttestationRepository | None = None,
) -> APIRouter:
    router = APIRouter()

    def _load_experiment_authz(experiment_id: str, credential: Credential):
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        _require_researcher_own_tenant_or_maintainer(credential, experiment.tenant_id)
        return experiment

    def _receipt_map(experiment_id: str) -> dict[str, str]:
        """{result_id: receipt_id} for the experiment (links each result to its
        attestation)."""
        out: dict[str, str] = {}
        for entry in receipt_index_repository.list_for_experiment(experiment_id):
            if entry.result_id is not None:
                out[entry.result_id] = entry.receipt_id
        return out

    def _collect_attestation_units(experiment_id: str) -> list[AttestationUnit]:
        """Best-effort re-derive the per-unit list for the response convenience
        field when serving a PERSISTED attestation. The canonical artifact is the
        COSE blob (which already commits to these units); `units` just lets a
        verifier recompute the root without re-pulling. Empty if the per-job DB is
        gone — the cose_b64 still stands as the durable artifact."""
        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            return []
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=_receipt_map(experiment_id)
        )
        return [
            AttestationUnit(
                unit_id=e.unit_id,
                consensus_result_hash=e.consensus_result_hash,
                receipt_id=e.receipt_id,
            )
            for e in entries
        ]

    def _persisted_to_attestation_response(
        record: AttestationRecord, units: list[AttestationUnit]
    ) -> ResultSetAttestationResponse:
        """Map a persisted canonical attestation row → the API response. The
        response's `experiment_id` is the tenant-facing label (receipt
        convention), matching the on-demand build path."""
        return ResultSetAttestationResponse(
            attestation_id=record.attestation_id,
            experiment_id=record.tenant_experiment_label,
            tenant_id=record.tenant_id,
            merkle_root=record.merkle_root,
            algorithm=record.algorithm,
            unit_count=record.unit_count,
            units=units,
            cose_b64=b64encode(record.cose_signed_blob).decode(),
            signing_key_pubkey_hex=record.signing_key_pubkey_hex,
            rekor_log_index=record.rekor_log_index,
            rekor_entry_uuid=record.rekor_entry_uuid,
            partial=record.partial,
        )

    @router.get(
        "/experiments/{experiment_id}/results",
        response_model=ResultListResponse,
        response_model_exclude_none=True,
    )
    async def list_results(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
        include: str = Query("consensus", pattern="^(consensus|raw)$"),
        limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
        cursor: str | None = Query(None),
    ) -> ResultListResponse:
        """Default returns the T-C consensus payloads (one per completed unit);
        `?include=raw` adds the T-X replicas. Paginated by an opaque cursor over
        (completed_at, result_id). Fetching marks the rows delivered (the per-row
        delivery anchor; the export bundle is the experiment-level one)."""
        experiment = _load_experiment_authz(experiment_id, credential)
        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            return ResultListResponse(results=[])
        repo = ResultRepository(per_job_db)

        after_completed_at, after_result_id = (None, None)
        if cursor:
            after_completed_at, _, after_result_id = cursor.partition("|")
        kwargs = {
            "limit": limit,
            "after_completed_at": after_completed_at,
            "after_result_id": after_result_id,
        }
        rows = repo.list_consensus(**kwargs) if include == "consensus" else repo.list_all(**kwargs)

        repo.mark_delivered([r.result_id for r in rows])
        rmap = _receipt_map(experiment_id)
        items = [
            filter_for_credential(
                _to_item(r, rmap.get(r.result_id)),
                credential,
                resource_tenant_id=experiment.tenant_id,
            )
            for r in rows
        ]
        next_cursor = (
            f"{rows[-1].completed_at.isoformat()}|{rows[-1].result_id}"
            if len(rows) == limit
            else None
        )
        return ResultListResponse(results=items, next_cursor=next_cursor)

    @router.get(
        "/experiments/{experiment_id}/attestation",
        response_model=ResultSetAttestationResponse,
        response_model_exclude_none=True,
    )
    async def get_attestation(
        experiment_id: str,
        checkpoint: bool = False,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ResultSetAttestationResponse:
        """#34 §6.3 — the model-blind result-set attestation: a COSE-signed in-toto
        statement over the Merkle root of the experiment's per-unit consensus set,
        so a tenant-side reduce has a reproducible, tamper-evident input. The
        FINAL attestation is PERSISTED + canonical (A1, 2026-06-08): written once
        at completion (or lazily on first GET) to the control-DB `attestations`
        table, so it has a stable id/bytes/Rekor-anchor and survives per-job DB
        deletion. This route serves the persisted row for COMPLETED experiments;
        checkpoints (?checkpoint=true) are still rebuilt on demand (deterministic
        from the stored consensus hashes). The coordinator never reads a payload;
        it hashes/orders the per-unit consensus hashes it holds.

        Default: available only once the experiment is COMPLETED (the set is final).
        **M9 leg 2 — `?checkpoint=true`**: also returns an attestation over a
        not-yet-complete experiment's consensus-so-far set, marked `partial: true`
        (in the response AND the signed predicate). This is the integrity anchor
        for a partial collection when a pause/capacity-collapse stalls an experiment
        before 100% — the researcher's results are tamper-evident even mid-run, and
        the M8 `run_until` finalize-on-partial reduces over exactly this set."""
        experiment = _load_experiment_authz(experiment_id, credential)
        is_complete = experiment.status is ExperimentStatus.COMPLETED
        if not is_complete and not checkpoint:
            raise HTTPException(
                status_code=status.HTTP_425_TOO_EARLY,
                detail={
                    "error": {
                        "code": "experiment_not_completed",
                        "message": (
                            "result-set attestation is available only once the experiment "
                            "is COMPLETED (the set is final); pass ?checkpoint=true for a "
                            "partial consensus-so-far attestation"
                        ),
                        "details": {"status": experiment.status.value},
                    }
                },
            )
        # A checkpoint of an already-complete experiment is just the final
        # attestation (not partial) — `partial` reflects set-finality, not the
        # caller's flag.
        partial = not is_complete

        # A1: serve the PERSISTED canonical attestation for a COMPLETED
        # experiment. It is written once at completion (eager, from either
        # completion path) or lazily below on first GET — a stable
        # id/bytes/anchor, durable past per-job DB deletion. Checkpoints
        # (partial) are transient and always rebuilt on demand.
        if is_complete and attestation_repository is not None:
            persisted = attestation_repository.get_final(experiment_id)
            if persisted is not None:
                return _persisted_to_attestation_response(
                    persisted, _collect_attestation_units(experiment_id)
                )

        # Only units that reached consensus (have a semantic_hash) AND have an
        # issued receipt are attested — a disagreed unit produced neither and is
        # excluded. Pages through ALL consensus units (no silent cap).
        entries: list[ResultSetEntry] = []
        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is not None:
            entries = collect_result_set_entries(
                per_job_db, receipt_id_by_result=_receipt_map(experiment_id)
            )

        attestation = build_result_set_attestation(
            attestation_id=_generate_attestation_id(),
            tenant_experiment_label=experiment.tenant_experiment_label,
            tenant_id=experiment.tenant_id,
            entries=entries,
            signing_key=signing_key,
            rekor_client=None,
            partial=partial,
        )

        # A1 lazy canonicalize-on-read: persist a freshly-built FINAL attestation
        # so a COMPLETED experiment that wasn't persisted eagerly (e.g. completed
        # before this migration, or via a path without the deps) now has a durable
        # canonical record. Idempotent — a race with an emit path 409s on the
        # partial-unique index, and we serve the now-canonical row.
        if is_complete and attestation_repository is not None:
            try:
                attestation_repository.insert(
                    attestation_id=attestation.attestation_id,
                    experiment_id=experiment_id,
                    tenant_id=attestation.tenant_id,
                    tenant_experiment_label=attestation.experiment_id,
                    merkle_root=attestation.merkle_root,
                    algorithm=attestation.algorithm,
                    unit_count=attestation.unit_count,
                    cose_signed_blob=attestation.cose_signed_blob,
                    signing_key_pubkey_hex=attestation.signing_key_pubkey_hex,
                    rekor_log_index=attestation.rekor_log_index,
                    rekor_entry_uuid=attestation.rekor_entry_uuid,
                    partial=False,
                )
            except DuplicateAttestationError:
                persisted = attestation_repository.get_final(experiment_id)
                if persisted is not None:
                    return _persisted_to_attestation_response(
                        persisted,
                        [
                            AttestationUnit(
                                unit_id=e.unit_id,
                                consensus_result_hash=e.consensus_result_hash,
                                receipt_id=e.receipt_id,
                            )
                            for e in attestation.entries
                        ],
                    )
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            action="attestation.checkpoint" if partial else "attestation.issue",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "attestation_id": attestation.attestation_id,
                "merkle_root": attestation.merkle_root,
                "unit_count": attestation.unit_count,
                "algorithm": RESULT_SET_ALGORITHM,
                "partial": partial,
            },
        )
        return ResultSetAttestationResponse(
            attestation_id=attestation.attestation_id,
            experiment_id=attestation.experiment_id,
            tenant_id=attestation.tenant_id,
            merkle_root=attestation.merkle_root,
            algorithm=attestation.algorithm,
            unit_count=attestation.unit_count,
            units=[
                AttestationUnit(
                    unit_id=e.unit_id,
                    consensus_result_hash=e.consensus_result_hash,
                    receipt_id=e.receipt_id,
                )
                for e in attestation.entries
            ],
            cose_b64=b64encode(attestation.cose_signed_blob).decode(),
            signing_key_pubkey_hex=attestation.signing_key_pubkey_hex,
            rekor_log_index=attestation.rekor_log_index,
            rekor_entry_uuid=attestation.rekor_entry_uuid,
            partial=attestation.partial,
        )

    @router.get(
        "/experiments/{experiment_id}/results/export",
        response_model_exclude_none=True,
    )
    async def export_results(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> dict[str, Any]:
        """The offload bundle: all consensus payloads + their COSE receipts + the
        signed manifest + a **signed proof-of-transfer**. Records a permanent
        custody row and stamps `results_collected_at` (arming collection-anchored
        age-off). The bundle is self-contained and offline-verifiable."""
        experiment = _load_experiment_authz(experiment_id, credential)
        per_job_db = per_job_factory.get(experiment_id)
        consensus = _drain_consensus(per_job_db) if per_job_db is not None else []
        rmap = _receipt_map(experiment_id)
        receipt_repo = ReceiptRepository(per_job_db) if per_job_db is not None else None

        results_out: list[dict[str, Any]] = []
        receipts_out: list[dict[str, Any]] = []
        seen_receipts: set[str] = set()
        for r in consensus:
            rid = rmap.get(r.result_id)
            results_out.append(
                {
                    "result_id": r.result_id,
                    "unit_id": r.unit_id,
                    "semantic_hash": r.semantic_hash,
                    "payload": None if r.payload_aged_off_at else r.payload,
                    "aged_off": r.payload_aged_off_at is not None,
                    "worker_signature": r.worker_signature,
                    "receipt_id": rid,
                    "completed_at": r.completed_at.isoformat(),
                }
            )
            if rid and receipt_repo is not None and rid not in seen_receipts:
                rec = receipt_repo.get_by_id(rid)
                if rec is not None:
                    receipts_out.append(
                        {"receipt_id": rid, "cose_b64": b64encode(rec.cose_signed_blob).decode()}
                    )
                    seen_receipts.add(rid)

        manifest = manifest_repository.get(experiment.manifest_hash)
        collected_at = datetime.now(UTC)
        collected_by = credential.pubkey_hex or f"<{credential.kind.value}>"
        root = _result_set_root(consensus)
        record_bytes = (
            f"{root}|{collected_by}|{collected_at.isoformat()}|{experiment.manifest_hash}".encode()
        )
        signature = signing_key.private_key.sign(record_bytes).hex()
        transfer = result_transfer_repository.record(
            transfer_id=f"xfer-{secrets.token_urlsafe(12)}",
            experiment_id=experiment_id,
            tenant_id=experiment.tenant_id,
            collected_by_pubkey=collected_by,
            collected_at=collected_at,
            manifest_hash=experiment.manifest_hash,
            result_set_root=root,
            receipt_count=len(receipts_out),
            coordinator_signature=signature,
        )
        experiment_repository.mark_results_collected(experiment_id)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="results.transferred",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"transfer_id": transfer.transfer_id, "result_set_root": root},
        )
        return {
            "experiment_id": experiment_id,
            "manifest_hash": experiment.manifest_hash,
            "manifest": manifest.manifest_json if manifest is not None else None,
            "consensus_results": results_out,
            "receipts": receipts_out,
            "transfer": {
                "transfer_id": transfer.transfer_id,
                "result_set_root": root,
                "collected_at": collected_at.isoformat(),
                "collected_by_pubkey": collected_by,
                "manifest_hash": experiment.manifest_hash,
                "receipt_count": len(receipts_out),
                "coordinator_signature": signature,
                "coordinator_pubkey_hex": signing_key.pubkey_hex,
            },
        }

    @router.get(
        "/experiments/{experiment_id}/results/{result_id}",
        response_model=ResultItem,
        response_model_exclude_none=True,
    )
    async def get_result(
        experiment_id: str,
        result_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ResultItem:
        experiment = _load_experiment_authz(experiment_id, credential)
        per_job_db = per_job_factory.get(experiment_id)
        result = ResultRepository(per_job_db).get_by_id(result_id) if per_job_db else None
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": {"code": "result_not_found", "message": "no such result"}},
            )
        ResultRepository(per_job_db).mark_delivered([result_id])
        rmap = _receipt_map(experiment_id)
        return filter_for_credential(
            _to_item(result, rmap.get(result_id)),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    return router
