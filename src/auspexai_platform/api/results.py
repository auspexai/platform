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
from auspexai_platform.db.models import Result
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    ResultRepository,
    ResultTransferRepository,
)
from auspexai_platform.exposure import ExposureTag, filter_for_credential
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
        consensus = (
            ResultRepository(per_job_db).list_consensus(limit=MAX_PAGE_SIZE)
            if per_job_db is not None
            else []
        )
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
