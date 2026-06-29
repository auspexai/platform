"""Model catalog — the network's bottom-up servable-model set (read-only).

`GET /api/v0/models/catalog` — a live aggregate over active workers'
`capabilities["models"]` (no curated table): `{models: [{model_id,
worker_count}], total_active_workers}`. `model_id` is the worker store id
(`<repo-slug>-<quant>`), the same exact-match space the M1 scheduler routes on,
so "available" reflects what the network can actually run right now.

RESTORED after AUD-18 (commit 1375456) deleted it as collateral: that change
retired the dormant model/software-REQUEST *queues* (now GitHub Discussions),
but the whole `model_requests.py` module went with them — taking this catalog
route, which is NOT a request queue. It's an authenticated, read-only aggregate
with live consumers (the SDK `model catalog` command + the R-D Requests page's
"Available on the network now"), so it carries none of the dormant-producer
attack surface the security review targeted. The request queues stay retired.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential
from auspexai_platform.db.repositories import WorkerRepository
from auspexai_platform.worker_status import heartbeat_cutoff


class CatalogEntry(BaseModel):
    model_id: str
    worker_count: int


class CatalogResponse(BaseModel):
    models: list[CatalogEntry]
    total_active_workers: int


def build_router(credential_dep, worker_repository: WorkerRepository) -> APIRouter:
    router = APIRouter()

    @router.get("/models/catalog", response_model=CatalogResponse, status_code=status.HTTP_200_OK)
    async def get_catalog(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> CatalogResponse:
        # Authenticated consumers (researchers / connected accounts) + maintainers;
        # not anonymous. (A connected account is the Tier-1 researcher case.)
        if not (
            credential.is_researcher() or credential.is_account() or credential.is_maintainer()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="researcher, account, or maintainer credential required",
            )
        cutoff = heartbeat_cutoff(datetime.now(UTC))
        counts = worker_repository.model_inventory_counts(heartbeat_cutoff=cutoff)
        models = [
            CatalogEntry(model_id=m, worker_count=c)
            for m, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
        return CatalogResponse(
            models=models,
            total_active_workers=worker_repository.count_active(heartbeat_cutoff=cutoff),
        )

    return router
