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
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential
from auspexai_platform.db.repositories import WorkerRepository
from auspexai_platform.hf_catalog import catalog_fetched_at, read_catalog
from auspexai_platform.supported_models import supported_by_id
from auspexai_platform.worker_status import heartbeat_cutoff


class CatalogEntry(BaseModel):
    model_id: str
    worker_count: int


class CatalogResponse(BaseModel):
    models: list[CatalogEntry]
    total_active_workers: int


class SupportedEntry(BaseModel):
    model_id: str
    display_name: str
    family: str
    param_b: float | None  # None for fleet-present models outside the curated set
    quant: str
    approx_ram_gb: float | None  # None when the model isn't in the curated catalog
    on_worker_count: int  # active workers that have it available now (the green dot)
    fits_worker_count: int  # active workers big enough (curated + RAM known)
    ram_known_workers: int  # active workers that reported RAM (denominator honesty)
    status: str  # 'available' | 'runnable' | 'too_big' | 'unknown'
    in_catalog: bool  # True = in the provisionable set (has sizing metadata)
    hf_repo: str | None = None  # provenance when the entry came from the HF poll


class SupportedResponse(BaseModel):
    models: list[SupportedEntry]
    total_active_workers: int
    fleet_can_auto_acquire: bool  # ≥1 active worker pulls models on demand
    catalog_source: str  # 'hf' (fresh poll) | 'curated' (static seed fallback)
    catalog_fetched_at: str | None  # when the HF poll last refreshed the cache


def build_router(
    credential_dep,
    worker_repository: WorkerRepository,
    hf_catalog_path: Path | None = None,
) -> APIRouter:
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

    @router.get(
        "/models/supported", response_model=SupportedResponse, status_code=status.HTTP_200_OK
    )
    async def get_supported(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SupportedResponse:
        """The Requests-page catalog = the fleet's REAL inventory PLUS the curated
        provisionable set (union, deduped). Two honest layers:
          - `available` — present on ≥1 active worker RIGHT NOW
            (`capabilities["models"]`), so no pull needed (the green dot). This
            INCLUDES models a worker holds that aren't in the curated set — the
            page reflects what the fleet actually has, not just the vetted menu;
          - `runnable`  — in the curated set, not on any worker, and the fleet
            could pull it (an auto-acquire worker exists; where RAM is reported,
            ≥1 is big enough);
          - `too_big`   — in the curated set, not present, RAM reported by ≥1
            worker and none is big enough (needs a bigger worker);
          - `unknown`   — in the curated set, not present, no worker reported RAM.
        RAM is strictly null-safe (a worker not reporting RAM is in neither
        `fits` nor `too_big`). `served_models` is empty on real heartbeats, so
        `capabilities["models"]` = 'present/available' — that's what the green
        dot means."""
        if not (
            credential.is_researcher()
            or credential.is_account()
            or credential.is_maintainer()
            or credential.is_worker()  # workers consult the catalog to pick what to install
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="researcher, account, maintainer, or worker credential required",
            )
        cutoff = heartbeat_cutoff(datetime.now(UTC))
        caps = worker_repository.active_capabilities(heartbeat_cutoff=cutoff)
        total_active = len(caps)
        auto_acquire_fleet = any(c.get("auto_acquire") is True for c in caps)

        # What each active worker actually HAS (present/available inventory).
        present: dict[str, int] = {}
        for c in caps:
            have = c.get("models")
            if isinstance(have, list):
                for mid in have:
                    if isinstance(mid, str):
                        present[mid] = present.get(mid, 0) + 1

        def _ram(c: dict) -> float | None:
            v = c.get("ram_total_gb")
            return float(v) if isinstance(v, (int, float)) else None

        ram_known = [r for c in caps if (r := _ram(c)) is not None]

        # Provisionable set = the fresh HF poll if the cache is warm, else the
        # curated static seed (the timer never ran, or HF was unreachable).
        hf = read_catalog(hf_catalog_path) if hf_catalog_path else []
        if hf:
            catalog: dict = {m.model_id: m for m in hf}
            catalog_source, fetched_at = "hf", catalog_fetched_at(hf_catalog_path)
        else:
            catalog = supported_by_id()
            catalog_source, fetched_at = "curated", None
        # UNION: everything on the fleet + the whole provisionable set (deduped).
        entries: list[SupportedEntry] = []
        for mid in set(present) | set(catalog):
            m = catalog.get(mid)
            on_n = present.get(mid, 0)
            fits_n = sum(1 for r in ram_known if r >= m.approx_ram_gb) if m else 0
            if on_n > 0:
                st = "available"  # it's on a worker — reflect reality regardless of catalog
            elif m is None:
                st = "unknown"  # unreachable (a non-curated id only enters via `present`)
            elif ram_known and fits_n == 0:
                st = "too_big"
            elif auto_acquire_fleet and (fits_n > 0 or not ram_known):
                st = "runnable"  # RAM unknown ⇒ benefit of the doubt
            else:
                st = "unknown"
            entries.append(
                SupportedEntry(
                    model_id=mid,
                    display_name=m.display_name if m else mid,
                    family=m.family if m else "",
                    param_b=m.param_b if m else None,
                    quant=m.quant if m else "",
                    approx_ram_gb=m.approx_ram_gb if m else None,
                    on_worker_count=on_n,
                    fits_worker_count=fits_n,
                    ram_known_workers=len(ram_known),
                    status=st,
                    in_catalog=m is not None,
                    hf_repo=getattr(m, "hf_repo", None),
                )
            )
        # Available first (most workers), then the provisionable menu by size.
        _rank = {"available": 0, "runnable": 1, "unknown": 2, "too_big": 3}
        entries.sort(
            key=lambda e: (
                _rank[e.status],
                -e.on_worker_count,
                e.param_b if e.param_b is not None else 999.0,
                e.model_id,
            )
        )
        return SupportedResponse(
            models=entries,
            total_active_workers=total_active,
            fleet_can_auto_acquire=auto_acquire_fleet,
            catalog_source=catalog_source,
            catalog_fetched_at=fetched_at,
        )

    return router
