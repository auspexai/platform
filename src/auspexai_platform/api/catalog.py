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
from auspexai_platform.supported_models import SUPPORTED_MODELS
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
    param_b: float
    quant: str
    approx_ram_gb: float
    served_worker_count: int  # active workers serving it right now (green dot)
    fits_worker_count: int  # active workers big enough to serve it (RAM known)
    ram_known_workers: int  # active workers that reported RAM (denominator honesty)
    status: str  # 'served' | 'runnable' | 'too_big' | 'unknown'


class SupportedResponse(BaseModel):
    models: list[SupportedEntry]
    total_active_workers: int
    fleet_can_auto_acquire: bool  # ≥1 active worker pulls models on demand


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

    @router.get(
        "/models/supported", response_model=SupportedResponse, status_code=status.HTTP_200_OK
    )
    async def get_supported(
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> SupportedResponse:
        """The TOP-DOWN catalog: every model the network SUPPORTS, whether or not
        it's loaded on a worker right now — so a researcher sees their full menu,
        with the live fleet overlaid. `status` per model:
          - `served`   — ≥1 active worker is serving it now (the green dot);
          - `runnable` — not served, but the fleet could run it (an auto-acquire
                         worker exists, and — where RAM is reported — ≥1 is big
                         enough);
          - `too_big`  — RAM is reported by ≥1 worker and NONE is big enough;
          - `unknown`  — not served and no worker reported RAM, so capacity can't
                         be judged (never rendered as 'can't run').
        RAM (`ram_total_gb`) is frequently null on real heartbeats, so it is
        strictly null-safe: a worker that doesn't report RAM is counted in
        neither `fits` nor `too_big`, only in the honest denominator."""
        if not (
            credential.is_researcher() or credential.is_account() or credential.is_maintainer()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="researcher, account, or maintainer credential required",
            )
        cutoff = heartbeat_cutoff(datetime.now(UTC))
        caps = worker_repository.active_capabilities(heartbeat_cutoff=cutoff)
        total_active = len(caps)
        auto_acquire_fleet = any(c.get("auto_acquire") is True for c in caps)

        # Per-model tallies over the active fleet.
        served: dict[str, int] = {}
        for c in caps:
            have = c.get("models")
            if isinstance(have, list):
                for mid in have:
                    if isinstance(mid, str):
                        served[mid] = served.get(mid, 0) + 1

        def _ram(c: dict) -> float | None:
            v = c.get("ram_total_gb")
            return float(v) if isinstance(v, (int, float)) else None

        ram_known = [r for c in caps if (r := _ram(c)) is not None]

        entries: list[SupportedEntry] = []
        for m in SUPPORTED_MODELS:
            served_n = served.get(m.model_id, 0)
            fits_n = sum(1 for r in ram_known if r >= m.approx_ram_gb)
            if served_n > 0:
                st = "served"
            elif ram_known and fits_n == 0:
                st = "too_big"  # someone reported RAM and nobody is big enough
            elif auto_acquire_fleet and (fits_n > 0 or not ram_known):
                st = "runnable"  # the fleet can pull it (RAM unknown ⇒ give benefit of doubt)
            else:
                st = "unknown"
            entries.append(
                SupportedEntry(
                    model_id=m.model_id,
                    display_name=m.display_name,
                    family=m.family,
                    param_b=m.param_b,
                    quant=m.quant,
                    approx_ram_gb=m.approx_ram_gb,
                    served_worker_count=served_n,
                    fits_worker_count=fits_n,
                    ram_known_workers=len(ram_known),
                    status=st,
                )
            )
        # Served first (most workers), then by ascending size — the natural menu.
        _rank = {"served": 0, "runnable": 1, "unknown": 2, "too_big": 3}
        entries.sort(key=lambda e: (_rank[e.status], -e.served_worker_count, e.param_b))
        return SupportedResponse(
            models=entries,
            total_active_workers=total_active,
            fleet_can_auto_acquire=auto_acquire_fleet,
        )

    return router
