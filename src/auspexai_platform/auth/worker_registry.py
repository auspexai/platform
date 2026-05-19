"""Worker pubkey → worker_id lookup, used by the RFC 9421 signature verifier.

Mirrors `TenantRegistry`: a thin façade over `WorkerRepository` that exposes
just the surface the auth path needs (`get_worker_for_pubkey`). Keeping a
narrow façade keeps the auth seam small and lets the verifier hold a single
keyid resolver without depending on the wider repository surface.

The `WorkerBinding` shape is intentionally larger than `TenantBinding`
because the worker credential carries account_id + trust_tier (researcher
credentials only carry tenant_id).
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.models import TrustTier
from auspexai_platform.db.repositories.workers import WorkerRepository


@dataclass(frozen=True)
class WorkerBinding:
    """Auth-layer representation of an enrolled worker."""

    worker_id: str
    pubkey_hex: str  # lowercase, 64 hex chars
    account_id: str | None
    trust_tier: TrustTier


class WorkerRegistry:
    """DB-backed pubkey → worker lookup for the auth path."""

    def __init__(self, repository: WorkerRepository):
        self._repo = repository

    def get_worker_for_pubkey(self, pubkey_hex: str) -> WorkerBinding | None:
        worker = self._repo.get_by_pubkey(pubkey_hex)
        if worker is None or worker.retired_at is not None:
            return None
        return WorkerBinding(
            worker_id=worker.worker_id,
            pubkey_hex=worker.pubkey_hex,
            account_id=worker.account_id,
            trust_tier=worker.trust_tier,
        )
