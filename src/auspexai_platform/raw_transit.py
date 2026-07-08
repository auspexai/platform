"""Ephemeral raw-content transit buffer (D20, ratified 2026-07-06 Q1: live
collection — raw NEVER rests in AuspexAI infrastructure).

When an experiment DECLARES capture (`[capture] raw`), the executor emits a
`raw_response`; the coordinator pops it off the result BEFORE persistence
(features persist as today; raw is never written to disk) and parks it here —
a bounded, in-memory, TTL'd ring keyed by result_id. The researcher's driver
collects it DURING the run (workers online, buffer warm); an R3-gated,
audited read serves it; then it evicts. Post-hoc / post-restart it is simply
gone — that is the honest live-collection guarantee (§7 containment: untrusted
model text transits coordinator memory, never at-rest storage).

In-memory by design: restart loss is correct, not a bug. Bounded by count AND
age so a high-volume run can't grow it without limit.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass

MAX_ITEMS = 20_000  # ~a large run's in-flight window; evict oldest beyond this
TTL_SECONDS = 3600  # raw a driver hasn't collected within an hour is dropped


@dataclass(frozen=True)
class RawItem:
    """One buffered raw model output. AUD-26: `raw_signature` + `worker_pubkey` are
    the DETACHED worker signature over sha256(raw) bound to unit+worker — the
    coordinator verifies it at ingest, and the R3 driver can re-verify with them."""

    experiment_id: str
    raw_text: str
    raw_signature: str | None
    worker_pubkey: str | None
    stored_monotonic: float


class RawTransitBuffer:
    def __init__(self, *, max_items: int = MAX_ITEMS, ttl_seconds: int = TTL_SECONDS):
        self._max = max_items
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._store: OrderedDict[str, RawItem] = OrderedDict()

    def put(
        self,
        *,
        experiment_id: str,
        result_id: str,
        raw_text: str,
        now: float,
        raw_signature: str | None = None,
        worker_pubkey: str | None = None,
    ) -> None:
        with self._lock:
            self._evict(now)
            self._store[result_id] = RawItem(
                experiment_id=experiment_id,
                raw_text=raw_text,
                raw_signature=raw_signature,
                worker_pubkey=worker_pubkey,
                stored_monotonic=now,
            )
            self._store.move_to_end(result_id)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def get(self, *, experiment_id: str, result_id: str, now: float) -> str | None:
        with self._lock:
            self._evict(now)
            item = self._store.get(result_id)
            if item is None or item.experiment_id != experiment_id:
                return None
            return item.raw_text

    def collect_experiment(self, *, experiment_id: str, now: float) -> dict[str, str]:
        """All currently-buffered raw for one experiment (the driver's bulk
        collect). {result_id: raw_text}."""
        with self._lock:
            self._evict(now)
            return {
                rid: it.raw_text
                for rid, it in self._store.items()
                if it.experiment_id == experiment_id
            }

    def collect_experiment_signed(
        self, *, experiment_id: str, now: float
    ) -> dict[str, dict[str, str | None]]:
        """AUD-26: like `collect_experiment` but also returns each item's detached
        signature + worker pubkey so the driver can verify authenticity.
        {result_id: {"raw": text, "raw_signature": sig, "worker_pubkey": pub}}."""
        with self._lock:
            self._evict(now)
            return {
                rid: {
                    "raw": it.raw_text,
                    "raw_signature": it.raw_signature,
                    "worker_pubkey": it.worker_pubkey,
                }
                for rid, it in self._store.items()
                if it.experiment_id == experiment_id
            }

    def _evict(self, now: float) -> None:
        cutoff = now - self._ttl
        stale = [rid for rid, it in self._store.items() if it.stored_monotonic < cutoff]
        for rid in stale:
            del self._store[rid]
