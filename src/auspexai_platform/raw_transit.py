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

MAX_ITEMS = 20_000  # ~a large run's in-flight window; evict oldest beyond this
TTL_SECONDS = 3600  # raw a driver hasn't collected within an hour is dropped


class RawTransitBuffer:
    def __init__(self, *, max_items: int = MAX_ITEMS, ttl_seconds: int = TTL_SECONDS):
        self._max = max_items
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # result_id -> (experiment_id, raw_text, stored_monotonic)
        self._store: OrderedDict[str, tuple[str, str, float]] = OrderedDict()

    def put(self, *, experiment_id: str, result_id: str, raw_text: str, now: float) -> None:
        with self._lock:
            self._evict(now)
            self._store[result_id] = (experiment_id, raw_text, now)
            self._store.move_to_end(result_id)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def get(self, *, experiment_id: str, result_id: str, now: float) -> str | None:
        with self._lock:
            self._evict(now)
            item = self._store.get(result_id)
            if item is None or item[0] != experiment_id:
                return None
            return item[1]

    def collect_experiment(self, *, experiment_id: str, now: float) -> dict[str, str]:
        """All currently-buffered raw for one experiment (the driver's bulk
        collect). {result_id: raw_text}."""
        with self._lock:
            self._evict(now)
            return {rid: raw for rid, (exp, raw, _) in self._store.items() if exp == experiment_id}

    def _evict(self, now: float) -> None:
        cutoff = now - self._ttl
        stale = [rid for rid, (_, _, ts) in self._store.items() if ts < cutoff]
        for rid in stale:
            del self._store[rid]
