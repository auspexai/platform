"""Derived worker status — the display-facing state of a worker.

A worker carries three independent stored signals (`retired_at`,
`quarantined_at`, `last_heartbeat_at`) plus its trust tier. The *derived*
status collapses those into a single label the worker itself and the worker's
own-account researcher can act on:

    retired > quarantined > offline (stale heartbeat) > active

Precedence is first-match-wins in that order — a quarantined worker that has
also gone stale reads as `quarantined` (the actionable maintainer state), and a
retired worker always reads `retired`.

"Active" = enrolled, not retired, not quarantined, and heartbeating within
`STALE_HEARTBEAT_MINUTES`. This is the same freshness window the operator
console uses for its online/offline badge, and it backs the network-size counts
(`WorkerRepository.count_active`) shown to researchers and workers.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from auspexai_platform.db.models import Worker, WorkerStatus

# Heartbeat freshness window. A worker whose last heartbeat is older than this
# (or which has never heartbeated) is "offline". 3 minutes mirrors the operator
# console's liveness badge.
STALE_HEARTBEAT_MINUTES = 3


def heartbeat_cutoff(now: datetime) -> datetime:
    """The earliest `last_heartbeat_at` that still counts as fresh, for `now`."""
    return now - timedelta(minutes=STALE_HEARTBEAT_MINUTES)


def is_heartbeat_fresh(worker: Worker, now: datetime) -> bool:
    return worker.last_heartbeat_at is not None and worker.last_heartbeat_at >= heartbeat_cutoff(
        now
    )


def derive_worker_status(worker: Worker, now: datetime) -> WorkerStatus:
    """Collapse a Worker's flags + heartbeat recency into a single status.

    `now` is passed in (not read here) so callers control the clock and the
    function stays pure/testable.
    """
    if worker.retired_at is not None:
        return WorkerStatus.RETIRED
    if worker.quarantined_at is not None:
        return WorkerStatus.QUARANTINED
    if not is_heartbeat_fresh(worker, now):
        return WorkerStatus.OFFLINE
    return WorkerStatus.ACTIVE
