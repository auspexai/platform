"""Unit tests for derived worker status + the network-active count.

`derive_worker_status` collapses a Worker's stored flags + heartbeat recency
into one label with precedence retired > quarantined > offline > active.
`WorkerRepository.count_active` counts the network-wide 'active' set.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from auspexai_platform.db.models import TrustTier, Worker, WorkerStatus
from auspexai_platform.worker_status import (
    STALE_HEARTBEAT_MINUTES,
    derive_worker_status,
    heartbeat_cutoff,
)

NOW = datetime(2026, 5, 31, 12, 0, 0, tzinfo=UTC)
FRESH = NOW - timedelta(minutes=1)  # within the window
STALE = NOW - timedelta(minutes=STALE_HEARTBEAT_MINUTES + 1)  # outside it


def _worker(**kw) -> Worker:
    base = dict(
        worker_id="w",
        pubkey_hex="a" * 64,
        account_id=None,
        trust_tier=TrustTier.T1_AUTHENTICATED,
        registered_at=NOW - timedelta(days=1),
        last_heartbeat_at=FRESH,
        retired_at=None,
        quarantined_at=None,
        quarantine_reason=None,
    )
    base.update(kw)
    return Worker(**base)


def test_active_when_fresh_heartbeat_and_no_flags() -> None:
    assert derive_worker_status(_worker(last_heartbeat_at=FRESH), NOW) is WorkerStatus.ACTIVE


def test_offline_when_heartbeat_stale() -> None:
    assert derive_worker_status(_worker(last_heartbeat_at=STALE), NOW) is WorkerStatus.OFFLINE


def test_offline_when_never_heartbeated() -> None:
    assert derive_worker_status(_worker(last_heartbeat_at=None), NOW) is WorkerStatus.OFFLINE


def test_quarantined_beats_offline() -> None:
    # Quarantined + stale heartbeat → quarantined (the actionable state).
    w = _worker(last_heartbeat_at=STALE, quarantined_at=NOW - timedelta(hours=1))
    assert derive_worker_status(w, NOW) is WorkerStatus.QUARANTINED


def test_quarantined_beats_active() -> None:
    w = _worker(last_heartbeat_at=FRESH, quarantined_at=NOW - timedelta(hours=1))
    assert derive_worker_status(w, NOW) is WorkerStatus.QUARANTINED


def test_retired_beats_everything() -> None:
    w = _worker(
        last_heartbeat_at=FRESH,
        quarantined_at=NOW - timedelta(hours=1),
        retired_at=NOW - timedelta(hours=2),
    )
    assert derive_worker_status(w, NOW) is WorkerStatus.RETIRED


def test_heartbeat_cutoff_window() -> None:
    assert heartbeat_cutoff(NOW) == NOW - timedelta(minutes=STALE_HEARTBEAT_MINUTES)


# ---- count_active ----------------------------------------------------------


def test_count_active_only_counts_fresh_unflagged(worker_repository) -> None:
    # active: fresh heartbeat, no flags
    a = worker_repository.enroll(worker_id="w-active", pubkey_hex="1" * 64)
    worker_repository.record_heartbeat("w-active")
    # offline: enrolled, never heartbeated
    worker_repository.enroll(worker_id="w-offline", pubkey_hex="2" * 64)
    # quarantined: fresh heartbeat but quarantined
    worker_repository.enroll(worker_id="w-quar", pubkey_hex="3" * 64)
    worker_repository.record_heartbeat("w-quar")
    worker_repository.quarantine("w-quar", reason="testing")
    # retired
    worker_repository.enroll(worker_id="w-retired", pubkey_hex="4" * 64)
    worker_repository.record_heartbeat("w-retired")
    worker_repository.retire("w-retired")

    assert a.worker_id == "w-active"
    cutoff = heartbeat_cutoff(datetime.now(UTC))
    assert worker_repository.count_active(heartbeat_cutoff=cutoff) == 1


# ---- count_capable (#30 / M1) ----------------------------------------------


def test_count_capable_requires_all_models_and_active(worker_repository) -> None:
    cutoff = heartbeat_cutoff(datetime.now(UTC))
    # capable: fresh + holds m-x
    worker_repository.enroll(worker_id="w-has", pubkey_hex="1" * 64)
    worker_repository.record_heartbeat("w-has", capabilities={"models": ["m-x", "m-y"]})
    # active but lacks m-x
    worker_repository.enroll(worker_id="w-lacks", pubkey_hex="2" * 64)
    worker_repository.record_heartbeat("w-lacks", capabilities={"models": ["m-y"]})
    # holds m-x but quarantined → not active → excluded
    worker_repository.enroll(worker_id="w-quar", pubkey_hex="3" * 64)
    worker_repository.record_heartbeat("w-quar", capabilities={"models": ["m-x"]})
    worker_repository.quarantine("w-quar", reason="testing")

    assert worker_repository.count_capable(required_models=["m-x"], heartbeat_cutoff=cutoff) == 1
    # empty requirement ⇒ same as count_active (the two fresh, unflagged workers)
    assert worker_repository.count_capable(required_models=[], heartbeat_cutoff=cutoff) == 2
    assert worker_repository.count_active(heartbeat_cutoff=cutoff) == 2
