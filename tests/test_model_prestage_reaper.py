"""A11 model_prestage reaper — abandon stale 'requested' (stops the D22-B-shaped
perpetual re-poll) + reap dead-worker rows (orphans + unblock re-staging)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from auspexai_platform.db.repositories.model_prestage import (
    DuplicatePrestageError,
    ModelPrestageRepository,
)


def _mk(repo: ModelPrestageRepository, worker_id: str, model_id: str = "m1") -> None:
    repo.create(
        model_id=model_id,
        hf_repo=f"org/{model_id}",
        hf_filename=f"{model_id}.gguf",
        worker_id=worker_id,
        requested_by="conductor",
    )


def test_abandon_stale_requested(db, worker_repository) -> None:
    worker_repository.enroll(worker_id="wkr-1", pubkey_hex="11" * 32, capabilities={})
    repo = ModelPrestageRepository(db)
    _mk(repo, "wkr-1")
    now = datetime.now(UTC)
    # A fresh 'requested' row is NOT older than a past cutoff → untouched.
    assert repo.abandon_stale_requested(older_than=now - timedelta(days=1), apply=True) == 0
    assert repo.list_open_for_worker("wkr-1")  # still polled
    # It IS older than a future cutoff → dry-run counts, apply flips it.
    assert repo.abandon_stale_requested(older_than=now + timedelta(days=1), apply=False) == 1
    assert repo.list_open_for_worker("wkr-1")  # dry-run wrote nothing
    assert repo.abandon_stale_requested(older_than=now + timedelta(days=1), apply=True) == 1
    # Abandoned → no longer re-polled, and idempotent (not re-abandoned).
    assert repo.list_open_for_worker("wkr-1") == []
    assert repo.abandon_stale_requested(older_than=now + timedelta(days=1), apply=True) == 0


def test_reap_dead_worker_rows(db, worker_repository) -> None:
    worker_repository.enroll(worker_id="wkr-live", pubkey_hex="aa" * 32, capabilities={})
    worker_repository.enroll(worker_id="wkr-dead", pubkey_hex="bb" * 32, capabilities={})
    now = datetime.now(UTC)
    db.execute(
        "UPDATE workers SET last_heartbeat_at = ? WHERE worker_id = ?",
        (now.isoformat(), "wkr-live"),
    )
    db.execute(
        "UPDATE workers SET last_heartbeat_at = ? WHERE worker_id = ?",
        ((now - timedelta(days=60)).isoformat(), "wkr-dead"),
    )
    repo = ModelPrestageRepository(db)
    _mk(repo, "wkr-live")
    _mk(repo, "wkr-dead")
    cutoff = now - timedelta(days=30)
    # Dry-run: only the dead worker's row.
    assert repo.reap_dead_worker_rows(heartbeat_cutoff=cutoff, apply=False) == 1
    assert repo.reap_dead_worker_rows(heartbeat_cutoff=cutoff, apply=True) == 1
    # The live worker keeps its row; the dead worker's is gone.
    assert repo.has_open(model_id="m1", worker_id="wkr-live") is True
    assert repo.has_open(model_id="m1", worker_id="wkr-dead") is False
    # Re-staging the reaped pair is now UNBLOCKED (no DuplicatePrestageError).
    _mk(repo, "wkr-dead")
    assert repo.has_open(model_id="m1", worker_id="wkr-dead") is True


def test_acquired_row_blocks_recreate_until_reaped(db, worker_repository) -> None:
    # Documents the mechanism the reaper addresses: an 'acquired' row holds the
    # UNIQUE(model,worker) slot, so create() collides until the row is reaped.
    worker_repository.enroll(worker_id="wkr-x", pubkey_hex="cc" * 32, capabilities={})
    now = datetime.now(UTC)
    db.execute(
        "UPDATE workers SET last_heartbeat_at = ? WHERE worker_id = ?",
        ((now - timedelta(days=60)).isoformat(), "wkr-x"),
    )
    repo = ModelPrestageRepository(db)
    _mk(repo, "wkr-x")
    repo.mark_acquired(model_id="m1", worker_id="wkr-x")
    with pytest.raises(DuplicatePrestageError):
        _mk(repo, "wkr-x")
    # Reaping the dead-worker row clears the slot → re-stage succeeds.
    assert repo.reap_dead_worker_rows(heartbeat_cutoff=now - timedelta(days=30), apply=True) == 1
    _mk(repo, "wkr-x")
