"""WorkerRepository tests — workers table + lifecycle methods."""

from __future__ import annotations

import pytest

from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AccountRepository, WorkerRepository
from auspexai_platform.db.repositories.workers import (
    DuplicateWorkerError,
    WorkerNotFoundError,
)

# ---- enroll ---------------------------------------------------------------


def test_enroll_returns_worker_with_t0_default(
    worker_repository: WorkerRepository,
) -> None:
    worker = worker_repository.enroll(
        worker_id="wkr-a",
        pubkey_hex="A" * 64,
        capabilities={"os": "linux", "ram_gb": 16},
    )
    assert worker.worker_id == "wkr-a"
    assert worker.pubkey_hex == "a" * 64  # normalized to lowercase
    assert worker.trust_tier is TrustTier.T0_ANONYMOUS
    assert worker.account_id is None
    assert worker.capabilities == {"os": "linux", "ram_gb": 16}
    assert worker.last_heartbeat_at is None
    assert worker.retired_at is None


def test_enroll_duplicate_pubkey_raises(worker_repository: WorkerRepository) -> None:
    worker_repository.enroll(worker_id="wkr-1", pubkey_hex="a" * 64)
    with pytest.raises(DuplicateWorkerError):
        worker_repository.enroll(worker_id="wkr-2", pubkey_hex="a" * 64)


def test_enroll_duplicate_worker_id_raises(worker_repository: WorkerRepository) -> None:
    worker_repository.enroll(worker_id="wkr-shared", pubkey_hex="a" * 64)
    with pytest.raises(DuplicateWorkerError):
        worker_repository.enroll(worker_id="wkr-shared", pubkey_hex="b" * 64)


# ---- lookups --------------------------------------------------------------


def test_get_by_pubkey_returns_match(worker_repository: WorkerRepository) -> None:
    enrolled = worker_repository.enroll(worker_id="wkr-x", pubkey_hex="C" * 64)
    found = worker_repository.get_by_pubkey("c" * 64)
    assert found is not None
    assert found.worker_id == enrolled.worker_id


def test_get_by_pubkey_returns_none_when_missing(
    worker_repository: WorkerRepository,
) -> None:
    assert worker_repository.get_by_pubkey("f" * 64) is None


# ---- bind_account ---------------------------------------------------------


def test_bind_account_promotes_to_t1(
    worker_repository: WorkerRepository,
    account_repository: AccountRepository,
) -> None:
    worker_repository.enroll(worker_id="wkr-up", pubkey_hex="a" * 64)
    account = account_repository.create(
        account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="1"
    )
    bound = worker_repository.bind_account(
        "wkr-up", account_id=account.account_id, trust_tier=TrustTier.T1_VERIFIED
    )
    assert bound.account_id == account.account_id
    assert bound.trust_tier is TrustTier.T1_VERIFIED


def test_bind_account_unknown_worker_raises(
    worker_repository: WorkerRepository,
    account_repository: AccountRepository,
) -> None:
    account = account_repository.create(
        account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="1"
    )
    with pytest.raises(WorkerNotFoundError):
        worker_repository.bind_account(
            "wkr-nope",
            account_id=account.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )


def test_bind_account_retired_worker_raises(
    worker_repository: WorkerRepository,
    account_repository: AccountRepository,
) -> None:
    worker_repository.enroll(worker_id="wkr-retire", pubkey_hex="a" * 64)
    worker_repository.retire("wkr-retire")
    account = account_repository.create(
        account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="1"
    )
    with pytest.raises(WorkerNotFoundError):
        worker_repository.bind_account(
            "wkr-retire",
            account_id=account.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )


# ---- record_heartbeat -----------------------------------------------------


def test_record_heartbeat_sets_timestamp(worker_repository: WorkerRepository) -> None:
    worker_repository.enroll(worker_id="wkr-hb", pubkey_hex="a" * 64)
    updated = worker_repository.record_heartbeat("wkr-hb")
    assert updated.last_heartbeat_at is not None


def test_record_heartbeat_updates_capabilities_when_supplied(
    worker_repository: WorkerRepository,
) -> None:
    worker_repository.enroll(
        worker_id="wkr-hb",
        pubkey_hex="a" * 64,
        capabilities={"os": "linux"},
    )
    updated = worker_repository.record_heartbeat(
        "wkr-hb",
        capabilities={"os": "linux", "ram_gb": 32, "gpus": ["rtx-3090"]},
    )
    assert updated.capabilities == {
        "os": "linux",
        "ram_gb": 32,
        "gpus": ["rtx-3090"],
    }


def test_record_heartbeat_unknown_raises(worker_repository: WorkerRepository) -> None:
    with pytest.raises(WorkerNotFoundError):
        worker_repository.record_heartbeat("wkr-nope")


# ---- retire ----------------------------------------------------------------


def test_retire_sets_retired_at(worker_repository: WorkerRepository) -> None:
    worker_repository.enroll(worker_id="wkr-r", pubkey_hex="a" * 64)
    retired = worker_repository.retire("wkr-r")
    assert retired.retired_at is not None


def test_retire_is_idempotent(worker_repository: WorkerRepository) -> None:
    worker_repository.enroll(worker_id="wkr-r", pubkey_hex="a" * 64)
    first = worker_repository.retire("wkr-r")
    second = worker_repository.retire("wkr-r")
    # retired_at preserved across re-retires (COALESCE).
    assert first.retired_at == second.retired_at


def test_retire_unknown_raises(worker_repository: WorkerRepository) -> None:
    with pytest.raises(WorkerNotFoundError):
        worker_repository.retire("wkr-nope")


# ---- list_for_account -----------------------------------------------------


def test_list_for_account(
    worker_repository: WorkerRepository,
    account_repository: AccountRepository,
) -> None:
    account = account_repository.create(
        account_id="acct-1", idp=IdentityProvider.GITHUB, idp_sub="1"
    )
    worker_repository.enroll(worker_id="wkr-a", pubkey_hex="a" * 64)
    worker_repository.enroll(worker_id="wkr-b", pubkey_hex="b" * 64)
    worker_repository.bind_account(
        "wkr-a", account_id=account.account_id, trust_tier=TrustTier.T1_VERIFIED
    )
    workers = worker_repository.list_for_account(account.account_id)
    assert [w.worker_id for w in workers] == ["wkr-a"]
