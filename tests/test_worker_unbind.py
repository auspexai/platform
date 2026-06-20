"""Worker unbind (logout): drop the account binding, revert to T0-anonymous, keep the worker
running, and keep receipts permanently credited to the account (the account_id_at_issue
snapshot, 0041) — the inverse of the heavy `retire` purge.
"""

from __future__ import annotations

import pytest

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import AccountRepository, WorkerRepository
from auspexai_platform.db.repositories.receipt_index import ReceiptIndexRepository
from auspexai_platform.db.repositories.workers import WorkerNotFoundError


def test_unbind_reverts_to_t0_keeps_worker_and_preserves_receipt_attribution(db: Database) -> None:
    accounts = AccountRepository(db)
    workers = WorkerRepository(db)
    ri = ReceiptIndexRepository(db)

    acct = accounts.create(account_id="acct-a", idp=IdentityProvider.GITHUB, idp_sub="gh-1")
    w = workers.enroll(worker_id="wkr-x", pubkey_hex="11" * 32)
    workers.bind_account(
        w.worker_id, account_id=acct.account_id, trust_tier=TrustTier.T1_AUTHENTICATED
    )

    # A receipt earned WHILE bound snapshots the account onto account_id_at_issue.
    ri.record(
        receipt_id="r1",
        experiment_id="exp-1",
        worker_id=w.worker_id,
        worker_pubkey="11" * 32,
        unit_id="u1",
    )
    assert [e.receipt_id for e in ri.list_for_account(acct.account_id)] == ["r1"]

    # Logout: revert to T0-anonymous, but the worker stays alive (NOT retired/purged).
    after = workers.unbind(w.worker_id)
    assert after.account_id is None
    assert after.trust_tier is TrustTier.T0_ANONYMOUS
    assert after.retired_at is None

    # The receipt STAYS credited to the account — via the snapshot, not the now-NULL live link.
    assert [e.receipt_id for e in ri.list_for_account(acct.account_id)] == ["r1"]

    # A new receipt earned while anonymous is NOT credited to the old account.
    ri.record(
        receipt_id="r2",
        experiment_id="exp-1",
        worker_id=w.worker_id,
        worker_pubkey="11" * 32,
        unit_id="u2",
    )
    assert [e.receipt_id for e in ri.list_for_account(acct.account_id)] == ["r1"]

    # Idempotent on an already-anonymous worker.
    assert workers.unbind(w.worker_id).account_id is None


def test_unbind_of_unknown_worker_raises(db: Database) -> None:
    workers = WorkerRepository(db)
    with pytest.raises(WorkerNotFoundError):
        workers.unbind("wkr-nope")
