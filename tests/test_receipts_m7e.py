"""Tests for M7e — per-account receipt aggregation + control-DB receipt_index.

Covers the ReceiptIndexRepository in isolation, the M7c→index hook
(verifying receipts get indexed at issuance time), and the three
new GET endpoints (receipt-by-id anonymous-public, account-listing
self+maintainer, worker-listing self+maintainer).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import (
    Experiment,
    ExperimentStatus,
    Result,
    WorkUnit,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    ReceiptIndexRepository,
    WorkerRepository,
)
from auspexai_platform.db.repositories.receipt_index import DuplicateReceiptIndexError
from auspexai_platform.receipts import (
    ReceiptRepository,
    issue_receipts_for_completed_unit,
    load_or_generate_signing_key,
)

AUTHORITY = "testserver"


# ---- ReceiptIndexRepository in isolation ---------------------------------


class TestReceiptIndexRepository:
    def test_record_and_get(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-1", pubkey_hex="a" * 64)
        entry = receipt_index_repository.record(
            receipt_id="rcpt-aaa",
            experiment_id="exp-1",
            worker_id="wkr-1",
            worker_pubkey="a" * 64,
        )
        assert entry.receipt_id == "rcpt-aaa"
        assert entry.experiment_id == "exp-1"
        assert entry.worker_id == "wkr-1"
        assert entry.worker_pubkey == "a" * 64

        got = receipt_index_repository.get_by_id("rcpt-aaa")
        assert got == entry

    def test_get_missing_returns_none(
        self, receipt_index_repository: ReceiptIndexRepository
    ) -> None:
        assert receipt_index_repository.get_by_id("rcpt-nope") is None

    def test_duplicate_record_raises(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-dup", pubkey_hex="b" * 64)
        receipt_index_repository.record(
            receipt_id="rcpt-dup",
            experiment_id="exp-1",
            worker_id="wkr-dup",
            worker_pubkey="b" * 64,
        )
        import pytest

        with pytest.raises(DuplicateReceiptIndexError):
            receipt_index_repository.record(
                receipt_id="rcpt-dup",
                experiment_id="exp-2",
                worker_id="wkr-dup",
                worker_pubkey="b" * 64,
            )

    def test_list_for_worker(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-list-1", pubkey_hex="a" * 64)
        worker_repository.enroll(worker_id="wkr-list-2", pubkey_hex="b" * 64)
        for i in range(3):
            receipt_index_repository.record(
                receipt_id=f"rcpt-w1-{i}",
                experiment_id="exp-1",
                worker_id="wkr-list-1",
                worker_pubkey="a" * 64,
            )
        receipt_index_repository.record(
            receipt_id="rcpt-w2",
            experiment_id="exp-1",
            worker_id="wkr-list-2",
            worker_pubkey="b" * 64,
        )
        w1 = receipt_index_repository.list_for_worker("wkr-list-1")
        assert {e.receipt_id for e in w1} == {"rcpt-w1-0", "rcpt-w1-1", "rcpt-w1-2"}
        w2 = receipt_index_repository.list_for_worker("wkr-list-2")
        assert {e.receipt_id for e in w2} == {"rcpt-w2"}

    def test_list_for_pubkey(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-pubkey", pubkey_hex="a" * 64)
        receipt_index_repository.record(
            receipt_id="rcpt-A",
            experiment_id="exp-1",
            worker_id="wkr-pubkey",
            worker_pubkey="A" * 64,  # caller passes mixed case; repo normalizes
        )
        # Case-insensitive lookup.
        result = receipt_index_repository.list_for_pubkey("a" * 64)
        assert len(result) == 1
        assert result[0].receipt_id == "rcpt-A"
        assert result[0].worker_pubkey == "a" * 64

    def test_list_for_account_joins_workers(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
        account_repository: AccountRepository,
    ) -> None:
        from auspexai_platform.db.models import IdentityProvider

        # Create an account.
        account = account_repository.create(
            account_id="acct-alice",
            idp=IdentityProvider.GITHUB,
            idp_sub="gh-42",
        )

        # Enroll two workers, bind one to the account.
        worker_a = worker_repository.enroll(
            worker_id="wkr-bound",
            pubkey_hex="11" * 32,
        )
        from auspexai_platform.db.models import TrustTier

        worker_repository.bind_account(
            worker_a.worker_id,
            account_id=account.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )
        worker_b = worker_repository.enroll(
            worker_id="wkr-anon",
            pubkey_hex="22" * 32,
        )

        # Record receipts for both workers.
        receipt_index_repository.record(
            receipt_id="rcpt-bound-1",
            experiment_id="exp-1",
            worker_id=worker_a.worker_id,
            worker_pubkey=worker_a.pubkey_hex,
        )
        receipt_index_repository.record(
            receipt_id="rcpt-anon-1",
            experiment_id="exp-1",
            worker_id=worker_b.worker_id,
            worker_pubkey=worker_b.pubkey_hex,
        )

        # Account-scoped listing returns only the bound worker's receipts.
        results = receipt_index_repository.list_for_account(account.account_id)
        assert [e.receipt_id for e in results] == ["rcpt-bound-1"]


# ---- M7c hook writes to the index -----------------------------------------


class TestM7cIssuanceWritesIndex:
    def test_issuance_writes_index_rows(
        self,
        tmp_path: Path,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        # The receipt_index FK requires the worker rows to exist in the
        # control DB before indexing; enroll them first.
        for i in range(3):
            worker_repository.enroll(
                worker_id=f"wkr-{i}",
                pubkey_hex=f"{i:02x}" * 32,
            )
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        factory = PerJobDatabaseFactory(tmp_path / "jobs")
        per_job_db = factory.get_or_create("exp-issuance-test")
        receipt_repo = ReceiptRepository(per_job_db)

        experiment = Experiment(
            experiment_id="exp-issuance-test",
            tenant_id="tenant-a",
            tenant_experiment_label="doubler",
            manifest_hash="0" * 64,
            status=ExperimentStatus.APPROVED,
            submitted_at=datetime(2026, 5, 22, 8, 0, tzinfo=UTC),
            revision=1,
        )
        work_unit = WorkUnit(
            unit_id="u-1",
            payload={"input": 1},
            status=WorkUnitStatus.COMPLETED,
            replication_target=3,
            completions_so_far=3,
            created_at=datetime(2026, 5, 22, 9, 0, tzinfo=UTC),
        )
        results = [
            Result(
                result_id=f"r-{i}",
                unit_id="u-1",
                worker_id=f"wkr-{i}",
                worker_pubkey_hex=f"{i:02x}" * 32,
                exit_code=0,
                payload={"answer": 42},
                worker_signature="sig",
                completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
                received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
            )
            for i in range(3)
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=work_unit,
            experiment=experiment,
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
            receipt_index_repo=receipt_index_repository,
        )
        assert len(outcome.issued_receipt_ids) == 3

        # Every issued receipt is in the control-DB index.
        for receipt_id in outcome.issued_receipt_ids:
            entry = receipt_index_repository.get_by_id(receipt_id)
            assert entry is not None
            assert entry.experiment_id == "exp-issuance-test"
            assert entry.worker_id.startswith("wkr-")

    def test_issuance_without_index_repo_still_works(
        self,
        tmp_path: Path,
        worker_repository: WorkerRepository,
    ) -> None:
        # Even though there's no index, the issuance pipeline references
        # workers; enrolling avoids any other validation that grows in
        # later milestones.
        worker_repository.enroll(worker_id="wkr-1", pubkey_hex="11" * 32)
        """Backward-compat: if receipt_index_repo=None, issuance still
        succeeds (the index hook is best-effort)."""
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        factory = PerJobDatabaseFactory(tmp_path / "jobs")
        per_job_db = factory.get_or_create("exp-no-index")
        receipt_repo = ReceiptRepository(per_job_db)
        experiment = Experiment(
            experiment_id="exp-no-index",
            tenant_id="tenant-a",
            tenant_experiment_label="doubler",
            manifest_hash="0" * 64,
            status=ExperimentStatus.APPROVED,
            submitted_at=datetime(2026, 5, 22, 8, 0, tzinfo=UTC),
            revision=1,
        )
        work_unit = WorkUnit(
            unit_id="u-1",
            payload={"input": 1},
            status=WorkUnitStatus.COMPLETED,
            replication_target=1,
            completions_so_far=1,
            created_at=datetime(2026, 5, 22, 9, 0, tzinfo=UTC),
        )
        results = [
            Result(
                result_id="r-1",
                unit_id="u-1",
                worker_id="wkr-1",
                worker_pubkey_hex="11" * 32,
                exit_code=0,
                payload={"answer": 42},
                worker_signature="sig",
                completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
                received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
            ),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=work_unit,
            experiment=experiment,
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
            receipt_index_repo=None,
        )
        # Issuance succeeded even without the index repo.
        assert len(outcome.issued_receipt_ids) == 1


# ---- GET /receipts/{receipt_id} — anonymous-public ------------------------


def _seed_receipt_via_issuance(
    client: TestClient,
    experiment_id: str,
    worker_id: str,
    worker_pubkey_hex: str,
) -> str:
    """Helper: directly use the issuance pipeline to land a receipt the
    M7e endpoints can fetch. Returns the receipt_id."""
    signing_key = client.app.state.receipt_signing_key
    per_job_factory: PerJobDatabaseFactory = client.app.state.per_job_factory
    receipt_index_repo: ReceiptIndexRepository = client.app.state.receipt_index_repository
    per_job_db = per_job_factory.get_or_create(experiment_id)
    receipt_repo = ReceiptRepository(per_job_db)

    experiment = Experiment(
        experiment_id=experiment_id,
        tenant_id="tenant-test",
        tenant_experiment_label="label",
        manifest_hash="0" * 64,
        status=ExperimentStatus.APPROVED,
        submitted_at=datetime(2026, 5, 22, 8, 0, tzinfo=UTC),
        revision=1,
    )
    work_unit = WorkUnit(
        unit_id="u-1",
        payload={"input": 1},
        status=WorkUnitStatus.COMPLETED,
        replication_target=1,
        completions_so_far=1,
        created_at=datetime(2026, 5, 22, 9, 0, tzinfo=UTC),
    )
    results = [
        Result(
            result_id="r-1",
            unit_id="u-1",
            worker_id=worker_id,
            worker_pubkey_hex=worker_pubkey_hex,
            exit_code=0,
            payload={"answer": 42},
            worker_signature="sig",
            completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
            received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
        ),
    ]
    outcome = issue_receipts_for_completed_unit(
        work_unit=work_unit,
        experiment=experiment,
        results=results,
        receipt_repo=receipt_repo,
        signing_key=signing_key,
        receipt_index_repo=receipt_index_repo,
    )
    return outcome.issued_receipt_ids[0]


class TestGetReceiptById:
    def test_anonymous_can_fetch_existing_receipt(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        """No credentials, just GET /receipts/{id} — returns COSE bytes +
        decoded body."""
        worker = worker_repository.enroll(worker_id="wkr-1", pubkey_hex="aa" * 32)
        receipt_id = _seed_receipt_via_issuance(
            client, "exp-1", worker.worker_id, worker.pubkey_hex
        )

        response = client.get(f"/api/v0/receipts/{receipt_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["receipt_id"] == receipt_id
        assert body["experiment_id"] == "exp-1"
        # cose_signed_blob_b64 is non-empty base64.
        assert body["cose_signed_blob_b64"]
        decoded = base64.b64decode(body["cose_signed_blob_b64"])
        assert decoded  # at minimum non-empty
        # Decoded receipt body has the expected tenant.
        assert body["receipt"]["tenant_id"] == "tenant-test"
        assert body["receipt"]["experiment_id"] == "label"

    def test_missing_receipt_returns_404(self, client: TestClient) -> None:
        response = client.get("/api/v0/receipts/rcpt-does-not-exist")
        assert response.status_code == 404
        assert response.json()["detail"]["error"]["code"] == "receipt_not_found"


# ---- GET /accounts/{account_id}/receipts — account-self + maintainer ----


def _signed_get(
    client: TestClient,
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    path: str,
):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


class TestListAccountReceipts:
    def _setup_account_with_receipts(
        self,
        client: TestClient,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
    ):
        """Helper: enroll a worker, bind to an account, issue a receipt."""
        from auspexai_platform.db.models import IdentityProvider, TrustTier

        account = account_repository.create(
            account_id="acct-bob",
            idp=IdentityProvider.GITHUB,
            idp_sub="gh-99",
        )
        priv = Ed25519PrivateKey.generate()
        pubkey_hex = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-bob", pubkey_hex=pubkey_hex)
        worker_repository.bind_account(
            worker.worker_id,
            account_id=account.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )
        receipt_id = _seed_receipt_via_issuance(client, "exp-bob", worker.worker_id, pubkey_hex)
        return priv, pubkey_hex, account.account_id, worker.worker_id, receipt_id

    def test_account_self_can_list(
        self,
        client: TestClient,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        priv, pub, account_id, _worker_id, receipt_id = self._setup_account_with_receipts(
            client, account_repository, worker_repository
        )
        response = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/accounts/{account_id}/receipts",
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert [r["receipt_id"] for r in body["receipts"]] == [receipt_id]

    def test_maintainer_can_list_any_account(
        self,
        client: TestClient,
        maintainer_token: str,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        _priv, _pub, account_id, _worker_id, receipt_id = self._setup_account_with_receipts(
            client, account_repository, worker_repository
        )
        response = client.get(
            f"/api/v0/accounts/{account_id}/receipts",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        body = response.json()
        assert [r["receipt_id"] for r in body["receipts"]] == [receipt_id]

    def test_different_account_holder_forbidden(
        self,
        client: TestClient,
        account_repository: AccountRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        """A worker bound to account A cannot list account B's receipts."""
        from auspexai_platform.db.models import IdentityProvider, TrustTier

        # Account A + its worker, with a receipt.
        _priv_a, _pub_a, account_a_id, _wid_a, _rcpt = self._setup_account_with_receipts(
            client, account_repository, worker_repository
        )

        # Account B + its worker.
        account_b = account_repository.create(
            account_id="acct-carol",
            idp=IdentityProvider.GITHUB,
            idp_sub="gh-100",
        )
        priv_b = Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()
        worker_b = worker_repository.enroll(worker_id="wkr-carol", pubkey_hex=pub_b)
        worker_repository.bind_account(
            worker_b.worker_id,
            account_id=account_b.account_id,
            trust_tier=TrustTier.T1_VERIFIED,
        )

        # Carol tries to list Alice/Bob's account receipts.
        response = _signed_get(
            client,
            privkey=priv_b,
            pubkey_hex=pub_b,
            path=f"/api/v0/accounts/{account_a_id}/receipts",
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"]["code"] == "account_self_or_maintainer_required"

    def test_anonymous_forbidden(self, client: TestClient) -> None:
        # No credentials at all — anonymous can't list account receipts.
        response = client.get("/api/v0/accounts/some-account/receipts")
        # Anonymous credential class doesn't have account_id; gets 403.
        assert response.status_code in (401, 403)


# ---- GET /workers/{worker_id}/receipts — worker-self + maintainer -------


class TestListWorkerReceipts:
    def test_worker_self_can_list(
        self,
        client: TestClient,
        worker_repository: WorkerRepository,
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-self", pubkey_hex=pub)
        receipt_id = _seed_receipt_via_issuance(client, "exp-self", worker.worker_id, pub)

        response = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{worker.worker_id}/receipts",
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert [r["receipt_id"] for r in body["receipts"]] == [receipt_id]

    def test_maintainer_can_list_any_worker(
        self,
        client: TestClient,
        maintainer_token: str,
        worker_repository: WorkerRepository,
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-X", pubkey_hex=pub)
        receipt_id = _seed_receipt_via_issuance(client, "exp-X", worker.worker_id, pub)
        response = client.get(
            f"/api/v0/workers/{worker.worker_id}/receipts",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        body = response.json()
        assert [r["receipt_id"] for r in body["receipts"]] == [receipt_id]

    def test_different_worker_forbidden(
        self,
        client: TestClient,
        worker_repository: WorkerRepository,
    ) -> None:
        """Worker A cannot list worker B's receipts."""
        priv_a = Ed25519PrivateKey.generate()
        pub_a = priv_a.public_key().public_bytes_raw().hex()
        worker_repository.enroll(worker_id="wkr-A", pubkey_hex=pub_a)
        priv_b = Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()
        worker_b = worker_repository.enroll(worker_id="wkr-B", pubkey_hex=pub_b)

        response = _signed_get(
            client,
            privkey=priv_a,
            pubkey_hex=pub_a,
            path=f"/api/v0/workers/{worker_b.worker_id}/receipts",
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"]["code"] == "worker_self_or_maintainer_required"
