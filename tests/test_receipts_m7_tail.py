"""Tests for M7-tail (coord side) — canonical-receipt fetch endpoint.

GET /api/v0/workers/{worker_id}/results/{result_id}/canonical-receipt
returns the COSE-Sign1 bytes for one of the worker's results. Worker-self
+ maintainer scope. Used by the worker's background fetch loop to
populate its local submitted_results.canonical_blob cache.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

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
    ReceiptIndexRepository,
    WorkerRepository,
)
from auspexai_platform.receipts import (
    ReceiptRepository,
    cose_sign1_decode,
    decode_cbor,
    issue_receipts_for_completed_unit,
    unwrap_statement,
)

AUTHORITY = "testserver"


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


def _seed_receipt(
    client: TestClient,
    *,
    worker_id: str,
    worker_pubkey_hex: str,
    result_id: str = "res-1",
    experiment_id: str = "exp-tail",
) -> str:
    """Drive M7c issuance to land a receipt the M7-tail endpoint can fetch.
    Returns the receipt_id."""
    signing_key = client.app.state.receipt_signing_key
    per_job_factory: PerJobDatabaseFactory = client.app.state.per_job_factory
    receipt_index_repo: ReceiptIndexRepository = client.app.state.receipt_index_repository
    per_job_db = per_job_factory.get_or_create(experiment_id)
    receipt_repo = ReceiptRepository(per_job_db)

    experiment = Experiment(
        experiment_id=experiment_id,
        tenant_id="tenant-test",
        tenant_experiment_label="tail-test",
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
            result_id=result_id,
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


# ---- ReceiptIndexRepository.get_for_worker_result ---------------------


class TestGetForWorkerResult:
    def test_records_with_result_id_are_findable(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-x", pubkey_hex="a" * 64)
        receipt_index_repository.record(
            receipt_id="rcpt-1",
            experiment_id="exp-1",
            worker_id="wkr-x",
            worker_pubkey="a" * 64,
            result_id="res-target",
        )
        entry = receipt_index_repository.get_for_worker_result(
            worker_id="wkr-x", result_id="res-target"
        )
        assert entry is not None
        assert entry.receipt_id == "rcpt-1"
        assert entry.result_id == "res-target"

    def test_records_without_result_id_not_findable_by_result(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-x", pubkey_hex="a" * 64)
        # Legacy row pattern: record without result_id (pre-M7-tail).
        receipt_index_repository.record(
            receipt_id="rcpt-legacy",
            experiment_id="exp-1",
            worker_id="wkr-x",
            worker_pubkey="a" * 64,
            # result_id omitted -> stored as NULL
        )
        entry = receipt_index_repository.get_for_worker_result(
            worker_id="wkr-x", result_id="res-anything"
        )
        # NULL result_id won't match any non-null result_id query.
        assert entry is None

    def test_unknown_worker_result_pair(
        self, receipt_index_repository: ReceiptIndexRepository
    ) -> None:
        assert (
            receipt_index_repository.get_for_worker_result(
                worker_id="wkr-nope", result_id="res-nope"
            )
            is None
        )


# ---- Canonical-receipt endpoint -----------------------------------------


class TestCanonicalReceiptEndpoint:
    def test_worker_self_can_fetch_own_canonical_receipt(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-self", pubkey_hex=pub)
        _seed_receipt(
            client,
            worker_id=worker.worker_id,
            worker_pubkey_hex=pub,
            result_id="res-A",
        )

        response = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/workers/{worker.worker_id}/results/res-A/canonical-receipt",
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["receipt_id"].startswith("rcpt-")
        assert body["experiment_id"] == "exp-tail"
        # COSE blob round-trips.
        cose_bytes = base64.b64decode(body["cose_signed_blob_b64"])
        signing_key = client.app.state.receipt_signing_key
        payload, kid = cose_sign1_decode(cose_bytes, expected_pubkey=signing_key.public_key)
        assert kid == signing_key.pubkey_hex
        receipt = decode_cbor(unwrap_statement(payload))
        assert receipt.tenant_id == "tenant-test"
        assert receipt.experiment_id == "tail-test"
        # Receipt body carried in response too (convenience).
        assert body["receipt"]["tenant_id"] == "tenant-test"

    def test_maintainer_can_fetch_any_worker_result(
        self,
        client: TestClient,
        maintainer_token: str,
        worker_repository: WorkerRepository,
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-x", pubkey_hex=pub)
        _seed_receipt(
            client,
            worker_id=worker.worker_id,
            worker_pubkey_hex=pub,
            result_id="res-M",
        )

        response = client.get(
            f"/api/v0/workers/{worker.worker_id}/results/res-M/canonical-receipt",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        assert response.json()["receipt_id"].startswith("rcpt-")

    def test_different_worker_forbidden(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        # Worker A enrolls and earns a receipt; worker B tries to fetch it.
        priv_a = Ed25519PrivateKey.generate()
        pub_a = priv_a.public_key().public_bytes_raw().hex()
        worker_a = worker_repository.enroll(worker_id="wkr-a", pubkey_hex=pub_a)
        _seed_receipt(
            client,
            worker_id=worker_a.worker_id,
            worker_pubkey_hex=pub_a,
            result_id="res-A",
        )

        priv_b = Ed25519PrivateKey.generate()
        pub_b = priv_b.public_key().public_bytes_raw().hex()
        worker_repository.enroll(worker_id="wkr-b", pubkey_hex=pub_b)

        response = _signed_get(
            client,
            privkey=priv_b,
            pubkey_hex=pub_b,
            path=f"/api/v0/workers/{worker_a.worker_id}/results/res-A/canonical-receipt",
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"]["code"] == "worker_self_or_maintainer_required"

    def test_unknown_result_returns_404(
        self,
        client: TestClient,
        maintainer_token: str,
        worker_repository: WorkerRepository,
    ) -> None:
        # Enroll a worker but never issue a receipt for the requested result.
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker_repository.enroll(worker_id="wkr-empty", pubkey_hex=pub)

        response = client.get(
            "/api/v0/workers/wkr-empty/results/res-nope/canonical-receipt",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error"]["code"] == "receipt_not_issued"

    def test_anonymous_forbidden(self, client: TestClient) -> None:
        response = client.get("/api/v0/workers/wkr-anon/results/res-anon/canonical-receipt")
        assert response.status_code in (401, 403)


# ---- Issuance writes result_id into the index ---------------------------


class TestIssuanceCarriesResultId:
    def test_result_id_recorded_on_issuance(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        """End-to-end: M7c issuance lands a receipt; the index row carries
        result_id so M7-tail's get_for_worker_result lookup works."""
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-trace", pubkey_hex=pub)
        receipt_id = _seed_receipt(
            client,
            worker_id=worker.worker_id,
            worker_pubkey_hex=pub,
            result_id="res-trace",
        )

        receipt_index_repository: ReceiptIndexRepository = client.app.state.receipt_index_repository
        entry = receipt_index_repository.get_for_worker_result(
            worker_id=worker.worker_id, result_id="res-trace"
        )
        assert entry is not None
        assert entry.receipt_id == receipt_id
        assert entry.result_id == "res-trace"
