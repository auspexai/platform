"""D22-B — terminal receipt outcomes (the teardown-race fix).

Covers the coordinator half of the fix:
- ReceiptIndexRepository.record_no_receipt / get_result_outcome (0057 sibling
  table — negative outcomes never touch receipt_index's trust queries).
- issue_receipts_for_completed_unit writes no_receipt markers for results that
  earn no receipt (disagreement) — and, crucially, writes NONE for
  observe-only/process_only units where every replica is a valid observation
  that earns its own receipt (firewall #1: non-consensus is a VALID state).
- The canonical-receipt endpoint returns 410 (terminal) for a marked result vs
  404 (transient) for an unmarked one.
- settle_terminal_experiment cancels open units + marks receiptless results.
"""

from __future__ import annotations

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
from auspexai_platform.db.repositories import ReceiptIndexRepository, WorkerRepository
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.receipts import ReceiptRepository, issue_receipts_for_completed_unit
from auspexai_platform.scheduler.teardown import settle_terminal_experiment

AUTHORITY = "testserver"


def _result(result_id: str, worker_id: str, pub: str, payload: dict, unit_id="u-1") -> Result:
    return Result(
        result_id=result_id,
        unit_id=unit_id,
        worker_id=worker_id,
        worker_pubkey_hex=pub,
        exit_code=0,
        payload=payload,
        worker_signature="sig",
        completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
        received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
    )


def _experiment(exp_id="exp-d22b", status=ExperimentStatus.APPROVED) -> Experiment:
    return Experiment(
        experiment_id=exp_id,
        tenant_id="tenant-test",
        tenant_experiment_label="d22b",
        manifest_hash="0" * 64,
        status=status,
        submitted_at=datetime(2026, 5, 22, 8, 0, tzinfo=UTC),
        revision=1,
    )


def _unit(unit_id="u-1", target=2) -> WorkUnit:
    return WorkUnit(
        unit_id=unit_id,
        payload={"input": 1},
        status=WorkUnitStatus.COMPLETED,
        replication_target=target,
        completions_so_far=target,
        created_at=datetime(2026, 5, 22, 9, 0, tzinfo=UTC),
    )


# ---- repository roundtrip ------------------------------------------------


class TestReceiptOutcomeRepository:
    def test_record_and_get(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-a", pubkey_hex="a" * 64)
        assert (
            receipt_index_repository.get_result_outcome(worker_id="wkr-a", result_id="res-1")
            is None
        )
        receipt_index_repository.record_no_receipt(
            worker_id="wkr-a",
            result_id="res-1",
            experiment_id="exp-1",
            unit_id="u-1",
            outcome="no_receipt",
            reason="non_consensus",
        )
        got = receipt_index_repository.get_result_outcome(worker_id="wkr-a", result_id="res-1")
        assert got is not None
        assert got.outcome == "no_receipt"
        assert got.reason == "non_consensus"

    def test_idempotent_first_reason_wins(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-a", pubkey_hex="a" * 64)
        receipt_index_repository.record_no_receipt(
            worker_id="wkr-a",
            result_id="res-1",
            experiment_id="e",
            unit_id="u",
            outcome="no_receipt",
            reason="diverged_from_consensus",
        )
        # A later abort-cascade write is a no-op (INSERT OR IGNORE).
        receipt_index_repository.record_no_receipt(
            worker_id="wkr-a",
            result_id="res-1",
            experiment_id="e",
            unit_id="u",
            outcome="experiment_terminal",
            reason="experiment_aborted",
        )
        got = receipt_index_repository.get_result_outcome(worker_id="wkr-a", result_id="res-1")
        assert got.reason == "diverged_from_consensus"


# ---- issuance-time markers ----------------------------------------------


class TestIssuanceMarkers:
    def test_disagreement_marks_all_results(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
        per_job_factory: PerJobDatabaseFactory,
    ) -> None:
        worker_repository.enroll(worker_id="wkr-1", pubkey_hex="1" * 64)
        worker_repository.enroll(worker_id="wkr-2", pubkey_hex="2" * 64)
        per_job_db = per_job_factory.get_or_create("exp-dis")
        # Two DIFFERENT payloads under exact-hash agreement → no consensus.
        results = [
            _result("res-1", "wkr-1", "1" * 64, {"answer": 1}),
            _result("res-2", "wkr-2", "2" * 64, {"answer": 2}),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=_unit(),
            experiment=_experiment("exp-dis"),
            results=results,
            receipt_repo=ReceiptRepository(per_job_db),
            signing_key=_signing_key(),
            receipt_index_repo=receipt_index_repository,
        )
        assert outcome.issued_receipt_ids == []  # no receipts on disagreement
        for rid, wid in (("res-1", "wkr-1"), ("res-2", "wkr-2")):
            got = receipt_index_repository.get_result_outcome(worker_id=wid, result_id=rid)
            assert got is not None and got.reason == "non_consensus"

    def test_process_only_marks_nothing(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
        per_job_factory: PerJobDatabaseFactory,
    ) -> None:
        """Firewall #1: observe-only replicas are each a VALID observation that
        earns its OWN receipt — none is ever marked receiptless."""
        worker_repository.enroll(worker_id="wkr-1", pubkey_hex="1" * 64)
        worker_repository.enroll(worker_id="wkr-2", pubkey_hex="2" * 64)
        per_job_db = per_job_factory.get_or_create("exp-obs")
        results = [
            _result("res-1", "wkr-1", "1" * 64, {"answer": 1}),
            _result("res-2", "wkr-2", "2" * 64, {"answer": 2}),  # differ — fine
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=_unit(),
            experiment=_experiment("exp-obs"),
            results=results,
            receipt_repo=ReceiptRepository(per_job_db),
            signing_key=_signing_key(),
            receipt_index_repo=receipt_index_repository,
            manifest={"reducer": {"kind": "builtin_process_only"}},
        )
        assert len(outcome.issued_receipt_ids) == 2  # each observation earns one
        for wid, rid in (("wkr-1", "res-1"), ("wkr-2", "res-2")):
            assert receipt_index_repository.get_result_outcome(worker_id=wid, result_id=rid) is None


# ---- endpoint: 410 terminal vs 404 transient ----------------------------


class TestEndpointTerminalVsTransient:
    def _signed_get(self, client, priv, pub, path):
        headers = sign_request(
            privkey=priv,
            pubkey_hex=pub,
            method="GET",
            path=path,
            authority=AUTHORITY,
            body=b"",
        )
        return client.get(path, headers=headers)

    def test_marked_result_returns_410(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-t", pubkey_hex=pub)
        client.app.state.receipt_index_repository.record_no_receipt(
            worker_id=worker.worker_id,
            result_id="res-div",
            experiment_id="e",
            unit_id="u",
            outcome="no_receipt",
            reason="diverged_from_consensus",
        )
        resp = self._signed_get(
            client,
            priv,
            pub,
            f"/api/v0/workers/{worker.worker_id}/results/res-div/canonical-receipt",
        )
        assert resp.status_code == 410, resp.text
        err = resp.json()["detail"]["error"]
        assert err["code"] == "receipt_will_not_issue"
        assert err["details"]["reason"] == "diverged_from_consensus"

    def test_unmarked_result_returns_404(
        self, client: TestClient, worker_repository: WorkerRepository
    ) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        worker = worker_repository.enroll(worker_id="wkr-t", pubkey_hex=pub)
        resp = self._signed_get(
            client,
            priv,
            pub,
            f"/api/v0/workers/{worker.worker_id}/results/res-pending/canonical-receipt",
        )
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"]["error"]["code"] == "receipt_not_issued"


# ---- abort cascade -------------------------------------------------------


class TestSettleTerminalExperiment:
    def test_cancels_open_units_and_marks_results(
        self,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
        per_job_factory: PerJobDatabaseFactory,
    ) -> None:
        # settle_terminal_experiment takes experiment_id/status directly and only
        # touches the per-job DB + receipt_index — no experiments-table row needed.
        exp_id = "exp-cascade"
        worker_repository.enroll(worker_id="wkr-1", pubkey_hex="1" * 64)

        per_job_db = per_job_factory.get_or_create(exp_id)
        wu_repo = WorkUnitRepository(per_job_db)
        wu_repo.submit_batch([{"unit_id": "u-open", "payload": {}}], replication_target=3)
        wu_repo.mark_in_progress("u-open")
        ResultRepository(per_job_db).insert(
            result_id="res-open",
            unit_id="u-open",
            worker_id="wkr-1",
            worker_pubkey_hex="1" * 64,
            exit_code=0,
            payload={"a": 1},
            worker_signature="s",
            completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
        )

        out = settle_terminal_experiment(
            experiment_id=exp_id,
            experiment_status=ExperimentStatus.ABORTED,
            per_job_factory=per_job_factory,
            receipt_index_repository=receipt_index_repository,
        )
        assert out.units_cancelled == 1
        assert out.results_marked == 1
        assert wu_repo.get_by_unit_id("u-open").status == WorkUnitStatus.CANCELLED
        marker = receipt_index_repository.get_result_outcome(
            worker_id="wkr-1", result_id="res-open"
        )
        assert marker is not None and marker.reason == "experiment_aborted"

        # Idempotent: a second settle is a no-op.
        out2 = settle_terminal_experiment(
            experiment_id=exp_id,
            experiment_status=ExperimentStatus.ABORTED,
            per_job_factory=per_job_factory,
            receipt_index_repository=receipt_index_repository,
        )
        assert out2.units_cancelled == 0 and out2.results_marked == 0


def _signing_key():
    from auspexai_platform.receipts import SigningKey

    return SigningKey._from_private(Ed25519PrivateKey.generate())
