"""Tests for M7c — receipt issuance trigger + hash_agreement reducer.

Covers the reducer in isolation and the issuance pipeline against
in-memory fixtures. Route-integration coverage lives in
`test_integration_full_flow.py`, which exercises the full
submit_result -> receipt issuance path via the HTTP flow and includes
the "receipts.issue.agreed" entry in its audit-trace assertion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from auspexai_platform.db import Database
from auspexai_platform.db.models import (
    Experiment,
    ExperimentStatus,
    Result,
    WorkUnit,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.receipts import (
    HASH_AGREEMENT_METHOD,
    ReceiptRepository,
    cose_sign1_decode,
    decode_cbor,
    hash_agreement_reducer,
    issue_receipts_for_completed_unit,
    load_or_generate_signing_key,
    unwrap_statement,
)


def _result(
    *,
    result_id: str = "res-1",
    unit_id: str = "u-1",
    worker_id: str = "wkr-a",
    worker_pubkey_hex: str | None = None,
    exit_code: int = 0,
    payload: dict[str, Any] | None = None,
    completed_at: datetime | None = None,
) -> Result:
    return Result(
        result_id=result_id,
        unit_id=unit_id,
        worker_id=worker_id,
        worker_pubkey_hex=worker_pubkey_hex or ("a" * 64),
        exit_code=exit_code,
        payload=payload or {"answer": 42},
        worker_signature="base64-sig-placeholder",
        completed_at=completed_at or datetime(2026, 5, 22, 10, 0, 0, tzinfo=UTC),
        received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
    )


def _work_unit(*, replication_target: int = 3) -> WorkUnit:
    return WorkUnit(
        unit_id="u-1",
        payload={"input": 1},
        status=WorkUnitStatus.COMPLETED,
        replication_target=replication_target,
        completions_so_far=replication_target,
        created_at=datetime(2026, 5, 22, 9, 0, 0, tzinfo=UTC),
    )


def _experiment() -> Experiment:
    return Experiment(
        experiment_id="exp-coord-001",
        tenant_id="tenant-a",
        tenant_experiment_label="doubler-v1",
        manifest_hash="b" * 64,
        status=ExperimentStatus.APPROVED,
        submitted_at=datetime(2026, 5, 22, 8, 0, 0, tzinfo=UTC),
        revision=1,
    )


# ---- hash_agreement reducer ----------------------------------------------


class TestHashAgreementReducer:
    def test_empty_results_disagree(self) -> None:
        out = hash_agreement_reducer([])
        assert out.agreed is False
        assert out.agreeing_workers == 0
        assert out.semantic_hash is None

    def test_all_same_payload_agree(self) -> None:
        results = [
            _result(result_id="r-1", worker_id="wkr-a", worker_pubkey_hex="a" * 64),
            _result(result_id="r-2", worker_id="wkr-b", worker_pubkey_hex="b" * 64),
            _result(result_id="r-3", worker_id="wkr-c", worker_pubkey_hex="c" * 64),
        ]
        out = hash_agreement_reducer(results)
        assert out.agreed is True
        assert out.method == HASH_AGREEMENT_METHOD
        assert out.agreeing_workers == 3
        assert out.semantic_hash is not None
        assert len(out.semantic_hash) == 64  # SHA-256 hex

    def test_payload_disagreement(self) -> None:
        results = [
            _result(result_id="r-1", payload={"answer": 42}),
            _result(result_id="r-2", payload={"answer": 43}),  # different
        ]
        out = hash_agreement_reducer(results)
        assert out.agreed is False
        assert out.agreeing_workers == 0

    def test_exit_code_disagreement(self) -> None:
        results = [
            _result(result_id="r-1", exit_code=0),
            _result(result_id="r-2", exit_code=1),  # different
        ]
        out = hash_agreement_reducer(results)
        assert out.agreed is False

    def test_different_worker_pubkeys_still_agree(self) -> None:
        """Workers' pubkeys differ but their semantic payloads agree —
        that's the whole point of replication."""
        results = [
            _result(worker_pubkey_hex="a" * 64),
            _result(worker_pubkey_hex="b" * 64),
        ]
        out = hash_agreement_reducer(results)
        assert out.agreed is True

    def test_different_completed_at_still_agree(self) -> None:
        """Workers complete at different times but agree on semantic payload."""
        results = [
            _result(completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC)),
            _result(completed_at=datetime(2026, 5, 22, 11, 0, tzinfo=UTC)),
        ]
        out = hash_agreement_reducer(results)
        assert out.agreed is True


# ---- issue_receipts_for_completed_unit ------------------------------------


@pytest.fixture
def per_job_db(tmp_path: Path) -> Database:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    return factory.get_or_create("exp-coord-001")


class TestIssueReceiptsForCompletedUnit:
    def test_agreement_issues_one_receipt_per_worker(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        wu = _work_unit(replication_target=3)
        results = [
            _result(result_id="r-1", worker_id="wkr-a", worker_pubkey_hex="a" * 64),
            _result(result_id="r-2", worker_id="wkr-b", worker_pubkey_hex="b" * 64),
            _result(result_id="r-3", worker_id="wkr-c", worker_pubkey_hex="c" * 64),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=wu,
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )

        assert outcome.agreement.agreed is True
        assert outcome.agreement.agreeing_workers == 3
        assert len(outcome.issued_receipt_ids) == 3
        for rid in outcome.issued_receipt_ids:
            assert rid.startswith("rcpt-")

        # Each receipt round-trips through COSE decode + CBOR decode + Pydantic.
        for record in receipt_repo.list_all():
            payload, kid = cose_sign1_decode(
                record.cose_signed_blob, expected_pubkey=signing_key.public_key
            )
            assert kid == signing_key.pubkey_hex
            receipt = decode_cbor(unwrap_statement(payload))
            assert receipt.tenant_id == "tenant-a"
            # experiment_id in receipt is tenant-side label, not coord-side id.
            assert receipt.experiment_id == "doubler-v1"
            assert receipt.work_unit_ids == ["u-1"]
            assert receipt.quorum_agreement.method == HASH_AGREEMENT_METHOD
            assert receipt.quorum_agreement.agreeing_workers == 3
            assert receipt.quorum_agreement.replication_factor == 3
            assert len(receipt.result_hash_anchors) == 3

    def test_disagreement_issues_no_receipts(self, tmp_path: Path, per_job_db: Database) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        wu = _work_unit(replication_target=3)
        # Distinct workers (the real replication shape; same-worker duplicate
        # rows are deduped to one voice — see TestSameWorkerDedup).
        results = [
            _result(result_id="r-1", worker_pubkey_hex="a" * 64, payload={"answer": 42}),
            _result(result_id="r-2", worker_pubkey_hex="b" * 64, payload={"answer": 43}),
            _result(result_id="r-3", worker_pubkey_hex="c" * 64, payload={"answer": 42}),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=wu,
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert outcome.agreement.agreed is False
        assert outcome.issued_receipt_ids == []
        assert receipt_repo.list_all() == []

    def test_worker_pubkey_in_receipt_matches_result(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        """Each receipt's worker_pubkey is the raw 32-byte form of that
        worker's pubkey_hex."""
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        results = [
            _result(result_id="r-1", worker_pubkey_hex="01" * 32),
            _result(result_id="r-2", worker_pubkey_hex="02" * 32),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=_work_unit(replication_target=2),
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert len(outcome.issued_receipt_ids) == 2

        records = receipt_repo.list_all()
        pubkeys_in_receipts = set()
        for record in records:
            receipt = decode_cbor(record.receipt_body_cbor)
            pubkeys_in_receipts.add(receipt.worker_pubkey.hex())
        assert pubkeys_in_receipts == {"01" * 32, "02" * 32}

    def test_result_hash_anchors_use_full_canonical_form(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        """Each anchor's result_sha256 is sha256(canonical-result-form) —
        meaning workers with different pubkeys or completed_at produce
        different anchors even when semantic payloads agree."""
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        results = [
            _result(
                result_id="r-1",
                worker_pubkey_hex="01" * 32,
                completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
            ),
            _result(
                result_id="r-2",
                worker_pubkey_hex="02" * 32,
                completed_at=datetime(2026, 5, 22, 11, 0, tzinfo=UTC),
            ),
        ]
        issue_receipts_for_completed_unit(
            work_unit=_work_unit(replication_target=2),
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )

        # Pick any receipt — anchors are the same content across all
        # receipts in one batch — and verify they cover both workers.
        record = receipt_repo.list_all()[0]
        receipt = decode_cbor(record.receipt_body_cbor)
        anchor_hashes = {a.result_sha256 for a in receipt.result_hash_anchors}
        assert len(anchor_hashes) == 2  # two distinct hashes (one per worker)

    def test_replication_factor_from_work_unit(self, tmp_path: Path, per_job_db: Database) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        outcome = issue_receipts_for_completed_unit(
            work_unit=_work_unit(replication_target=5),
            experiment=_experiment(),
            results=[
                _result(result_id="r-1", worker_pubkey_hex="a" * 64),
                _result(result_id="r-2", worker_pubkey_hex="b" * 64),
                _result(result_id="r-3", worker_pubkey_hex="c" * 64),
                _result(result_id="r-4", worker_pubkey_hex="d" * 64),
                _result(result_id="r-5", worker_pubkey_hex="e" * 64),
            ],
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert outcome.agreement.agreed is True
        for record in receipt_repo.list_all():
            receipt = decode_cbor(record.receipt_body_cbor)
            assert receipt.quorum_agreement.replication_factor == 5
            assert receipt.quorum_agreement.agreeing_workers == 5


class TestSameWorkerDedup:
    """Audit 2026-06-12 side-finding: `agreeing_workers` is a signed quorum
    claim — a duplicated same-worker result row (unreachable via the API:
    assignments UNIQUE(unit_id, worker_id) + result_already_submitted 409, but
    possible via direct DB write or a future regression) must count one voice
    and earn one receipt."""

    def test_duplicate_same_worker_results_count_once(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        wu = _work_unit(replication_target=2)
        results = [
            _result(result_id="r-1", worker_id="wkr-a", worker_pubkey_hex="a" * 64),
            _result(result_id="r-1-dup", worker_id="wkr-a", worker_pubkey_hex="a" * 64),
            _result(result_id="r-2", worker_id="wkr-b", worker_pubkey_hex="b" * 64),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=wu,
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert outcome.agreement.agreed is True
        assert outcome.agreement.agreeing_workers == 2  # not 3
        assert len(outcome.issued_receipt_ids) == 2  # one per WORKER, not per row

    def test_duplicate_disagreeing_row_from_same_worker_cannot_block_quorum(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        """The first (earliest-completed) row per worker is the worker's voice;
        a later divergent duplicate is ignored rather than poisoning agreement."""
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt_repo = ReceiptRepository(per_job_db)
        wu = _work_unit(replication_target=2)
        early = datetime(2026, 5, 22, 10, 0, tzinfo=UTC)
        late = datetime(2026, 5, 22, 11, 0, tzinfo=UTC)
        results = [
            _result(
                result_id="r-1",
                worker_id="wkr-a",
                worker_pubkey_hex="a" * 64,
                completed_at=early,
            ),
            _result(
                result_id="r-1-dup",
                worker_id="wkr-a",
                worker_pubkey_hex="a" * 64,
                payload={"answer": 999},
                completed_at=late,
            ),
            _result(result_id="r-2", worker_id="wkr-b", worker_pubkey_hex="b" * 64),
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=wu,
            experiment=_experiment(),
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert outcome.agreement.agreed is True
        assert outcome.agreement.agreeing_workers == 2
