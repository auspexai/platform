"""AssignmentRepository + ResultRepository tests — per-job assignments/results."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.assignments import (
    AssignmentAlreadyResolvedError,
    AssignmentRepository,
    DuplicateAssignmentError,
)
from auspexai_platform.db.repositories.results import (
    DuplicateResultError,
    ResultRepository,
)
from auspexai_platform.db.repositories.work_units import WorkUnitRepository


@pytest.fixture
def per_job_db(per_job_factory: PerJobDatabaseFactory):
    return per_job_factory.get_or_create("exp-assign")


@pytest.fixture
def work_units_repo(per_job_db) -> WorkUnitRepository:
    return WorkUnitRepository(per_job_db)


@pytest.fixture
def assignments_repo(per_job_db) -> AssignmentRepository:
    return AssignmentRepository(per_job_db)


@pytest.fixture
def results_repo(per_job_db) -> ResultRepository:
    return ResultRepository(per_job_db)


@pytest.fixture
def seeded_unit(work_units_repo: WorkUnitRepository):
    return work_units_repo.submit_batch([{"unit_id": "u1", "payload": {"input": 5}}])[0]


# ---- AssignmentRepository ------------------------------------------------


def test_create_returns_assignment(seeded_unit, assignments_repo: AssignmentRepository) -> None:
    assignment = assignments_repo.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="A" * 64,
    )
    assert assignment.unit_id == "u1"
    assert assignment.worker_id == "wkr-a"
    assert assignment.worker_pubkey_hex == "a" * 64
    assert assignment.result_id is None


def test_create_duplicate_unit_and_worker_raises(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    with pytest.raises(DuplicateAssignmentError):
        assignments_repo.create(
            assignment_id="asg-2",
            unit_id="u1",
            worker_id="wkr-a",
            worker_pubkey_hex="b" * 64,
        )


def test_active_worker_ids_excludes_refused_and_completed(
    work_units_repo: WorkUnitRepository,
    assignments_repo: AssignmentRepository,
    results_repo: ResultRepository,
) -> None:
    """D12 busy/idle: active_worker_ids = workers with an OFFERED, unresolved
    assignment — excludes refused offers and result-attached (completed) ones."""
    work_units_repo.submit_batch([{"unit_id": f"u{i}", "payload": {}} for i in range(1, 5)])
    assignments_repo.create(
        assignment_id="a-a", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    assignments_repo.create(
        assignment_id="a-b", unit_id="u2", worker_id="wkr-b", worker_pubkey_hex="b" * 64
    )
    # refused → not active
    assignments_repo.create(
        assignment_id="a-c", unit_id="u3", worker_id="wkr-c", worker_pubkey_hex="c" * 64
    )
    assignments_repo.mark_refused(assignment_id="a-c", kind="busy", reason="test")
    # result attached → not active
    assignments_repo.create(
        assignment_id="a-d", unit_id="u4", worker_id="wkr-d", worker_pubkey_hex="d" * 64
    )
    results_repo.insert(
        result_id="r-d",
        unit_id="u4",
        worker_id="wkr-d",
        worker_pubkey_hex="d" * 64,
        exit_code=0,
        payload={},
        worker_signature="s",
        completed_at=datetime(2026, 5, 30, tzinfo=UTC),
    )
    assignments_repo.attach_result("a-d", "r-d")

    assert assignments_repo.active_worker_ids() == {"wkr-a", "wkr-b"}


def test_two_workers_can_share_one_unit(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    a = assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    b = assignments_repo.create(
        assignment_id="asg-2", unit_id="u1", worker_id="wkr-b", worker_pubkey_hex="b" * 64
    )
    assert assignments_repo.count_for_unit("u1") == 2
    assert {a.worker_id, b.worker_id} == {"wkr-a", "wkr-b"}


def test_attach_result_sets_result_id(seeded_unit, assignments_repo: AssignmentRepository) -> None:
    assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    updated = assignments_repo.attach_result("asg-1", "res-x")
    assert updated.result_id == "res-x"


def test_already_assigned_reports_correctly(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    assert assignments_repo.already_assigned("u1", "wkr-a") is False
    assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    assert assignments_repo.already_assigned("u1", "wkr-a") is True


def test_create_starts_attempt_count_at_one(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    a = assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    assert a.attempt_count == 1


def test_reactivate_clears_refusal_and_bumps_attempt(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    """§2.1 #8 dispatch-retry: reactivate re-arms a refused assignment so the
    unit can be re-offered to the same worker, bumping the attempt counter and
    freeing the active-replication slot again."""
    assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    assignments_repo.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="boom")
    assert assignments_repo.count_active_for_unit("u1") == 0  # refused frees the slot

    updated = assignments_repo.reactivate("asg-1")
    assert updated.refused_at is None
    assert updated.refused_kind is None
    assert updated.refused_reason is None
    assert updated.attempt_count == 2
    assert assignments_repo.count_active_for_unit("u1") == 1  # active again


def test_reactivate_on_completed_assignment_raises(
    seeded_unit, assignments_repo: AssignmentRepository
) -> None:
    assignments_repo.create(
        assignment_id="asg-1", unit_id="u1", worker_id="wkr-a", worker_pubkey_hex="a" * 64
    )
    assignments_repo.attach_result("asg-1", "res-x")
    with pytest.raises(AssignmentAlreadyResolvedError):
        assignments_repo.reactivate("asg-1")


# ---- ResultRepository ---------------------------------------------------


def test_insert_returns_result(seeded_unit, results_repo: ResultRepository) -> None:
    result = results_repo.insert(
        result_id="res-1",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="A" * 64,
        exit_code=0,
        payload={"output": 10},
        worker_signature="sig=",
        completed_at=datetime.now(UTC),
    )
    assert result.exit_code == 0
    assert result.payload == {"output": 10}
    assert result.worker_pubkey_hex == "a" * 64


def test_insert_duplicate_result_id_raises(seeded_unit, results_repo: ResultRepository) -> None:
    results_repo.insert(
        result_id="res-1",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="a" * 64,
        exit_code=0,
        payload={},
        worker_signature="sig=",
        completed_at=datetime.now(UTC),
    )
    with pytest.raises(DuplicateResultError):
        results_repo.insert(
            result_id="res-1",
            unit_id="u1",
            worker_id="wkr-b",
            worker_pubkey_hex="b" * 64,
            exit_code=0,
            payload={},
            worker_signature="sig=",
            completed_at=datetime.now(UTC),
        )


def test_list_for_unit(seeded_unit, results_repo: ResultRepository) -> None:
    results_repo.insert(
        result_id="res-a",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="a" * 64,
        exit_code=0,
        payload={"x": 1},
        worker_signature="sig=",
        completed_at=datetime.now(UTC),
    )
    results_repo.insert(
        result_id="res-b",
        unit_id="u1",
        worker_id="wkr-b",
        worker_pubkey_hex="b" * 64,
        exit_code=0,
        payload={"x": 2},
        worker_signature="sig=",
        completed_at=datetime.now(UTC),
    )
    results = results_repo.list_for_unit("u1")
    assert [r.result_id for r in results] == ["res-a", "res-b"]


# ---- WorkUnitRepository transitions (M6d additions) -------------------


def test_mark_in_progress_transitions_pending(
    seeded_unit, work_units_repo: WorkUnitRepository
) -> None:
    work_units_repo.mark_in_progress("u1")
    fetched = work_units_repo.get_by_unit_id("u1")
    assert fetched is not None
    assert fetched.status.value == "in_progress"


def test_mark_in_progress_is_noop_on_completed(
    seeded_unit, work_units_repo: WorkUnitRepository
) -> None:
    # Bump completions past target to drive it to completed.
    for _ in range(3):
        work_units_repo.increment_completions("u1")
    work_units_repo.mark_in_progress("u1")  # should NOT regress
    fetched = work_units_repo.get_by_unit_id("u1")
    assert fetched is not None
    assert fetched.status.value == "completed"


def test_increment_completions_promotes_to_completed_at_target(
    seeded_unit, work_units_repo: WorkUnitRepository
) -> None:
    # Default replication_target = 3.
    work_units_repo.increment_completions("u1")  # 1
    assert work_units_repo.get_by_unit_id("u1").status.value == "pending"
    work_units_repo.increment_completions("u1")  # 2
    assert work_units_repo.get_by_unit_id("u1").status.value == "pending"
    work_units_repo.increment_completions("u1")  # 3 → completed
    fetched = work_units_repo.get_by_unit_id("u1")
    assert fetched.status.value == "completed"
    assert fetched.completions_so_far == 3
