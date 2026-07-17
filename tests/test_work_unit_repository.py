"""WorkUnitRepository tests — submit batch + reads on a per-job DB."""

from __future__ import annotations

import pytest

from auspexai_platform.db.models import WorkUnitStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.work_units import (
    DuplicateWorkUnitError,
    WorkUnitRepository,
)


@pytest.fixture
def work_unit_repository(per_job_factory: PerJobDatabaseFactory) -> WorkUnitRepository:
    db = per_job_factory.get_or_create("exp-fixture")
    return WorkUnitRepository(db)


# ---- submit_batch ---------------------------------------------------------


def test_submit_batch_inserts_units(work_unit_repository: WorkUnitRepository) -> None:
    inserted = work_unit_repository.submit_batch(
        [
            {"unit_id": "u1", "payload": {"input": 1}},
            {"unit_id": "u2", "payload": {"input": 2}},
        ]
    )
    assert len(inserted) == 2
    assert {u.unit_id for u in inserted} == {"u1", "u2"}
    assert all(u.status is WorkUnitStatus.PENDING for u in inserted)
    assert all(u.completions_so_far == 0 for u in inserted)


def test_submit_batch_preserves_payload(work_unit_repository: WorkUnitRepository) -> None:
    work_unit_repository.submit_batch([{"unit_id": "u1", "payload": {"input": 42, "tag": "x"}}])
    fetched = work_unit_repository.get_by_unit_id("u1")
    assert fetched is not None
    assert fetched.payload == {"input": 42, "tag": "x"}


def test_submit_batch_empty_returns_empty(work_unit_repository: WorkUnitRepository) -> None:
    assert work_unit_repository.submit_batch([]) == []


# ---- has_status (scheduler existence check) -------------------------------


def test_has_status_existence_tracks_transitions(
    work_unit_repository: WorkUnitRepository,
) -> None:
    """The scheduler's per-poll reconcile leans on `has_status` instead of
    `list_all(status=...)`; it must answer existence exactly, without needing any
    rows materialized, across status transitions."""
    assert work_unit_repository.has_status(WorkUnitStatus.PENDING) is False
    work_unit_repository.submit_batch([{"unit_id": "u1", "payload": {}}])
    assert work_unit_repository.has_status(WorkUnitStatus.PENDING) is True
    assert work_unit_repository.has_status(WorkUnitStatus.IN_PROGRESS) is False
    # PENDING → IN_PROGRESS: pending existence flips off, in-progress flips on.
    work_unit_repository.mark_in_progress("u1")
    assert work_unit_repository.has_status(WorkUnitStatus.PENDING) is False
    assert work_unit_repository.has_status(WorkUnitStatus.IN_PROGRESS) is True
    # cancelled → neither active status remains (a run with no outstanding work).
    work_unit_repository.mark_cancelled("u1")
    assert work_unit_repository.has_status(WorkUnitStatus.PENDING) is False
    assert work_unit_repository.has_status(WorkUnitStatus.IN_PROGRESS) is False
    assert work_unit_repository.has_status(WorkUnitStatus.CANCELLED) is True


def test_submit_batch_duplicate_in_one_call_rolls_back(
    work_unit_repository: WorkUnitRepository,
) -> None:
    """If a batch contains a duplicate unit_id, the entire transaction rolls
    back — no partial inserts."""
    with pytest.raises(DuplicateWorkUnitError):
        work_unit_repository.submit_batch(
            [
                {"unit_id": "u1", "payload": {}},
                {"unit_id": "u1", "payload": {}},
            ]
        )
    assert work_unit_repository.list_all() == []


def test_submit_batch_collides_with_existing(
    work_unit_repository: WorkUnitRepository,
) -> None:
    work_unit_repository.submit_batch([{"unit_id": "u1", "payload": {}}])
    with pytest.raises(DuplicateWorkUnitError):
        work_unit_repository.submit_batch([{"unit_id": "u1", "payload": {"new": True}}])
    # Existing row unchanged.
    fetched = work_unit_repository.get_by_unit_id("u1")
    assert fetched is not None
    assert fetched.payload == {}


# ---- reads ----------------------------------------------------------------


def test_list_all_returns_all_units(work_unit_repository: WorkUnitRepository) -> None:
    work_unit_repository.submit_batch(
        [
            {"unit_id": "u1", "payload": {}},
            {"unit_id": "u2", "payload": {}},
        ]
    )
    units = work_unit_repository.list_all()
    assert [u.unit_id for u in units] == ["u1", "u2"]


def test_list_all_filtered_by_status(work_unit_repository: WorkUnitRepository) -> None:
    work_unit_repository.submit_batch(
        [{"unit_id": "u1", "payload": {}}, {"unit_id": "u2", "payload": {}}]
    )
    assert len(work_unit_repository.list_all(status=WorkUnitStatus.PENDING)) == 2
    assert len(work_unit_repository.list_all(status=WorkUnitStatus.COMPLETED)) == 0


def test_count_by_status(work_unit_repository: WorkUnitRepository) -> None:
    work_unit_repository.submit_batch(
        [{"unit_id": "u1", "payload": {}}, {"unit_id": "u2", "payload": {}}]
    )
    assert work_unit_repository.count_by_status() == {"pending": 2}


def test_get_unknown_returns_none(work_unit_repository: WorkUnitRepository) -> None:
    assert work_unit_repository.get_by_unit_id("nope") is None
