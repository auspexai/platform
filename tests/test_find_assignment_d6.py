"""Regression tests for the D6 unit-id-collision finding (§9 #46, 2026-06-10).

Tenant-chosen unit_ids collide across experiments; the bare
(unit_id, worker_id) scan in `_find_assignment` once matched — and the
submission route then accepted a result into — an ABORTED experiment's stale
assignment. The fix: skip terminal experiments, and match an explicit
assignment_id (sent by workers ≥ v0.2.2) exactly.

Tested at the `_find_assignment` level: two per-job DBs with identical
(unit_id, worker_id) assignments and a fake experiment-status lookup.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from auspexai_platform.api.assignments import _find_assignment
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import AssignmentRepository, WorkUnitRepository

UNIT = "p-greeting-r0"  # tenant-chosen — identical across both experiments
WORKER = "wkr-test01"
PUBKEY = "a" * 64


@dataclass
class _Exp:
    status: str


class _FakeExperimentRepo:
    def __init__(self, statuses: dict[str, str]) -> None:
        self._statuses = statuses

    def get_by_id(self, experiment_id: str) -> _Exp | None:
        s = self._statuses.get(experiment_id)
        return _Exp(status=s) if s else None


def _factory_with_collision(tmp_path: Path) -> PerJobDatabaseFactory:
    """Two experiments, SAME (unit_id, worker_id), distinct assignment ids.
    exp-old is iterated first (matching the live incident's scan order)."""
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    for exp_id, asg_id in (("exp-old", "asg-old00001"), ("exp-new", "asg-new00001")):
        db = factory.get_or_create(exp_id)
        WorkUnitRepository(db).submit_batch([{"unit_id": UNIT, "payload": {}}])
        AssignmentRepository(db).create(
            assignment_id=asg_id, unit_id=UNIT, worker_id=WORKER, worker_pubkey_hex=PUBKEY
        )
    return factory


def test_terminal_experiments_are_skipped(tmp_path: Path) -> None:
    # The incident shape: the older colliding experiment was ABORTED — the
    # scan must fall through to the active one, not resurrect the stale row.
    factory = _factory_with_collision(tmp_path)
    repo = _FakeExperimentRepo({"exp-old": "aborted", "exp-new": "approved"})
    exp_id, _db, assignment = _find_assignment(factory, UNIT, WORKER, experiment_repository=repo)
    assert exp_id == "exp-new"
    assert assignment.assignment_id == "asg-new00001"


def test_assignment_id_hint_matches_exactly(tmp_path: Path) -> None:
    # Even with BOTH experiments active (ambiguous scan), the v0.2.2 worker's
    # explicit assignment_id resolves the right one.
    factory = _factory_with_collision(tmp_path)
    repo = _FakeExperimentRepo({"exp-old": "approved", "exp-new": "approved"})
    exp_id, _db, assignment = _find_assignment(
        factory,
        UNIT,
        WORKER,
        experiment_repository=repo,
        assignment_id="asg-new00001",
    )
    assert exp_id == "exp-new"
    assert assignment.assignment_id == "asg-new00001"


def test_only_terminal_match_resolves_to_none(tmp_path: Path) -> None:
    # If the ONLY matching assignment lives in an aborted experiment, the
    # route must 404 (assignment is gone with its experiment) — never accept.
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    db = factory.get_or_create("exp-old")
    WorkUnitRepository(db).submit_batch([{"unit_id": UNIT, "payload": {}}])
    AssignmentRepository(db).create(
        assignment_id="asg-old00001", unit_id=UNIT, worker_id=WORKER, worker_pubkey_hex=PUBKEY
    )
    repo = _FakeExperimentRepo({"exp-old": "aborted"})
    exp_id, _db, assignment = _find_assignment(factory, UNIT, WORKER, experiment_repository=repo)
    assert exp_id is None
    assert assignment is None


def test_no_hint_no_repo_preserves_legacy_behavior(tmp_path: Path) -> None:
    # Old call shape (no experiment repo, no hint) still resolves — pure
    # backward compatibility for any internal caller not yet threading context.
    factory = _factory_with_collision(tmp_path)
    exp_id, _db, assignment = _find_assignment(factory, UNIT, WORKER)
    assert exp_id == "exp-old"
    assert assignment.assignment_id == "asg-old00001"
