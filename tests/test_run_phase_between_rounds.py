"""The 2026-07-04 campaign legibility fix: an all-settled, UNFINALIZED
experiment is 'running' between rounds (recent activity) or 'stalled' (driver
gone) — 'completing' is reserved for finalized runs. One derivation feeds the
My Experiments badges, the experiment page, and the console tiles."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from auspexai_platform.api.experiments import _experiment_phase
from auspexai_platform.db.models import ExperimentStatus


class _FakeUnits:
    def __init__(self, counts, latest):
        self._c, self._l = counts, latest

    def count_by_status(self):
        return self._c

    def latest_completion_at(self):
        return self._l


class _FakeFactory:
    def __init__(self, repo):
        self._r = repo

    def get(self, _):
        return object()  # non-None; the repo is monkeypatched below


def _exp(finalized):
    return SimpleNamespace(
        experiment_id="exp-x",
        status=ExperimentStatus.APPROVED,
        submitted_at=datetime.now(UTC) - timedelta(hours=5),
        submissions_finalized=finalized,
    )


def _phase(monkeypatch, *, finalized, latest):
    import auspexai_platform.api.experiments as mod

    repo = _FakeUnits({"completed": 30}, latest)
    monkeypatch.setattr(mod, "WorkUnitRepository", lambda pj: repo)
    return _experiment_phase(_exp(finalized), _FakeFactory(repo), datetime.now(UTC))


def test_settled_recent_is_running_between_rounds(monkeypatch):
    recent = (datetime.now(UTC) - timedelta(minutes=25)).isoformat()
    assert _phase(monkeypatch, finalized=False, latest=recent) == "running"


def test_settled_stale_is_stalled(monkeypatch):
    stale = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    assert _phase(monkeypatch, finalized=False, latest=stale) == "stalled"


def test_finalized_is_completing(monkeypatch):
    recent = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    assert _phase(monkeypatch, finalized=True, latest=recent) == "completing"
