"""C6a: an approved experiment with pending work that NO active worker can
satisfy (capability gap) surfaces on the needs-attention rail instead of
sitting silently pending."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from auspexai_platform.api.experiments import _capability_unsatisfiable_experiments
from auspexai_platform.db.models import ExperimentStatus, WorkerStatus, WorkUnitStatus


class _WU:
    def __init__(self, pending):
        self._pending = pending

    def list_all(self, status=None):
        if status == WorkUnitStatus.PENDING:
            return [SimpleNamespace(unit_id="u1")] if self._pending else []
        return []


class _Factory:
    def __init__(self, wu):
        self._wu = wu

    def get(self, _):
        return object()


class _ExpRepo:
    def __init__(self, exps):
        self._exps = exps

    def list_all(self, status=None):
        return [e for e in self._exps if e.status == status]


class _WorkerRepo:
    def __init__(self, workers):
        self._w = workers

    def list_all(self):
        return self._w


def _exp(req, requires_real=False):
    return SimpleNamespace(
        experiment_id="exp-cap",
        tenant_id="lab",
        status=ExperimentStatus.APPROVED,
        tenant_experiment_label="cap-run",
        required_capabilities=req,
        requires_real_execution=requires_real,
        required_containment="permissive",
    )


def _worker(models=None, features=None, policy="permissive", fresh=True):
    hb = datetime.now(UTC) - timedelta(minutes=1 if fresh else 999)
    caps = {"sandbox_policy": policy, "execute_tenant_code": "provisioned"}
    if models is not None:
        caps["models"] = models
    if features is not None:
        caps["worker_features"] = features
    return SimpleNamespace(last_heartbeat_at=hb, status=WorkerStatus.ACTIVE, capabilities=caps)


import auspexai_platform.api.experiments as mod  # noqa: E402


def _run(monkeypatch, exps, workers, wu_pending=True):
    monkeypatch.setattr(mod, "WorkUnitRepository", lambda pj: _WU(wu_pending))
    return _capability_unsatisfiable_experiments(
        _ExpRepo(exps), _Factory(_WU(wu_pending)), _WorkerRepo(workers), datetime.now(UTC)
    )


def test_model_no_worker_serves_is_flagged(monkeypatch):
    exp = _exp({"models": ["qwen-exotic-q4"]})
    # Only worker serves a different model, no auto_acquire.
    got = _run(monkeypatch, [exp], [_worker(models=["gemma-3-1b-it-q4"])])
    assert len(got) == 1
    assert "qwen-exotic-q4" in got[0][1]


def test_satisfiable_is_not_flagged(monkeypatch):
    exp = _exp({"models": ["gemma-3-1b-it-q4"]})
    got = _run(monkeypatch, [exp], [_worker(models=["gemma-3-1b-it-q4"])])
    assert got == []


def test_no_requirements_never_flagged(monkeypatch):
    got = _run(monkeypatch, [_exp({})], [_worker()])
    assert got == []


def test_no_pending_units_not_flagged(monkeypatch):
    exp = _exp({"models": ["nobody-serves"]})
    got = _run(monkeypatch, [exp], [_worker(models=["x"])], wu_pending=False)
    assert got == []
