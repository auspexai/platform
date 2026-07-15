"""Layer 2b: an approved experiment the fleet keeps REFUSING at serve time (e.g. an
Ollama too old for the model) surfaces on the needs-attention rail. Distinct from C6a
(nobody MATCHES the capability) — here workers match but refuse serving, which C6a
cannot see, so the run would silently spin then sit stuck-pending."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import auspexai_platform.api.experiments as mod
from auspexai_platform.api.experiments import _serve_refused_experiments
from auspexai_platform.db.models import ExperimentStatus, WorkUnitStatus


class _WU:
    def __init__(self, pending: bool):
        self._pending = pending

    def list_all(self, status=None):
        if status == WorkUnitStatus.PENDING:
            return [SimpleNamespace(unit_id="u1")] if self._pending else []
        return []


class _Assign:
    def __init__(self, summary):
        self._summary = summary

    def refusal_progress_summary(self):
        return self._summary


class _ExpRepo:
    def __init__(self, exps):
        self._exps = exps

    def list_all(self, status=None):
        return [e for e in self._exps if e.status == status]


class _Factory:
    def get(self, _):
        return object()


def _exp():
    return SimpleNamespace(
        experiment_id="exp-serve",
        tenant_id="lab",
        status=ExperimentStatus.APPROVED,
        tenant_experiment_label="serve-run",
    )


def _run(monkeypatch, *, pending: bool, summary: tuple[int, int, int, str | None]):
    monkeypatch.setattr(mod, "WorkUnitRepository", lambda pj: _WU(pending))
    monkeypatch.setattr(mod, "AssignmentRepository", lambda pj: _Assign(summary))
    return _serve_refused_experiments(_ExpRepo([_exp()]), _Factory(), datetime.now(UTC))


def test_persistent_refusals_zero_completed_is_flagged(monkeypatch):
    # 21 refusals across 2 workers, nothing completed — the phi/qwen3 case.
    got = _run(monkeypatch, pending=True, summary=(21, 2, 0, "Ollama too old — update it"))
    assert len(got) == 1
    exp, refused, reason = got[0]
    assert exp.experiment_id == "exp-serve"
    assert refused == 21
    assert "Ollama too old" in reason


def test_progressing_run_is_not_flagged(monkeypatch):
    # Some refusals but units ARE completing → healthy, not a fleet-can't-serve alarm.
    got = _run(monkeypatch, pending=True, summary=(4, 1, 30, "thermal"))
    assert got == []


def test_below_threshold_is_not_flagged(monkeypatch):
    # A one-off transient refusal is not an alarm.
    got = _run(monkeypatch, pending=True, summary=(1, 1, 0, "busy"))
    assert got == []


def test_no_pending_work_is_not_flagged(monkeypatch):
    # Refused-but-nothing-waiting (e.g. a finished run) is not stuck.
    got = _run(monkeypatch, pending=False, summary=(21, 2, 0, "Ollama too old"))
    assert got == []
