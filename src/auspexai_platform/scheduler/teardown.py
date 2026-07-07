"""D22-B teardown cascade + receipt-outcome settle.

When an experiment goes terminal (aborted/archived), a plain status flip leaves
its non-terminal work units `in_progress` forever and — worse — leaves every
result it collected without any terminal signal, so the worker's M7-tail
canonical-receipt loop polls a 404 that will never resolve (the pre-D22-B leak:
243 results across 16 experiments on the first audited fleet).

This module closes that gap:

  * `settle_terminal_experiment` — the ABORT-time cascade (called from the abort
    route): cancel the experiment's still-open units and mark every result that
    earned no receipt as terminal-receiptless (`experiment_<status>`), so
    workers stop polling.

  * `settle_all_terminal_experiments` — the idempotent sweep behind the one-shot
    backfill (`scripts/settle_terminal_experiments.py`) and a recurring guard:
    the same settle for every terminal experiment, PLUS a `no_receipt` marker
    for any finalized-unit result that never won a receipt in a still-live
    experiment (the legitimate non-consensus / outlier case — a VALID state,
    firewall #1, not a failure; we mark only the RECEIPT terminal so the worker
    stops polling, never the result's validity/exportability).

All writes are idempotent (INSERT OR IGNORE / status-guarded UPDATE), so
re-running any of these is a no-op — safe to wire to a timer and to re-run the
backfill.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from auspexai_platform.db.models import ExperimentStatus, WorkUnitStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.experiments import ExperimentRepository
from auspexai_platform.db.repositories.receipt_index import ReceiptIndexRepository
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.unit_consensus import UnitConsensusRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository

logger = logging.getLogger(__name__)

_TERMINAL_EXPERIMENT_STATES = (ExperimentStatus.ABORTED, ExperimentStatus.ARCHIVED)
_NON_TERMINAL_UNIT_STATES = (WorkUnitStatus.PENDING, WorkUnitStatus.IN_PROGRESS)


@dataclass(frozen=True)
class SettleResult:
    """Per-experiment settle counts (for logging / the backfill summary)."""

    experiment_id: str
    units_cancelled: int
    results_marked: int


def _mark_receiptless_results(
    *,
    experiment_id: str,
    experiment_status: ExperimentStatus,
    per_job_db,
    receipt_index_repository: ReceiptIndexRepository,
    apply: bool = True,
) -> int:
    """Mark every result of this experiment that earned no receipt as terminally
    receipt-less. A result with a real receipt (in receipt_index) is skipped, as
    is one already marked in receipt_outcomes — so the count is the number of
    results NEWLY resolved, accurate in both dry-run and apply.

    The reason is derived from state, never pejorative:
      * unit reached consensus (unit_consensus row) → 'diverged_from_consensus'
        (this replica was a valid outlier / non-consensus observation);
      * else, for a terminal experiment → 'experiment_<status>';
      * else → 'non_consensus' (finalized-without-receipt, best-effort).
    `apply=False` counts what WOULD be marked without writing (dry-run)."""
    results_repo = ResultRepository(per_job_db)
    consensus_repo = UnitConsensusRepository(per_job_db)
    marked = 0
    for worker_id, result_id, unit_id in results_repo.all_result_refs():
        # Positive receipt already exists → nothing terminal to record.
        if (
            receipt_index_repository.get_for_worker_result(worker_id=worker_id, result_id=result_id)
            is not None
        ):
            continue
        # Already resolved terminal → no-op (keeps counts + dry-run honest).
        if (
            receipt_index_repository.get_result_outcome(worker_id=worker_id, result_id=result_id)
            is not None
        ):
            continue
        if consensus_repo.get(unit_id) is not None:
            outcome, reason = "no_receipt", "diverged_from_consensus"
        elif experiment_status in _TERMINAL_EXPERIMENT_STATES:
            outcome, reason = "experiment_terminal", f"experiment_{experiment_status.value}"
        else:
            # A finalized-unit result with no receipt and no consensus row: rare
            # (capacity-settled), still terminal for receipt purposes.
            outcome, reason = "no_receipt", "non_consensus"
        if apply:
            try:
                receipt_index_repository.record_no_receipt(
                    worker_id=worker_id,
                    result_id=result_id,
                    experiment_id=experiment_id,
                    unit_id=unit_id,
                    outcome=outcome,
                    reason=reason,
                )
            except Exception:
                logger.exception(
                    "settle: receipt_outcomes write failed exp=%s result=%s",
                    experiment_id,
                    result_id,
                )
                continue
        marked += 1
    return marked


def _cancel_open_units(*, per_job_db, apply: bool = True) -> int:
    """Cancel this experiment's still-open (pending/in_progress) units → the
    terminal CANCELLED state, because the experiment went terminal before they
    completed (distinct from FAILED, a code/schema fault). The scheduler only
    offers PENDING/IN_PROGRESS, so a cancelled unit is never re-offered. Returns
    the count transitioned (dry-run: the count that WOULD be cancelled)."""
    work_units_repo = WorkUnitRepository(per_job_db)
    cancelled = 0
    for state in _NON_TERMINAL_UNIT_STATES:
        for unit in work_units_repo.list_all(status=state):
            if apply:
                _, just_cancelled = work_units_repo.mark_cancelled(unit.unit_id)
                if just_cancelled:
                    cancelled += 1
            else:
                cancelled += 1
    return cancelled


def settle_terminal_experiment(
    *,
    experiment_id: str,
    experiment_status: ExperimentStatus,
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository: ReceiptIndexRepository,
    apply: bool = True,
) -> SettleResult:
    """The abort-time cascade for ONE experiment: cancel its open units and mark
    its receiptless results terminal. Idempotent + best-effort — a missing
    per-job DB (never dispatched) yields a zero-count result rather than raising,
    so it never blocks the status transition it follows."""
    per_job_db = per_job_factory.get(experiment_id)
    if per_job_db is None:
        return SettleResult(experiment_id=experiment_id, units_cancelled=0, results_marked=0)
    units_cancelled = _cancel_open_units(per_job_db=per_job_db, apply=apply)
    results_marked = _mark_receiptless_results(
        experiment_id=experiment_id,
        experiment_status=experiment_status,
        per_job_db=per_job_db,
        receipt_index_repository=receipt_index_repository,
        apply=apply,
    )
    if units_cancelled or results_marked:
        logger.info(
            "settle: experiment %s (%s) — cancelled %d open unit(s), marked %d "
            "receiptless result(s)",
            experiment_id,
            experiment_status.value,
            units_cancelled,
            results_marked,
        )
    return SettleResult(
        experiment_id=experiment_id,
        units_cancelled=units_cancelled,
        results_marked=results_marked,
    )


def settle_all_terminal_experiments(
    *,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository: ReceiptIndexRepository,
    include_completed: bool = True,
    apply: bool = True,
) -> list[SettleResult]:
    """Sweep every experiment and settle its receipt outcomes — the idempotent
    engine behind the one-shot backfill and a recurring guard.

    * ABORTED/ARCHIVED experiments: cancel open units + mark receiptless results.
    * COMPLETED experiments (`include_completed`): mark finalized-unit results
      that never won a receipt (the historical non-consensus / outlier backlog
      that predates the issuance-time markers). No unit-cancellation — a
      completed experiment's units are already terminal.

    APPROVED/PAUSED/SUBMITTED experiments are left untouched: their pending
    units may still legitimately earn receipts, so a 404 there is genuinely
    transient. Returns the non-empty settle results (experiments that changed)."""
    statuses = list(_TERMINAL_EXPERIMENT_STATES)
    if include_completed:
        statuses.append(ExperimentStatus.COMPLETED)

    out: list[SettleResult] = []
    for status in statuses:
        for exp in experiment_repository.list_all(status=status):
            per_job_db = per_job_factory.get(exp.experiment_id)
            if per_job_db is None:
                continue
            units_cancelled = (
                _cancel_open_units(per_job_db=per_job_db, apply=apply)
                if status in _TERMINAL_EXPERIMENT_STATES
                else 0
            )
            results_marked = _mark_receiptless_results(
                experiment_id=exp.experiment_id,
                experiment_status=exp.status,
                per_job_db=per_job_db,
                receipt_index_repository=receipt_index_repository,
                apply=apply,
            )
            if units_cancelled or results_marked:
                out.append(
                    SettleResult(
                        experiment_id=exp.experiment_id,
                        units_cancelled=units_cancelled,
                        results_marked=results_marked,
                    )
                )
    return out
