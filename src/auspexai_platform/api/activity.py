"""Experiment-activity rollup endpoint (R-D3, tenant-scoped anonymized read).

GET /api/v0/experiments/{experiment_id}/activity — an anonymized liveness
rollup for one experiment: the "is my experiment really running?" signal for
the researcher dashboard. Returns a distinct active-contributor *count* (no
worker identities), the work-unit status breakdown, the latest-activity
timestamp, and replication fill.

Worker identity is anonymized by default: third-party volunteers stay
aggregate-only per the volunteer-anonymity rule (principles §5.9 / §11) — the
active-contributor figure is a COUNT(DISTINCT worker_id), not a list.

The one exception (R-D3 own-worker enrichment) is `own_workers`: workers bound
to the *experiment's tenant's own account* are listed non-anonymously to that
tenant, keyed on the b-lite `tenants.account_id` linkage (§8.2 / §6.9) and
gated by the ACCOUNT_SCOPED exposure tag. A researcher who brought their own
compute can confirm their resources are backing their work — including each
own-worker's derived **status** and, when quarantined, the maintainer's
**reason** (status follows the worker wherever it surfaces; reason is no longer
operator-only because the researcher only ever sees their own account's
workers). Third-party workers never appear there — they stay folded into the
anonymized active-contributor count. See researcher_dashboard_design.md §11.

`network_active_workers` is a PUBLIC count of all workers active network-wide
(heartbeat-fresh, not retired, not quarantined) — the "how big is the collective
my experiment draws on" signal; identity-free, so safe for any caller.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    ExperimentRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.db.repositories.receipt_index import ReceiptIndexRepository
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.exposure import ExposureTag, is_visible
from auspexai_platform.receipts.attestation import collect_diverged_units
from auspexai_platform.scheduler import worker_satisfies
from auspexai_platform.worker_status import derive_worker_status, heartbeat_cutoff


def _experiment_eligibility_reason(worker, required: dict, requires_real_execution: bool) -> str:
    """Why an own-account worker can't serve THIS experiment (R-D #2). Mirrors the
    `worker_satisfies` gates so the researcher sees the actionable reason."""
    caps = worker.capabilities or {}
    models = (required or {}).get("models") or []
    if (models or requires_real_execution) and caps.get("execute_tenant_code") != "provisioned":
        return "not in provisioned execution mode"
    held = set(caps.get("models") or [])
    missing = [m for m in models if m not in held]
    if missing and caps.get("auto_acquire") is not True:
        return f"doesn't hold {', '.join(missing)}; auto-acquire off"
    return "not eligible for this experiment"


def _liveness_note(
    experiment,
    *,
    work_unit_counts: dict[str, int],
    capable_worker_count: int | None,
) -> str | None:
    """D8: a plain-language explanation of the run's current state for the
    watching researcher, so a paused/stalled experiment self-explains instead of
    reading as a silent stall.

    The headline case is the C14 regime-3 pause: the coordinator pauses a run
    when the eligible fleet can no longer meet the unit's corroboration floor,
    and auto-resumes it once enough eligible workers return. That's a
    `last_action_by_class == system` pause — not a maintainer action — so the
    researcher is told it's a self-healing hold, not a fault.

    Returns None when there's nothing noteworthy to say (the common healthy
    case), so the dashboard banner only ever appears when it has something to
    explain.
    """
    status_val = getattr(experiment.status, "value", experiment.status)
    by = getattr(experiment, "last_action_by_class", None)
    by_val = getattr(by, "value", by)
    floor = getattr(experiment, "replication_floor", None) or getattr(
        experiment, "replication_target", None
    )

    if status_val == ExperimentStatus.PAUSED.value:
        if by_val == CredentialClass.SYSTEM.value:
            return (
                f"Paused by the coordinator: each unit needs {floor} corroborating "
                "workers, but the eligible fleet is short right now. It auto-resumes "
                "as soon as enough eligible workers are available — e.g. log a "
                "logged-out worker back in."
            )
        return "Paused by the maintainer."

    if (
        status_val == ExperimentStatus.APPROVED.value
        and work_unit_counts.get("in_progress", 0) > 0
        and floor
        and capable_worker_count is not None
        and capable_worker_count < floor
    ):
        return (
            f"Running, but corroboration is thin: {capable_worker_count} capable "
            f"worker(s) for a replication floor of {floor} — units may pause until "
            "more eligible workers join."
        )

    return None


class OwnWorkerActivity(BaseModel):
    """One of the requesting tenant's own-account workers, shown
    non-anonymously (R-D3 own-worker enrichment). Only ever populated for
    workers bound to the experiment's tenant's account; gated as a unit by the
    parent `own_workers` field's ACCOUNT_SCOPED tag."""

    worker_id: str
    worker_pubkey_hex: str
    result_count: int
    trust_tier: int
    last_activity_at: datetime | None = None
    # Derived status (active / offline / quarantined / retired) + the
    # maintainer's quarantine reason when quarantined. These follow the worker
    # to its own-account researcher; reason is intentionally surfaced here (not
    # operator-only) because this list only ever holds the researcher's own
    # account's workers.
    status: str | None = None
    quarantine_reason: str | None = None
    last_heartbeat_at: datetime | None = None
    # R-D #2: this worker's role for THIS experiment, so an account worker that
    # can't serve it shows WITH a reason instead of vanishing from the list.
    #   backing    — has submitted >=1 result to this experiment
    #   eligible   — could serve it (holds the models / auto-acquire) but hasn't yet
    #   ineligible — can't serve it (see experiment_ineligible_reason)
    experiment_eligibility: str | None = None
    experiment_ineligible_reason: str | None = None


class ExperimentActivityResponse(BaseModel):
    """Liveness rollup for one experiment. The anonymized fields are aggregate
    counts/timestamps with no per-worker identity; `own_workers` is the single
    account-scoped exception (see module docstring)."""

    experiment_id: Annotated[str | None, ExposureTag.PUBLIC] = None
    # Distinct workers that have submitted >=1 result. Integer only: the
    # volunteer-anonymity rule forbids surfacing *which* volunteers ran the work.
    active_contributor_count: Annotated[int | None, ExposureTag.PUBLIC] = None
    total_work_units: Annotated[int | None, ExposureTag.PUBLIC] = None
    work_unit_counts: Annotated[dict[str, int] | None, ExposureTag.PUBLIC] = None
    # Most recent result received_at across the experiment (omitted when no
    # results have been submitted yet).
    last_activity_at: Annotated[datetime | None, ExposureTag.PUBLIC] = None
    # Replication fill: total completions vs total target across all units.
    completions_total: Annotated[int | None, ExposureTag.PUBLIC] = None
    replication_target_total: Annotated[int | None, ExposureTag.PUBLIC] = None
    # Network size the experiment draws on: total workers active network-wide
    # (heartbeat-fresh, not retired/quarantined). Identity-free → PUBLIC.
    network_active_workers: Annotated[int | None, ExposureTag.PUBLIC] = None
    # M1 (#30): the models this experiment requires workers to locally hold, and
    # how many active workers currently satisfy that (the 'empty pool' signal
    # feeding #32 / the M2 demand-board). Omitted when there's no requirement.
    required_capabilities: Annotated[dict[str, list[str]] | None, ExposureTag.TENANT_SCOPED] = None
    capable_worker_count: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    # R-D3 own-worker enrichment: the tenant's OWN-account workers, listed
    # non-anonymously. ACCOUNT_SCOPED — visible only to a credential whose
    # account_id matches the experiment's tenant's account (or the maintainer).
    # The filter gates the whole list as a unit; the list is also populated
    # server-side with own-account workers only, so it can never carry a
    # third-party identity even before filtering (defense in depth).
    own_workers: Annotated[list[OwnWorkerActivity] | None, ExposureTag.ACCOUNT_SCOPED] = None
    # D8 "liveness note": a plain-language self-explanation of the run's current
    # state for the watching researcher — most importantly, why a C14 regime-3
    # pause is a "waiting for an eligible worker, auto-resumes" hold rather than a
    # silent stall. TENANT_SCOPED: it's the owner's own run; carries no identity.
    liveness_note: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    # Richer D8 (live corroboration health): the number of completed units whose
    # independent replicas DIVERGED — workers disagreed, so no agreement, no
    # receipt (firewall #1's signed-observation, G4). A live > 0 is the
    # nondeterminism / model-version-skew signal a researcher would otherwise only
    # see retrospectively in the evidence footprint; it is NOT model drift. An
    # aggregate count with no per-worker identity → PUBLIC, like the other counts.
    # None on the empty rollup (no per-job DB yet).
    diverged_unit_count: Annotated[int | None, ExposureTag.PUBLIC] = None


def build_router(
    credential_dep,
    experiment_repository: ExperimentRepository,
    per_job_factory: PerJobDatabaseFactory,
    tenant_repository: TenantRepository,
    worker_repository: WorkerRepository,
    receipt_index_repository: ReceiptIndexRepository,
) -> APIRouter:
    router = APIRouter()

    def _own_workers(
        experiment, per_job_db, now: datetime
    ) -> tuple[list[OwnWorkerActivity], str | None]:
        """Build the own-account worker list for `experiment`'s tenant, plus the
        tenant's account_id (the resource_account_id used to gate the field).

        Returns ([], None) when the tenant isn't account-linked (b-lite
        `tenants.account_id` is NULL) — nothing to enrich, nothing to gate
        against. Otherwise returns the account's workers (R-D #2), each tagged
        with its role for THIS experiment (backing / eligible / ineligible) so an
        account worker that can't serve it shows WITH a reason rather than
        vanishing. The set is the UNION of the account's CURRENT workers and the
        workers that backed this experiment under the account's
        `account_id_at_issue` snapshot — so a contributor that has since logged
        out (unbound → account_id NULL) still shows as "backing" instead of
        disappearing while its receipts stay credited. Third-party contributors
        (a different account_id_at_issue) are never included.
        """
        tenant = tenant_repository.get_by_id(experiment.tenant_id)
        account_id = tenant.account_id if tenant is not None else None
        if account_id is None:
            return [], None
        # The union of (a) workers CURRENTLY bound to this account and (b) the
        # workers that contributed to THIS experiment under this account's
        # issuance snapshot. (b) catches logged-out contributors that (a) drops.
        current_map = {w.worker_id: w for w in worker_repository.list_for_account(account_id)}
        snapshot_ids = receipt_index_repository.account_contributor_worker_ids(
            experiment.experiment_id, account_id
        )
        own_ids = set(current_map) | set(snapshot_ids)
        if not own_ids:
            return [], account_id
        # Contributions to THIS experiment, keyed by worker_id.
        contribs = {
            c["worker_id"]: c for c in ResultRepository(per_job_db).per_worker_contributions()
        }
        required = getattr(experiment, "required_capabilities", None) or {}
        rre = bool(getattr(experiment, "requires_real_execution", False))
        own: list[OwnWorkerActivity] = []
        for wid in own_ids:
            worker = current_map.get(wid) or worker_repository.get_by_id(wid)
            if worker is None:
                continue
            c = contribs.get(wid)
            if c is not None:
                eligibility, reason = "backing", None
                result_count, last_activity = c["result_count"], c["last_received_at"]
                pubkey = c["worker_pubkey_hex"]
            else:
                satisfies = worker_satisfies(
                    worker,
                    required,
                    requires_real_execution=rre,
                    required_containment=getattr(experiment, "required_containment", "permissive"),
                )
                eligibility = "eligible" if satisfies else "ineligible"
                reason = (
                    None if satisfies else _experiment_eligibility_reason(worker, required, rre)
                )
                result_count, last_activity = 0, None
                pubkey = worker.pubkey_hex
            own.append(
                OwnWorkerActivity(
                    worker_id=worker.worker_id,
                    worker_pubkey_hex=pubkey,
                    result_count=result_count,
                    trust_tier=int(worker.trust_tier),
                    last_activity_at=last_activity,
                    status=derive_worker_status(worker, now).value,
                    quarantine_reason=worker.quarantine_reason,
                    last_heartbeat_at=worker.last_heartbeat_at,
                    experiment_eligibility=eligibility,
                    experiment_ineligible_reason=reason,
                )
            )
        own.sort(key=lambda w: w.worker_id)
        return own, account_id

    def _can_view(credential: Credential, experiment) -> bool:
        if credential.is_maintainer():
            return True
        return credential.is_researcher() and credential.tenant_id == experiment.tenant_id

    @router.get(
        "/experiments/{experiment_id}/activity",
        response_model=ExperimentActivityResponse,
        response_model_exclude_none=True,
    )
    async def get_experiment_activity(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentActivityResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        # Tenant-private (mirrors work-units / experiment-detail): a non-owning
        # researcher or anonymous caller gets the same 404 as a genuinely-absent
        # experiment, so the rollup never confirms an experiment id exists.
        if experiment is None or not _can_view(credential, experiment):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "experiment_not_found",
                        "message": f"no experiment with id {experiment_id!r}",
                        "details": {"experiment_id": experiment_id},
                    }
                },
            )

        now = datetime.now(UTC)
        network_active = worker_repository.count_active(heartbeat_cutoff=heartbeat_cutoff(now))

        # M1 (#30): how many active workers can actually run this experiment given
        # its model requirement. Only meaningful when there IS a requirement;
        # capable==0 with pending units is the empty-pool signal (#32 / M2).
        required_caps = experiment.required_capabilities or {}
        required_models = required_caps.get("models", [])
        capable_worker_count = (
            worker_repository.count_capable(
                required_models=required_models, heartbeat_cutoff=heartbeat_cutoff(now)
            )
            if required_models
            else None
        )

        per_job_db = per_job_factory.get(experiment_id)
        if per_job_db is None:
            # No work units ever submitted for this experiment → empty rollup.
            # (No contributors yet, so no own-worker enrichment either.)
            return ExperimentActivityResponse(
                experiment_id=experiment_id,
                active_contributor_count=0,
                total_work_units=0,
                work_unit_counts={},
                completions_total=0,
                replication_target_total=0,
                network_active_workers=network_active,
                required_capabilities=required_caps or None,
                capable_worker_count=capable_worker_count,
            )

        work_units = WorkUnitRepository(per_job_db)
        results = ResultRepository(per_job_db)

        counts = work_units.count_by_status()
        completions_total, target_total = work_units.replication_totals()
        own_workers, account_id = _own_workers(experiment, per_job_db, now)

        # Gate `own_workers` (ACCOUNT_SCOPED) via the same decision function the
        # field-exposure filter uses — but inline, so the typed
        # OwnWorkerActivity instances survive (filter_for_credential would
        # round-trip the list through plain dicts, which Pydantic then
        # re-serializes with a warning under filterwarnings=error). The owning
        # researcher (whose tenant carries this account) and the maintainer
        # see the list; everyone else gets it nulled. The PUBLIC aggregate
        # fields are unaffected.
        show_own = is_visible(
            ExposureTag.ACCOUNT_SCOPED, credential, resource_account_id=account_id
        )

        return ExperimentActivityResponse(
            experiment_id=experiment_id,
            active_contributor_count=results.count_distinct_workers(),
            total_work_units=sum(counts.values()),
            work_unit_counts=counts,
            last_activity_at=results.latest_received_at(),
            completions_total=completions_total,
            replication_target_total=target_total,
            network_active_workers=network_active,
            required_capabilities=required_caps or None,
            capable_worker_count=capable_worker_count,
            own_workers=(own_workers or None) if show_own else None,
            liveness_note=_liveness_note(
                experiment,
                work_unit_counts=counts,
                capable_worker_count=capable_worker_count,
            ),
            # Richer D8: live corroboration health — completed units whose
            # replicas diverged (no agreement, no receipt). 0 == cross-check clean.
            diverged_unit_count=len(collect_diverged_units(per_job_db)),
        )

    return router
