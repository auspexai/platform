"""Scheduler — picks the next work unit for a worker on demand (M6d).

Pull model: workers call `GET /workers/{id}/assignments` after each
heartbeat; the scheduler returns at most one assignment per call (one
unit at a time per worker for v0). No background loops, no push, no
SSE — those are M8 concerns.

Algorithm: **first-fit-with-capability filtering**. Walk approved
experiments in registration order; for each, walk pending + in_progress
work units in creation order; pick the first one this worker is
eligible for and not already assigned to.

Eligibility:
  - Worker not retired (filtered upstream by CredentialResolver)
  - Worker hasn't already been assigned this unit
  - Unit's total assignment count < unit.replication_target
    (no over-assignment beyond the quorum target)
  - **NO per-worker tier floor (D9 Phase 4 — worker-participation accrual):**
    a worker's trust tier does NOT gate which units it may take. Any
    consenting, enrolled worker (capability-satisfied, not retired /
    quarantined / paused) is eligible — so a freshly-onboarded low-tier
    worker is never stranded. The experiment's corroboration rides its
    (target, floor) + A4 account-weighted independence; the worker's tier
    governs only its own compute-standing accrual, not participation.

**Capability matching (#30, M1):** per §5.8 the scheduler matches a worker's
locally-held models against the experiment's `required_capabilities` (derived at
submit from the manifest's `local_weights_required` models, keyed by store
model_id). A worker is skipped for an experiment whose required models it
doesn't hold (`worker_satisfies`). An experiment with no requirement is open to
every worker (the pre-M1 behavior). Broader capability dimensions (OS/GPU) and
the full heterogeneous-pool routing remain Phase-2; M1 ships the model-inventory
thin slice that makes BYOM routing real.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    Assignment,
    ExperimentStatus,
    IntegrityPolicy,
    TrustTier,
    Worker,
    WorkUnit,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    WorkUnitRepository,
)

_TIER_REPLICATION_FLOOR = {
    TrustTier.T0_ANONYMOUS: 3,
    TrustTier.T1_AUTHENTICATED: 2,
    TrustTier.T2_TRUSTED: 1,
    TrustTier.T3_VETTED: 1,
}


def replication_floor_for_tier(tier: TrustTier) -> int:
    return _TIER_REPLICATION_FLOOR.get(tier, 3)


def integrity_policy_for_request(
    *, replication_factor: int, tenant_tier: TrustTier | int
) -> IntegrityPolicy:
    """A' (§9): seed an experiment's integrity policy from the researcher's
    requested replication, FLOORED by the tenant's trust tier via
    `_TIER_REPLICATION_FLOOR` (the TENANT-side floor; D9 Phase 4 removed the
    worker-side eligibility use of this map). A tenant earns lower replication
    (less consensus cross-check) only as
    its account earns trust (receipts). Effective replication = max(requested,
    tier floor), rounded UP to a policy tier (1 trusted / 3 standard / 5 high).
    Net: only T2+ tenants reach trusted/repl-1; T0/T1 floor at standard."""
    floor = _TIER_REPLICATION_FLOOR.get(TrustTier(int(tenant_tier)), 3)
    effective = max(int(replication_factor), floor)
    if effective <= 1:
        return IntegrityPolicy.TRUSTED
    if effective <= 3:
        return IntegrityPolicy.STANDARD
    return IntegrityPolicy.HIGH


def _derive_integrity_policy(replication_target: int) -> IntegrityPolicy:
    """C14: the integrity_policy enum is now a DERIVED coarse label over the real
    `replication_target` (the source of truth). 2 and 3 both read as 'standard' — the
    precise count is the target, the precise corroboration is the basis code."""
    if replication_target <= 1:
        return IntegrityPolicy.TRUSTED
    if replication_target <= 3:
        return IntegrityPolicy.STANDARD
    return IntegrityPolicy.HIGH


def resolve_replication(
    *,
    requested_target: int,
    requested_floor: int | None,
    tenant_tier: TrustTier | int,
    tier_floor_override: int | None = None,
) -> tuple[int, int, IntegrityPolicy]:
    """C14: resolve an experiment's (replication_target, replication_floor) from the
    researcher's request — decoupled from the {1,3,5} ladder so repl-2 is expressible.
    The tier floor is the COORDINATOR's trust requirement (lower tenant trust → more
    corroboration); it floors both. `requested_floor` defaults to 2 (a real cross-check);
    the floor is DORMANT until capacity-aware completion (regime 2) consumes it, and never
    exceeds the target. Returns (target, floor, derived policy label).

    `tier_floor_override` (the certified-starter exemption, Ethics §6.7): when set it
    REPLACES the tenant's trust-tier floor with the certified floor. DEFENSIVE /
    belt-and-suspenders, NOT load-bearing: a registered tenant floors at T1 (floor 2),
    which already equals the typical certified floor — so this only changes a hypothetical
    T0 (anonymous) submitter (floor 3 → 2), and registered tenants are never T0. It guards
    against a stall the current tenant model can't actually produce. (Verified live: a T1
    newcomer's certified-starter run seeded at floor 2 with or without the override.)"""
    tier_floor = (
        int(tier_floor_override)
        if tier_floor_override is not None
        else _TIER_REPLICATION_FLOOR.get(TrustTier(int(tenant_tier)), 3)
    )
    target = max(int(requested_target), tier_floor)
    floor = max(int(requested_floor) if requested_floor is not None else 2, tier_floor)
    floor = min(floor, target)
    return target, floor, _derive_integrity_policy(target)


def policy_floor_for_tier(tenant_tier: TrustTier | int) -> IntegrityPolicy:
    """A' approve-time clamp: the most-permissive (lowest-replication) integrity
    policy a tenant of this tier is ALLOWED to run at — the manual-override
    floor. Equivalent to seeding from a repl-1 request: the tier floor clamps it
    up. T0/T1 floor at STANDARD (repl-3); only T2+ may reach TRUSTED (repl-1).

    Reuses `integrity_policy_for_request` so the submit-time seed and the
    approve-time clamp can never disagree about where the floor sits."""
    return integrity_policy_for_request(replication_factor=1, tenant_tier=tenant_tier)


def is_sub_floor_policy(policy: IntegrityPolicy, tenant_tier: TrustTier | int) -> bool:
    """True when `policy` requests FEWER replicas (less consensus cross-check)
    than the tenant's tier floor allows — i.e. more trust than the account has
    earned. Raising replication ABOVE the floor is always permitted; only
    lowering BELOW it is gated (the A' approve-time clamp). Replication ordering
    comes from `INTEGRITY_POLICY_REPLICATION`: trusted=1 < standard=3 < high=5."""
    floor = policy_floor_for_tier(tenant_tier)
    return INTEGRITY_POLICY_REPLICATION[policy] < INTEGRITY_POLICY_REPLICATION[floor]


# §41 containment floor — the sandbox-isolation analogue of the A' replication
# floor. Less-trusted tenant CODE must run under stricter host isolation
# (protecting the volunteer's machine from the executor), and the scheduler
# routes such units only to workers whose sandbox policy meets the floor.
# Ordering: permissive < strict.
CONTAINMENT_PERMISSIVE = "permissive"
CONTAINMENT_STRICT = "strict"
_CONTAINMENT_RANK = {CONTAINMENT_PERMISSIVE: 0, CONTAINMENT_STRICT: 1}


def containment_rank(level: str | None) -> int:
    """Isolation-strength ordering; unknown/None (e.g. an old worker that doesn't
    yet report its policy) reads as permissive (0). A worker is eligible for
    required level R iff `rank(worker) >= rank(R)` — a worker may always be
    STRICTER than required, never weaker."""
    return _CONTAINMENT_RANK.get(level or CONTAINMENT_PERMISSIVE, 0)


def required_containment_for_tier(tenant_tier: TrustTier | int, strict_below_tier: int) -> str:
    """The minimum sandbox containment a tenant of this tier's CODE must run
    under. Mirrors `integrity_policy_for_request`: lower tenant trust → stricter
    requirement (the volunteer's host is protected from less-vetted code).
    `strict_below_tier == 0` disables the floor — the Phase-1 default (vetted
    tenants + operator-owned fleet → permissive acceptable)."""
    return CONTAINMENT_STRICT if int(tenant_tier) < strict_below_tier else CONTAINMENT_PERMISSIVE


# §2.1 #8 (dispatch-retry): a refused assignment used to permanently bar the
# worker from the unit (`already_assigned` skip), which on a small fleet
# stranded the unit when every worker refused — exactly what M0 hit (the
# sandbox runner-not-found + runner-crash failures were environmental, not the
# worker declining the work). Refusals split into two classes by `refused_kind`:
#
#   - RETRYABLE: environmental / transient failures that may succeed on a retry,
#     possibly on the *same* worker once the condition clears (a fixed sandbox,
#     a cooled GPU). The unit is re-offered (the row is reactivated) up to
#     MAX_ASSIGNMENT_ATTEMPTS times per worker.
#   - TERMINAL: policy / capability / integrity refusals that won't change
#     without operator or capability action (tenant deny/allow-list, sensitive
#     gate, manifest-hash mismatch, executor refused, explicit manual). The
#     worker stays excluded — re-offering would just refuse again.
#
# The kind strings are exactly what the worker daemon sends to /refuse
# (DispatchOutcomeKind for post-acceptance failures, DecisionKind for
# pre-dispatch gate refusals). Unknown kinds default to TERMINAL — a surprise
# refusal shouldn't silently spin in a retry loop.
_RETRYABLE_REFUSAL_KINDS = frozenset(
    {
        "runner_failed",  # DispatchOutcomeKind.RUNNER_CRASH — runner subprocess crashed
        "sandbox_unavailable",  # bwrap / sandbox couldn't start (the M0 case)
        "thermal_critical",  # W-H refuse-when-hot; retry once cooled
        "submit_failed_transient",  # result submission failed transiently
    }
)

# Some refusals carry the broad `executor_refused` kind but are actually
# *availability* (transient) failures, not policy/integrity (terminal) ones. The
# worker deliberately tags the reason so the coordinator can re-offer them (see
# worker provisioning.PackageFetchError): a package that couldn't be FETCHED yet
# (#40a) or a model that couldn't be SERVED yet may well succeed on a retry,
# whereas tenant_deny / manifest_swap / sensitive will not. Matched as substrings
# in the (lowercased) refusal reason; the per-worker attempt cap still bounds it.
_RETRYABLE_REFUSAL_REASON_MARKERS = (
    "package_unavailable",
    "serving unavailable",
    # v0_2 M1: a version-skewed worker refuses a serving_version_pin'd unit; the
    # unit re-offers to a version-matching peer (environmental, not the work).
    "serving_version_mismatch",
)

# Per-(unit, worker) attempt ceiling: the initial offer + retries. A retryable
# refusal that keeps recurring is bounded so a genuinely-broken pairing can't
# loop forever; once exhausted the worker is excluded like a terminal refusal.
MAX_ASSIGNMENT_ATTEMPTS = 3


def is_retryable_refusal(kind: str | None, reason: str | None = None) -> bool:
    """True if a refusal should re-offer the unit (incl. to the same worker).
    Retryable when the `kind` is a known-transient one, OR the `reason` carries
    an availability marker (a package/serving that wasn't ready yet — the worker
    tags these on the otherwise-terminal `executor_refused` kind). Unknown kinds
    with no marker are terminal."""
    if kind in _RETRYABLE_REFUSAL_KINDS:
        return True
    if reason:
        low = reason.lower()
        return any(m in low for m in _RETRYABLE_REFUSAL_REASON_MARKERS)
    return False


def worker_is_self_paused(worker: Worker) -> bool:
    """True if the worker declared a volunteer self-pause (§2.1 #11) — the
    resource owner temporarily withholding their machine, distinct from the
    operator `paused_at` hold. Worker-declared via `capabilities["self_paused"]`
    (like thermal/auto_acquire); the scheduler routes around it. The owner clears
    it (the operator can't), and the operator's `paused_at` is separate (the
    volunteer can't clear that) — two distinct holds, each cleared by its owner."""
    return worker.capabilities.get("self_paused") is True


def worker_is_degraded(worker: Worker) -> bool:
    """True if the worker's last heartbeat reports a thermal-critical state (M5,
    W-H increment 2). The worker declares `capabilities["thermal"]` =
    `{state, current_temp_c, ...}` (worker `health.ThermalSnapshot.to_dict`);
    `state == "critical"` means it's throttling/refusing locally, so the
    scheduler routes around it until it recovers. Absent/unreadable thermal ⇒
    not degraded (a worker with no sensor is never excluded on this axis)."""
    thermal = worker.capabilities.get("thermal")
    if not isinstance(thermal, dict):
        return False
    return thermal.get("state") == "critical"


# C16: how long an ACTIVE assignment may sit result-less and refusal-less before
# the offer is presumed lost in flight and becomes re-DELIVERABLE to its own
# worker. The offer response can be lost (read timeout / edge 502 under origin
# slowness — observed live 2026-07-01, exp-9WLGijaO): the row commits server-side
# but the worker never learns of it, and without this lease the unit wedges
# forever (the active row blocks re-offer; a full replica count blocks everyone
# else; below-floor blocks the settle-sweep). Keep the lease WELL above real unit
# durations: a worker still executing past it would double-run at worst, and the
# submit route 409s the second result (result_already_submitted) — safe, not free.
ASSIGNMENT_REDELIVERY_LEASE_SECONDS = 600


def assignment_presumed_lost(
    assignment: Assignment,
    *,
    redelivery_lease_seconds: float = ASSIGNMENT_REDELIVERY_LEASE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """C16: True for an ACTIVE row (no result, no refusal) older than the
    re-delivery lease — the offer response was presumably lost in flight and
    the worker never learned of its assignment. A fresh active row is presumed
    delivered (the worker may be executing right now)."""
    if assignment.result_id is not None or assignment.refused_at is not None:
        return False
    assigned_at = assignment.assigned_at
    if assigned_at.tzinfo is None:
        assigned_at = assigned_at.replace(tzinfo=UTC)
    age = ((now or datetime.now(UTC)) - assigned_at).total_seconds()
    return age > redelivery_lease_seconds


def reoffer_eligible(
    assignment: Assignment,
    *,
    max_attempts: int = MAX_ASSIGNMENT_ATTEMPTS,
    redelivery_lease_seconds: float = ASSIGNMENT_REDELIVERY_LEASE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """True if an existing assignment row can be re-offered to the same worker.

    Two cases, one policy point (the scheduler uses this to decide eligibility;
    the assignment route uses it to decide create-vs-reactivate):

    - **refused-retryable** (§2.1 #8 dispatch-retry): the row is refused, the
      refusal kind is retryable, and the attempt cap isn't exhausted.
    - **stale-active re-delivery** (C16, at-least-once offer): the row is ACTIVE
      (no result, no refusal) but older than the re-delivery lease — the offer
      response was presumably lost in flight, so the same row is re-delivered
      to its own worker through the same re-arm path. Without this, a lost
      response wedges the unit permanently.

    A result-bearing row is never re-offerable."""
    if assignment.result_id is not None:
        return False
    if assignment.refused_at is None:
        # C16 stale-active branch: re-deliver a presumed-lost offer, under the
        # same attempt cap that bounds refusal retries (no infinite re-delivery
        # to a pairing that never lands).
        return assignment.attempt_count < max_attempts and assignment_presumed_lost(
            assignment, redelivery_lease_seconds=redelivery_lease_seconds, now=now
        )
    if not is_retryable_refusal(assignment.refused_kind, assignment.refused_reason):
        return False
    return assignment.attempt_count < max_attempts


class SkipReason(StrEnum):
    """Why the scheduler passed over a unit/experiment for a given worker. The
    shared vocabulary the M4 scheduler-ops console surfaces as 'why a unit isn't
    being assigned'. (M1 introduces it + uses MISSING_CAPABILITY; M4 wires the
    per-unit reasons into the observability endpoint.)"""

    BELOW_TIER_FLOOR = "below_tier_floor"
    ALREADY_ASSIGNED = "already_assigned"
    AT_REPLICATION = "at_replication"
    MISSING_CAPABILITY = "missing_capability"
    TERMINALLY_REFUSED = "terminally_refused"  # §2.1 #8 — refused, not retryable
    RETRIES_EXHAUSTED = "retries_exhausted"  # §2.1 #8 — retryable but at cap


def worker_runs_provisioned(worker: Worker) -> bool:
    """True if the worker's owner consented to running real (provisioned) tenant
    code — declared via `capabilities["execute_tenant_code"] == "provisioned"`
    (M9 leg 4). Absent / `synthetic` / `off` ⇒ False.

    This is the worker→code consent axis (§9 #37), ORTHOGONAL to `trust_tier`
    (network→worker, which sizes replication). It is consumed by `worker_satisfies`
    purely for *consensus safety*: a `synthetic`-mode worker echoes every unit
    (`decide_execution` returns the built-in echo regardless of the manifest), so
    if it were offered a real, model-gated experiment its echo would diverge from
    the provisioned replicas and pollute hash-agreement consensus (#33) as a false
    disagreement. Excluding it is a routing decision, NOT a tier gate — the setter
    that controls this stays tier-agnostic (the owner's box, the owner's consent)."""
    return worker.capabilities.get("execute_tenant_code") == "provisioned"


def worker_satisfies(
    worker: Worker,
    required_capabilities: dict[str, list[str]],
    *,
    requires_real_execution: bool = False,
    required_containment: str = CONTAINMENT_PERMISSIVE,
) -> bool:
    """True if the worker is eligible for an experiment with these requirements
    (#30, M1; + M9 leg 4 execute-mode gate). `required_capabilities` is keyed by
    dimension; Phase-1 matches the "models" key against the worker's declared
    `capabilities["models"]` inventory by EXACT store model_id (hash-agreement
    consensus needs identical quants). Empty requirement ⇒ always satisfied (the
    pre-M1 behavior — every worker eligible, incl. synthetic-mode workers running
    the doubler/test tenants), UNLESS `requires_real_execution` is set (below).
    Unknown capability dimensions are ignored in Phase-1.

    **M9 leg 4 — consensus-safe routing.** A `models` requirement marks a
    *real-execution* experiment (it needs local weights ⇒ the tenant's executor
    must actually run). Such units route ONLY to `provisioned`-mode workers
    (`worker_runs_provisioned`); a `synthetic`/`off` worker is excluded even if it
    happens to hold the model in its store, because it would echo rather than run
    — polluting consensus.

    **Audit 2026-06-08 — model-less real execution.** A real-execution experiment
    that declares NO local weights also must be kept off synthetic-mode workers
    (else an all-synthetic fleet echoes identically → a FALSE consensus + receipt).
    The experiment-level `requires_real_execution` flag (derived at submit from the
    manifest) closes that gap: when set, only provisioned-mode workers are eligible
    regardless of the model requirement.

    M3 (lazy auto-acquire): a provisioned worker that declares
    `capabilities["auto_acquire"]` satisfies any model requirement — on assignment
    it pulls a missing locally-required model (reading coords from the staged
    manifest) and then runs, rather than refusing. The scheduler's replication
    bound still caps how many such workers ever get the unit, so the acquisition
    fan-out is naturally sized (≤ replication_target pull). If the manifest carries
    no acquisition coords, the worker refuses on assignment (model_not_acquirable)
    — surfaced as demand, not a silent stall.

    **§41 containment floor.** A worker is eligible only if its host isolation
    (`capabilities["sandbox_policy"]`) is at least as strict as the experiment's
    tenant tier requires (`required_containment`). An old worker that doesn't
    report a policy reads as permissive, so it's excluded from strict-required
    work — fail-safe. Default permissive ⇒ no gate (the Phase-1 norm).

    **v0.2 M1 `features` dimension.** A feature-gated experiment (today:
    `generation_policy` for seeded sampling) routes only to workers whose build
    declares the feature in `capabilities["worker_features"]`. An old worker
    that declares none reads as feature-less — fail-safe (a pre-M1 broker
    would burn sampling units with params_rejected instead of refusing)."""
    if containment_rank(worker.capabilities.get("sandbox_policy")) < containment_rank(
        required_containment
    ):
        return False
    required_features = set(required_capabilities.get("features", []))
    if required_features:
        declared = worker.capabilities.get("worker_features")
        have_features = set(declared) if isinstance(declared, list) else set()
        if not required_features <= have_features:
            return False
    required_models = set(required_capabilities.get("models", []))
    if not required_models:
        # No model requirement: every worker eligible UNLESS the experiment
        # explicitly requires real execution, in which case synthetic/off workers
        # would echo and pollute consensus — gate to provisioned-mode only.
        if requires_real_execution:
            return worker_runs_provisioned(worker)
        return True
    # Real-execution experiment → only provisioned-mode workers (consensus safety).
    if not worker_runs_provisioned(worker):
        return False
    # Top-down fleet-fit: a worker is eligible only if its RAM can actually SERVE
    # each required model — whether it holds the model or would auto-acquire it. The
    # coordinator sized the models from HF at submit (`model_ram_gb`); excluding a
    # too-small worker here means a too-big model is never routed to it (where it
    # would fail at load / refuse). Unsized models (no HF coords) and workers that
    # don't report RAM pass through — the worker's own acquire guard is the backstop.
    model_ram_gb = required_capabilities.get("model_ram_gb") or {}
    # Gate on the worker's usable SERVE budget (ram_total - headroom), not raw
    # ram_total — else we'd route a model the worker then refuses at load (an 8B-q4
    # on a unified 8 GB box). Fall back to ram_total for pre-fleet-fit workers.
    worker_ram = worker.capabilities.get("usable_memory_gb")
    if not isinstance(worker_ram, (int, float)):
        worker_ram = worker.capabilities.get("ram_total_gb")
    if isinstance(worker_ram, (int, float)) and model_ram_gb:
        for mid in required_models:
            fp = model_ram_gb.get(mid)
            if isinstance(fp, (int, float)) and worker_ram < fp:
                return False
    if worker.capabilities.get("auto_acquire") is True:
        return True
    have = worker.capabilities.get("models", [])
    have_models = set(have) if isinstance(have, list) else set()
    return required_models <= have_models


@dataclass(frozen=True)
class SchedulerPick:
    """Result of `Scheduler.pick_for_worker`. The route layer turns this
    into an Assignment + the wire-format work-unit envelope."""

    experiment_id: str
    tenant_id: str
    tenant_experiment_label: str
    manifest_hash: str
    work_unit: WorkUnit


class Scheduler:
    def __init__(
        self,
        experiment_repository: ExperimentRepository,
        per_job_factory: PerJobDatabaseFactory,
        account_suspended_for_tenant: Callable[[str], bool] | None = None,
    ):
        self._experiments = experiment_repository
        self._per_job_factory = per_job_factory
        # F5 (accountability cascade): resolves an experiment's owning tenant to
        # its account's suspension state. A suspended account's already-APPROVED
        # experiments stop dispatching (no burning volunteer compute on a
        # suspended account's work) — the dispatch-side complement to the
        # researcher-surface 403. None ⇒ no cascade (legacy / tests).
        self._account_suspended_for_tenant = account_suspended_for_tenant

    def pick_for_worker(self, worker: Worker) -> SchedulerPick | None:
        """Return the first eligible (experiment_id, work_unit) pair, or
        None if no work is available for this worker."""
        # M4: a paused worker is an operational pause — the scheduler offers it
        # nothing until unpaused (distinct from quarantine, which 423s at the
        # assignment route).
        if worker.paused_at is not None:
            return None
        # M5 (W-H increment 2): a worker reporting thermal-critical in its last
        # heartbeat is degraded — its results would diverge from quorum (throttled
        # host) and it just refused/aborted work locally. Route around it until it
        # cools and reports OK again. Analogous to the pause/quarantine skips.
        if worker_is_degraded(worker):
            return None
        # §2.1 #11: a volunteer self-paused worker is routed around too (owner's
        # hold — resource-owner sovereignty). Distinct from the operator pause.
        if worker_is_self_paused(worker):
            return None

        for experiment in self._experiments.list_all(status=ExperimentStatus.APPROVED):
            # #30 (M1): skip the whole experiment when this worker lacks a model
            # it requires (the requirement is experiment-level, derived from the
            # manifest at submit). Empty requirement ⇒ satisfied (pre-M1 behavior).
            if not worker_satisfies(
                worker,
                experiment.required_capabilities,
                requires_real_execution=experiment.requires_real_execution,
                required_containment=experiment.required_containment,
            ):
                continue
            # F5: halt dispatch for a suspended account's experiments. Approval
            # is not a forever-pass — if the accountability root is suspended,
            # the network stops spending volunteer compute on its work until
            # unsuspension (no experiment state change; resumes on unsuspend).
            if (
                self._account_suspended_for_tenant is not None
                and self._account_suspended_for_tenant(experiment.tenant_id)
            ):
                continue
            per_job_db = self._per_job_factory.get(experiment.experiment_id)
            if per_job_db is None:
                continue
            work_units = WorkUnitRepository(per_job_db)
            assignments = AssignmentRepository(per_job_db)

            if experiment.max_concurrent_assignments is not None:
                total_active = assignments.count_active_for_experiment()
                if total_active >= experiment.max_concurrent_assignments:
                    continue

            from auspexai_platform.db.models import WorkUnitStatus

            candidates: list[WorkUnit] = []
            candidates.extend(work_units.list_all(status=WorkUnitStatus.PENDING))
            candidates.extend(work_units.list_all(status=WorkUnitStatus.IN_PROGRESS))

            for unit in candidates:
                # M4-tail pin / force-assign: a pinned unit is offered ONLY to
                # its pinned worker (the maintainer override). Other workers skip
                # it; the pinned worker takes it through the normal eligibility
                # path below (replication-count, not tier — D9 Phase 4).
                if unit.pinned_worker_id is not None and unit.pinned_worker_id != worker.worker_id:
                    continue
                # §2.1 #8 (dispatch-retry): an existing assignment row only
                # blocks re-offer when it's active (still working / completed)
                # or terminally/exhaustedly refused. A retryable refusal under
                # the attempt cap stays eligible — the route reactivates the row.
                existing = assignments.get_for_unit_and_worker(unit.unit_id, worker.worker_id)
                if existing is not None and not reoffer_eligible(existing):
                    continue
                # C16: a stale-ACTIVE row (lost-delivery re-offer) already occupies
                # its replication slot — re-delivering it attaches no new worker, so
                # the capacity check applies only to NEW pairings and refused-row
                # re-arms (a refused row's slot was released to other workers, and
                # count_active excludes it — the check below still protects it).
                occupies_slot = existing is not None and existing.refused_at is None
                if (
                    not occupies_slot
                    and assignments.count_active_for_unit(unit.unit_id) >= unit.replication_target
                ):
                    continue
                return SchedulerPick(
                    experiment_id=experiment.experiment_id,
                    tenant_id=experiment.tenant_id,
                    tenant_experiment_label=experiment.tenant_experiment_label,
                    manifest_hash=experiment.manifest_hash,
                    work_unit=unit,
                )
        return None
