"""Scheduler — picks the next work unit for a worker on demand (M6d).

Pull model: workers call `GET /workers/{id}/assignments` after each
heartbeat; the scheduler returns at most one assignment per call (one
unit at a time per worker for v0). No background loops, no push, no
SSE — those are M8 concerns.

Algorithm: **capacity-aware RESERVATION scheduling** (0062). A worker is reserved
to at most one experiment at a time, so an admitted experiment runs UNINTERRUPTED
on a stable worker set — no mid-run model reloads (which would confound a drift
measurement) and no per-unit thrash when concurrent experiments demand more distinct
models than the constrained fleet can hold. Experiments that can't be granted a
worker QUEUE (approved, "queued" phase) until a reservation frees.

Each poll `_reconcile`s the reservation set against the LIVE fleet, model-agnostic and
with no a-priori model knowledge:
  1. RELEASE stale — a reservation whose worker went inactive (pause / retire / no
     heartbeat) or whose experiment ended, so a departed worker is never left pegged
     to a maybe-finished run and stranded.
  2. TOP UP — an admitted experiment left under its replication target (a worker left)
     reserves a free replacement, so it CONTINUES on another worker rather than hangs.
  3. ADMIT — approved experiments with no reservation reserve free FITTING workers.
     Bin-packing: place the MOST STRUCTURALLY SCARCE experiment first (fewest fitting
     workers; the reconcile-local form of capacity.eligible_capable_count), FIFO within
     equal scarcity; and give each run its LEAST-CONTENDED fitting workers (fewest other
     runs want them), smallest-capacity as the tiebreak — so a versatile worker is only
     handed out when nothing scarcer needs it. Capacity is the gate: an experiment with
     no free fitting worker stays queued; the replication FLOOR governs completion (via
     the C14 regimes in settle_sweep), not admission.
  4. RECLAIM — regime-aware bounded preemption (the late-arrival fix). A run still below
     floor after admission may take a fitting worker W from a holder E, but ONLY when E
     stays STRUCTURALLY VIABLE without W (>= floor(E) other fitting workers exist, so E
     recovers elsewhere) AND E is structurally LESS scarce than the starved run. Safe by
     construction and non-cyclic (a worker only moves toward the strictly-scarcer run). It
     is the only case bin-packing can't reach — a scarce worker granted before the run
     that uniquely needs it existed. Regimes untouched; only the reservation re-points.
`pick_for_worker` then serves only the experiment that reserved the polling worker.
Legacy first-fit-with-affinity remains when no reservation store is wired (tests).

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

import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    Assignment,
    ExperimentStatus,
    IntegrityPolicy,
    TrustTier,
    Worker,
    WorkUnit,
    WorkUnitStatus,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    WorkUnitRepository,
)
from auspexai_platform.hf_catalog import _LOAD_OVERHEAD

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


def worker_model_download(worker: Worker, model_ids: Collection[str]) -> dict | None:
    """The furthest-along IN-FLIGHT download on `worker` for one of `model_ids`,
    shaped `{model_id, bytes_downloaded, total_bytes, pct}` (the same shape the
    prestage `progress_for_models` returns), or None when the worker reports no
    matching in-flight pull.

    The worker declares `capabilities["downloads"]` = `{model_id:
    {bytes_downloaded, total_bytes}}` in every heartbeat (D12 5c) for whatever it
    is pulling RIGHT NOW — covering both an eager prestage and a lazy in-line
    auto-acquire. A sample that has reached its total (done >= total) is COMPLETE,
    not in flight, so it drops out (the model is about to serve). `pct` is None
    until a sample with a known total lands."""
    downloads = worker.capabilities.get("downloads")
    if not isinstance(downloads, dict) or not model_ids:
        return None
    wanted = set(model_ids)
    best: dict | None = None
    for model_id, prog in downloads.items():
        if model_id not in wanted or not isinstance(prog, dict):
            continue
        done = prog.get("bytes_downloaded") or 0
        total = prog.get("total_bytes")
        if total is not None and done >= total:
            continue  # complete — not in flight
        pct = round(done / total * 100, 1) if (done is not None and total) else None
        cand = {
            "model_id": model_id,
            "bytes_downloaded": done,
            "total_bytes": total,
            "pct": pct,
        }
        if best is None or (cand["pct"] or -1) > (best["pct"] or -1):
            best = cand
    return best


def worker_is_provisioning(worker: Worker, model_ids: Collection[str]) -> bool:
    """True if `worker` has an in-flight download of one of `model_ids` — it is
    PROVISIONING to serve, so an active assignment on it is progressing toward a
    result, not a lost offer or a stall. THE shared root fact for "is this
    assignment making no progress?": the re-delivery lease
    (`assignment_presumed_lost`) and the maintainer stall alarm
    (`_stalled_unit_experiments`) both consult it, so a downloading worker never
    trips either — a multi-GB first-serve is expected, not an incident."""
    return worker_model_download(worker, model_ids) is not None


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
    worker_provisioning: bool = False,
    redelivery_lease_seconds: float = ASSIGNMENT_REDELIVERY_LEASE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """C16: True for an ACTIVE row (no result, no refusal) older than the
    re-delivery lease — the offer response was presumably lost in flight and
    the worker never learned of its assignment. A fresh active row is presumed
    delivered (the worker may be executing right now).

    `worker_provisioning` (the shared root guard): when the assigned worker is
    still DOWNLOADING a required model (`worker_is_provisioning`), the offer was
    not lost — the worker is provisioning to serve, and a multi-GB first-serve
    legitimately outlasts the lease. Such a row is never presumed lost (no
    re-delivery churn to a worker that already holds the unit)."""
    if assignment.result_id is not None or assignment.refused_at is not None:
        return False
    if worker_provisioning:
        return False
    assigned_at = assignment.assigned_at
    if assigned_at.tzinfo is None:
        assigned_at = assigned_at.replace(tzinfo=UTC)
    age = ((now or datetime.now(UTC)) - assigned_at).total_seconds()
    return age > redelivery_lease_seconds


def reoffer_eligible(
    assignment: Assignment,
    *,
    worker_provisioning: bool = False,
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
        # to a pairing that never lands). A worker still provisioning the model
        # is NOT presumed lost (worker_provisioning), so it's left to deliver.
        return assignment.attempt_count < max_attempts and assignment_presumed_lost(
            assignment,
            worker_provisioning=worker_provisioning,
            redelivery_lease_seconds=redelivery_lease_seconds,
            now=now,
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
    required_capabilities: dict[str, Any],
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
            # Apply the SAME load overhead the catalog's runnability check uses
            # (hf_catalog._LOAD_OVERHEAD): serving a model needs headroom beyond its
            # raw weights (KV cache + compute/CUDA buffers). Gating on the bare
            # footprint routed mistral-7b-q4 (5.25 GB) onto a 5.44 GB-usable Jetson
            # that then 500s at load ("unable to allocate CUDA0 buffer"), bouncing
            # the unit between workers instead of falling through to a bigger box.
            if isinstance(fp, (int, float)) and worker_ram < fp * _LOAD_OVERHEAD:
                return False
    if worker.capabilities.get("auto_acquire") is True:
        return True
    have = worker.capabilities.get("models", [])
    have_models = set(have) if isinstance(have, list) else set()
    return required_models <= have_models


def _caps_with_footprints(
    required_capabilities: dict[str, Any], footprints: dict[str, float]
) -> dict[str, Any]:
    """`required_capabilities` with `model_ram_gb` backfilled from the fleet-authoritative
    `footprints` (the larger of submit-time and fleet-known is kept). So a submit-time HF
    sizing miss can't leave a required model unsized → no fall-open."""
    required = required_capabilities.get("models") or []
    if not required or not footprints:
        return required_capabilities
    ram = dict(required_capabilities.get("model_ram_gb") or {})
    changed = False
    for mid in required:
        fp = footprints.get(mid)
        if fp is not None and fp > ram.get(mid, 0.0):
            ram[mid] = fp
            changed = True
    return {**required_capabilities, "model_ram_gb": ram} if changed else required_capabilities


def serve_fits(
    worker: Worker,
    required_capabilities: dict[str, Any],
    *,
    requires_real_execution: bool = False,
    required_containment: str = CONTAINMENT_PERMISSIVE,
    footprints: dict[str, float] | None = None,
    oom: dict[str, float] | None = None,
    recovered: set[tuple[str, str]] | None = None,
) -> bool:
    """THE single runnability verdict — "can this worker SERVE these required capabilities" —
    shared by routing (`Scheduler._fits`) and the C14 regime capacity model
    (`capacity._eligible`), so the two can never disagree about what fits where. Three inputs,
    matching the availability catalog's fit verdict:

      1. `worker_satisfies` — models held/acquirable, features, containment, provisioned-mode,
         and the submit-time RAM gate;
      2. `footprints` — fleet-authoritative on-disk sizes backfilled into `model_ram_gb`, so a
         submit-time sizing MISS can't leave a model unsized and fall open (`auto_acquire →
         fits`); and
      3. `oom` — observed-OOM ground truth: a worker with usable <= a model's largest
         OOM'd-usable can't serve it, whatever the estimate said (`<= thr` matches the
         catalog's `r > thr`).

    `recovered` — {(worker_id, model_id)} pairs a REMEDIATED worker may retry despite (3):
    its operator freed memory / restarted the backend after the OOM, so this one worker
    shadows the model-level exclusion (a one-shot probe; a re-OOM lifts it). Surgical, so a
    node's fix never re-offers the model to other, un-remediated nodes.

    `footprints`/`oom`/`recovered` default to None (legacy / tests) → the plain
    `worker_satisfies` verdict, so nothing that doesn't wire them changes behavior."""
    caps = (
        _caps_with_footprints(required_capabilities or {}, footprints)
        if footprints
        else (required_capabilities or {})
    )
    if not worker_satisfies(
        worker,
        caps,
        requires_real_execution=requires_real_execution,
        required_containment=required_containment,
    ):
        return False
    if oom:
        wram = worker.capabilities.get("usable_memory_gb")
        if not isinstance(wram, (int, float)):
            wram = worker.capabilities.get("ram_total_gb")
        if isinstance(wram, (int, float)):
            for mid in caps.get("models") or []:
                thr = oom.get(mid)
                if thr is not None and wram <= thr:
                    # A remediated worker shadows the model-level exclusion for itself.
                    if recovered and (worker.worker_id, mid) in recovered:
                        continue
                    return False
    return True


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
        active_workers: Callable[[], list[Worker]] | None = None,
        reservation_repository=None,
        oom_thresholds: Callable[[], dict[str, float]] | None = None,
        recent_oom_sizes: Callable[[], dict[str, float]] | None = None,
        recovery_shadows: Callable[[], set[tuple[str, str]]] | None = None,
    ):
        self._experiments = experiment_repository
        self._per_job_factory = per_job_factory
        # Observed-OOM ground truth: () -> {model_id: largest usable-GB seen to OOM}. Routing
        # excludes a worker at/below a model's OOM threshold (the same override the catalog
        # applies), so an OOM-prone model is never offered to a too-small worker. None ⇒ no
        # override (legacy / tests).
        self._oom_thresholds = oom_thresholds
        # SOFT placement signal: () -> {model_id: largest usable-GB RECENTLY OOM'd at},
        # ungated by rate/runway. Placement PREFERS a worker the model doesn't OOM on when one
        # is free, so a flaky-on-small model lands on the big box that would otherwise idle
        # instead of maximising its OOM exposure. None ⇒ no preference (legacy / tests).
        self._recent_oom_sizes = recent_oom_sizes
        # Per-worker serve-recovery: () -> {(worker_id, model_id)} a remediated worker may
        # retry despite the model-level OOM exclusion (surgical recovery). None ⇒ none.
        self._recovery_shadows = recovery_shadows
        # Capacity-aware scheduling (reservation model): a worker↔experiment store so an
        # admitted experiment runs UNINTERRUPTED on a stable worker set (no mid-run model
        # reloads — which would confound a drift measurement, and no per-unit thrash) and
        # contenders queue. Reconciled against the live fleet each poll. None ⇒ legacy
        # first-fit-with-affinity (tests / no reservation store).
        self._reservations = reservation_repository
        # Constraint-aware ordering: () -> the active fleet, so pick_for_worker offers
        # the SCARCEST-fit work first — a model that fits fewer workers wins the
        # workers that can run it, so a fits-everywhere model yields those scarce
        # slots to a model that can ONLY run there (no starvation; a worker still
        # takes broad work when no constrained work is pending; never idle-reserved).
        # None ⇒ registration-order fallback (legacy / tests).
        self._active_workers = active_workers
        # F5 (accountability cascade): resolves an experiment's owning tenant to
        # its account's suspension state. A suspended account's already-APPROVED
        # experiments stop dispatching (no burning volunteer compute on a
        # suspended account's work) — the dispatch-side complement to the
        # researcher-surface 403. None ⇒ no cascade (legacy / tests).
        self._account_suspended_for_tenant = account_suspended_for_tenant
        # Reconcile is a critical section: it reads the reservation set and then
        # WRITES it (release / reserve). Two overlapping reconciles could both see a
        # worker free and reserve it to different experiments (last-write-wins → one
        # experiment silently loses a worker; churn until the next reconcile heals it).
        # Today the assignment route is `async def`, so `pick_for_worker` runs inline
        # on the single event-loop thread and reconciles never actually overlap — this
        # lock makes that invariant explicit and holds it if the coordinator ever grows
        # a sync/threadpool handler or a background reconcile. Uncontended in the
        # single-threaded case (and in tests), so it is free insurance.
        self._reconcile_lock = threading.Lock()

    def _order_for_worker(self, experiments: list, worker: Worker) -> list:
        """Order approved experiments for THIS worker's next pick, by two keys:

        1. **Scarcest-fit first** (anti-starvation): the model that fits the FEWEST
           active workers is offered first, so a fits-everywhere model yields its
           scarce-worker slots to one that can ONLY run there. (Unchanged.)
        2. **Model affinity** (concurrent-experiment thrash fix): WITHIN equal
           scarcity, prefer an experiment whose model this worker ALREADY has loaded
           (`served_models`). A constrained worker (one model in memory at a time)
           then batches a model's units before switching, so an expensive model
           RELOAD is amortized over a run of units instead of paid PER UNIT when two
           experiments target the same worker with different models. Without this the
           scheduler interleaves them and the worker reloads every unit — the fleet
           spends its time swapping weights, not generating. No researcher-side
           serialization, and no starvation: a model's ready units are finite per
           round, so a worker rotates to the other model once its loaded model runs
           dry (the fleet ends up doing model-A's round, then model-B's round, …).

        Registration (FIFO) order breaks remaining ties. Affinity is worker-local so
        it applies even without a fleet view; scarcity needs the active fleet."""
        if len(experiments) < 2:
            return experiments

        served = set(worker.capabilities.get("served_models") or [])

        def _affinity(exp) -> int:  # 0 = model already loaded HERE (prefer), else 1
            required = set((exp.required_capabilities or {}).get("models") or [])
            return 0 if (required & served) else 1

        if self._active_workers is None:
            return sorted(experiments, key=_affinity)  # affinity only (stable → FIFO tie)
        fleet = self._active_workers()

        def _fit_count(exp) -> int:
            return sum(
                1
                for w in fleet
                if worker_satisfies(
                    w,
                    exp.required_capabilities or {},
                    requires_real_execution=exp.requires_real_execution,
                    required_containment=exp.required_containment,
                )
            )

        return sorted(experiments, key=lambda e: (_fit_count(e), _affinity(e)))

    def _schedulable_fleet(self) -> list[Worker]:
        """Active workers currently eligible to HOLD a reservation — heartbeating and
        not paused / degraded / self-paused. A worker that drops out of this set has its
        reservation released by `_reconcile` (never left pegged to a maybe-finished
        run) and its experiment tops up onto a replacement."""
        if self._active_workers is None:
            return []
        return [
            w
            for w in self._active_workers()
            if w.paused_at is None and not worker_is_degraded(w) and not worker_is_self_paused(w)
        ]

    def _has_outstanding_work(self, experiment_id: str) -> bool:
        """Any PENDING or IN_PROGRESS unit — the run is still ACTIVE (don't release its
        reservations even between rounds). Existence-only (`has_status`, index-backed,
        short-circuited) — never materializes a big experiment's unit rows just to test
        non-emptiness, since this runs per experiment on every poll."""
        per_job = self._per_job_factory.get(experiment_id)
        if per_job is None:
            return False
        wr = WorkUnitRepository(per_job)
        return wr.has_status(WorkUnitStatus.PENDING) or wr.has_status(WorkUnitStatus.IN_PROGRESS)

    def _has_offerable_work(self, experiment_id: str) -> bool:
        """Work a NEW worker could actually take — a PENDING (unassigned) unit, or an
        IN_PROGRESS unit still under its replication target. An experiment whose units
        are all AT capacity needs no more workers, so don't reserve an idle one to it
        (which would leave it idle while a needy run queues). The common PENDING case is
        an index-backed existence check; only the no-pending case walks the (few)
        in-progress units, short-circuiting on the first under-target one."""
        per_job = self._per_job_factory.get(experiment_id)
        if per_job is None:
            return False
        wr = WorkUnitRepository(per_job)
        if wr.has_status(WorkUnitStatus.PENDING):
            return True
        ar = AssignmentRepository(per_job)
        return any(
            ar.count_active_for_unit(u.unit_id) < u.replication_target
            for u in wr.list_all(status=WorkUnitStatus.IN_PROGRESS)
        )

    def _worker_usable(self, worker: Worker) -> float:
        caps = worker.capabilities
        return float(caps.get("usable_memory_gb") or caps.get("ram_total_gb") or 1e9)

    def _fleet_model_footprints(self) -> dict[str, float]:
        """Fleet-authoritative SERVE footprint (GB) per model — the shared size half of the
        runnability verdict (`serve_memory.fleet_reported_footprints`), from the on-disk
        sizes the fleet's workers report. Routing consults this so its fit matches the
        availability catalog's: an experiment whose submit-time HF sizing MISSED (a filename
        case, an HF hiccup, a BYOM model) is still sized from the fleet, instead of the
        scheduler falling OPEN (auto_acquire → 'fits') and false-fitting a 20B onto a 4 GB
        worker. Empty when no fleet view is wired (legacy path)."""
        if self._active_workers is None:
            return {}
        from auspexai_platform.serve_memory import fleet_reported_footprints

        return fleet_reported_footprints(w.capabilities for w in self._active_workers())

    def _oom(self) -> dict[str, float]:
        """Observed-OOM ground truth {model_id: largest usable-GB seen to OOM}. A worker with
        usable <= this can't SERVE the model, whatever the estimate said — the same override
        the availability catalog applies (`ModelServeFailureRepository.oom_thresholds`). Empty
        when not wired (legacy / tests)."""
        return self._oom_thresholds() if self._oom_thresholds is not None else {}

    def _ooomd(self) -> dict[str, float]:
        """Soft placement signal {model_id: largest usable-GB recently OOM'd at}. A worker at
        or below this is a less-reliable place to run the model (deprioritised, not excluded).
        Empty when not wired (legacy / tests)."""
        return self._recent_oom_sizes() if self._recent_oom_sizes is not None else {}

    def _recovered(self) -> set[tuple[str, str]]:
        """Per-worker serve-recovery shadows {(worker_id, model_id)} — a remediated worker may
        retry despite the model-level OOM exclusion. Empty when not wired (legacy / tests).
        Tiny tables (only remediated workers), so `_fits` fetches it lazily per call."""
        return self._recovery_shadows() if self._recovery_shadows is not None else set()

    def _fits(
        self,
        worker: Worker,
        exp,
        fleet_fp: dict[str, float] | None = None,
        oom: dict[str, float] | None = None,
        recovered: set[tuple[str, str]] | None = None,
    ) -> bool:
        # Routing's fit is the SHARED `serve_fits` verdict (footprint-backfill + worker_satisfies
        # + observed-OOM + per-worker recovery), the same one the C14 regime capacity model uses
        # via capacity._eligible — so routing and regime can never disagree about what fits where.
        return serve_fits(
            worker,
            exp.required_capabilities or {},
            requires_real_execution=exp.requires_real_execution,
            required_containment=exp.required_containment,
            footprints=fleet_fp,
            oom=oom,
            recovered=recovered if recovered is not None else self._recovered(),
        )

    def _reconcile(self, polling: Worker | None = None) -> None:
        """Keep the reservation set in sync with the LIVE fleet + experiment state.
        Runs each poll. Three moves, in order:

          1. RELEASE stale — a reservation whose worker went inactive (pause / retire /
             no heartbeat) or whose experiment ended (terminal, or no outstanding work).
             A paused/offline worker is never left pegged to a finished run.
          2. TOP UP — an admitted experiment now UNDER its replication target (a worker
             left) reserves a free FITTING replacement, so it CONTINUES rather than
             hangs. Continuity beats new admission → runs before step 3.
          3. ADMIT — an approved experiment with NO reservation reserves free fitting
             workers, in fair (FIFO) order, ONLY IF the replication floor can be met
             (never partial — a below-floor reservation just stalls). Smallest-capacity
             workers first, so a scarce model keeps the big/scarce workers it needs.

        No fleet view or reservation store ⇒ no-op (legacy path). Runs under
        `_reconcile_lock` so its release→reserve writes are atomic against a
        concurrent poll."""
        if self._reservations is None or self._active_workers is None:
            return
        with self._reconcile_lock:
            self._reconcile_locked(polling)

    def _reconcile_locked(self, polling: Worker | None = None) -> None:
        # Per-pass memo: an experiment's work-state cannot change within one (locked)
        # reconcile, yet the release loop, the approved filter, and the top-up/admit
        # loops all consult it — so each experiment's outstanding/offerable check hits
        # the per-job DB at most once per poll instead of three-plus times.
        _outstanding: dict[str, bool] = {}
        _offerable: dict[str, bool] = {}

        def outstanding(eid: str) -> bool:
            if eid not in _outstanding:
                _outstanding[eid] = self._has_outstanding_work(eid)
            return _outstanding[eid]

        def offerable(eid: str) -> bool:
            if eid not in _offerable:
                _offerable[eid] = self._has_offerable_work(eid)
            return _offerable[eid]

        active_by_id = {w.worker_id: w for w in self._schedulable_fleet()}
        # A worker that is POLLING right now is demonstrably live — include it even if
        # the roster's heartbeat-recency filter hasn't caught its latest beat yet, so it
        # can be reserved on this very poll (it already passed the pause/degraded checks).
        if polling is not None:
            active_by_id[polling.worker_id] = polling
        # Fleet-authoritative model footprints + observed-OOM ground truth — so every
        # fit/scarcity/reclaim decision below sizes a model from what the fleet actually holds
        # AND excludes a worker a model has demonstrably OOM'd on, not the (possibly-missed,
        # possibly-optimistic) submit-time number. Computed once per reconcile; passed to every
        # self._fits.
        fleet_fp = self._fleet_model_footprints()
        oom = self._oom()
        ooomd = self._ooomd()  # soft: worker sizes each model recently OOM'd at (placement pref)

        # 1. release stale
        ended: set[str] = set()
        for worker_id, exp_id in self._reservations.all():
            if worker_id not in active_by_id or exp_id in ended:
                self._reservations.release_worker(worker_id)
                continue
            exp = self._experiments.get_by_id(exp_id)
            terminal = (
                exp is None
                or getattr(exp.status, "value", exp.status) != ExperimentStatus.APPROVED.value
            )
            if terminal or not outstanding(exp_id):
                self._reservations.release_experiment(exp_id)
                ended.add(exp_id)
                continue
            # The worker can no longer SERVE this experiment — e.g. an observed OOM (or a
            # newly-known fleet footprint) just made the model too-big for it. A held-but-
            # unservable reservation would idle the worker (`_pick_unit_from` returns None)
            # AND keep it from a run it CAN serve. Release it so it re-enters the free pool.
            if not self._fits(active_by_id[worker_id], exp, fleet_fp, oom):
                self._reservations.release_worker(worker_id)

        # recompute the free pool + counts after releases
        counts = self._reservations.counts_by_experiment()
        reserved_ids = {wid for wid, _ in self._reservations.all()}
        free = sorted(
            (w for wid, w in active_by_id.items() if wid not in reserved_ids),
            key=self._worker_usable,
        )
        approved = [
            e
            for e in self._experiments.list_all(status=ExperimentStatus.APPROVED)
            if not (
                self._account_suspended_for_tenant is not None
                and self._account_suspended_for_tenant(e.tenant_id)
            )
            and outstanding(e.experiment_id)
        ]
        # Bin-packing, EXPERIMENT order: place the MOST STRUCTURALLY SCARCE run first —
        # fewest fitting workers on the fleet, the reconcile-local form of
        # capacity.eligible_capable_count — FIFO as the tiebreak. The hardest-to-place run
        # reserves its workers before a fits-everywhere run can grab them (best-fit-
        # decreasing; the anti-starvation direction). Floor/capacity is NOT gated here — the
        # ratified C14 regimes (settle_sweep) own below-floor completion/pause.
        fleet_list = list(active_by_id.values())
        approved.sort(
            key=lambda e: (
                sum(1 for w in fleet_list if self._fits(w, e, fleet_fp, oom)),
                getattr(e, "submitted_at", "") or "",
            )
        )
        now = datetime.now(UTC).isoformat()

        def _contention(worker: Worker, exclude_id: str) -> int:
            """Bin-packing signal: how many OTHER approved-with-work experiments could also
            use `worker`. Granting a run its LEAST-contended fitting workers first keeps a
            worker several runs need free for the one with the fewest options — the
            model-agnostic way to conserve scarce/versatile workers (a fits-everywhere box
            is given away only when nothing scarcer wants it)."""
            return sum(
                1
                for e in approved
                if e.experiment_id != exclude_id and self._fits(worker, e, fleet_fp, oom)
            )

        exp_models = {}  # exp_id -> set(required models), memoized for _oom_risk

        def _oom_risk(worker: Worker, exp) -> int:
            """1 if a required model recently OOM'd on a worker THIS SIZE OR SMALLER — a
            less-reliable place to run it (deprioritised, not excluded), so a flaky-on-small
            model prefers a box it doesn't OOM on. 0 when there's no such history."""
            if not ooomd:
                return 0
            models = exp_models.get(exp.experiment_id)
            if models is None:
                models = set((exp.required_capabilities or {}).get("models") or [])
                exp_models[exp.experiment_id] = models
            wram = self._worker_usable(worker)
            return 1 if any(wram <= ooomd.get(m, -1.0) for m in models) else 0

        def _grant(exp, need: int) -> None:
            nonlocal free
            # Bin-packing, WORKER choice: least-contended first (conserve workers other runs
            # need); then RELIABLE first (a worker the model doesn't OOM on, over one it does —
            # so a flaky-on-small model lands on the idle big box, not its worst workers);
            # smallest-capacity as the final conserve tiebreak (keep big boxes for big models).
            fitting = sorted(
                (w for w in free if self._fits(w, exp, fleet_fp, oom)),
                key=lambda w: (
                    _contention(w, exp.experiment_id),
                    _oom_risk(w, exp),
                    self._worker_usable(w),
                ),
            )
            grant = fitting[:need]
            for w in grant:
                self._reservations.reserve(w.worker_id, exp.experiment_id, now=now)
            granted = {w.worker_id for w in grant}
            free = [w for w in free if w.worker_id not in granted]

        # 2. top up admitted runs (continuity before new admissions)
        for exp in approved:
            have = counts.get(exp.experiment_id, 0)
            target = int(getattr(exp, "replication_target", 1) or 1)
            if have > 0 and target - have > 0 and offerable(exp.experiment_id):
                _grant(exp, target - have)

        # 3. admit queued runs — reserve whatever fitting workers are free (up to
        #    target). CAPACITY is the gate, not the floor: the floor governs COMPLETION
        #    (regime-2 capacity-aware completion), not dispatch, so an admitted run makes
        #    progress with what it has and tops up later. An experiment with no free
        #    fitting worker grants 0 → stays queued (the fleet is fully committed); one
        #    with no OFFERABLE unit (all at capacity) needs no worker.
        for exp in approved:
            if counts.get(exp.experiment_id, 0) > 0:
                continue
            if not offerable(exp.experiment_id):
                continue
            _grant(exp, int(getattr(exp, "replication_target", 1) or 1))

        # 4. RECLAIM — regime-aware, bounded preemption; the late-arrival fix (design §4.3).
        #    A run still below its floor after admission (its fitting workers are all held by
        #    others) may take a fitting worker W from its current holder E, but ONLY when that
        #    is SAFE by the ratified C14 regime model:
        #      (a) E stays STRUCTURALLY VIABLE without W — E still has >= floor(E) OTHER
        #          fitting workers on the fleet, so E is merely TEMPORALLY using W and will
        #          recover elsewhere (regime-3 won't strand it — `eligible_capable_count`
        #          excluding W, computed reconcile-locally over fleet_list); AND
        #      (b) E is structurally LESS scarce (more fitting workers) than the starved run,
        #          so a worker only ever moves TOWARD the run that needs it most.
        #    (a)+(b) make it safe-by-construction and NON-CYCLIC: a strictly-scarcer run wins
        #    a worker from one with more options, so the loser can never reclaim it back (it
        #    isn't scarcer) — no ping-pong, no deadlock. This is the ONLY case bin-packing
        #    (step 3) cannot reach: a scarce worker granted before the run that uniquely needs
        #    it existed (the 3-second-late arrival). Regimes are untouched; only the
        #    reservation is re-pointed. Reclaim to FLOOR (the minimum to make progress); the
        #    rest toward target is left to opportunistic top-up.
        def _structural(e) -> int:
            return sum(1 for w in fleet_list if self._fits(w, e, fleet_fp, oom))

        for exp in approved:
            floor_exp = int(getattr(exp, "replication_floor", 1) or 1)
            if counts.get(exp.experiment_id, 0) >= floor_exp:
                continue  # not starved below floor
            if not offerable(exp.experiment_id):
                continue
            exp_fit = [w for w in fleet_list if self._fits(w, exp, fleet_fp, oom)]
            if not exp_fit:
                continue  # structurally unrunnable — regime-3's job, not reclaim's
            exp_scarcity = len(exp_fit)
            held_now = dict(self._reservations.all())  # worker_id -> holder experiment_id
            for w in exp_fit:
                if counts.get(exp.experiment_id, 0) >= floor_exp:
                    break
                holder_id = held_now.get(w.worker_id)
                if holder_id is None or holder_id == exp.experiment_id:
                    continue  # free (step 3 would have taken it) or already ours
                holder = self._experiments.get_by_id(holder_id)
                if holder is None:
                    continue
                # (b) reclaim only from a holder with strictly MORE options than the starved run.
                if _structural(holder) <= exp_scarcity:
                    continue
                # (a) holder must remain structurally viable WITHOUT w (>= its own floor).
                holder_floor = int(getattr(holder, "replication_floor", 1) or 1)
                holder_without_w = sum(
                    1
                    for w2 in fleet_list
                    if w2.worker_id != w.worker_id and self._fits(w2, holder, fleet_fp, oom)
                )
                if holder_without_w < holder_floor:
                    continue
                # Safe: re-point w from the holder to the starved run.
                self._reservations.reserve(w.worker_id, exp.experiment_id, now=now)
                held_now[w.worker_id] = exp.experiment_id
                counts[exp.experiment_id] = counts.get(exp.experiment_id, 0) + 1
                counts[holder_id] = counts.get(holder_id, 0) - 1

    def pick_for_worker(self, worker: Worker) -> SchedulerPick | None:
        """The next unit for `worker`, or None. With a reservation store: reconcile the
        fleet, then serve ONLY the experiment that reserved this worker (exclusive → no
        mid-run reload); an unreserved worker idles until admitted. Without one: the
        legacy first-fit-with-affinity walk."""
        # A paused / thermally-degraded / self-paused worker is offered nothing.
        if worker.paused_at is not None:
            return None
        if worker_is_degraded(worker):
            return None
        if worker_is_self_paused(worker):
            return None

        if self._reservations is not None:
            self._reconcile(worker)
            exp_id = self._reservations.experiment_for_worker(worker.worker_id)
            if exp_id is None:
                return None  # unreserved — fleet at capacity; idle until admitted
            experiment = self._experiments.get_by_id(exp_id)
            if (
                experiment is None
                or getattr(experiment.status, "value", experiment.status)
                != ExperimentStatus.APPROVED.value
            ):
                self._reservations.release_worker(worker.worker_id)
                return None
            if (
                self._account_suspended_for_tenant is not None
                and self._account_suspended_for_tenant(experiment.tenant_id)
            ):
                return None
            return self._pick_unit_from(experiment, worker)

        # Legacy first-fit-with-affinity (no reservation store — tests).
        approved = self._experiments.list_all(status=ExperimentStatus.APPROVED)
        for experiment in self._order_for_worker(approved, worker):
            if (
                self._account_suspended_for_tenant is not None
                and self._account_suspended_for_tenant(experiment.tenant_id)
            ):
                continue
            pick = self._pick_unit_from(experiment, worker)
            if pick is not None:
                return pick
        return None

    def idle_reason_for_worker(self, worker: Worker) -> dict[str, Any] | None:
        """WHY `worker` has no assignment right now — for the volunteer's dashboard, so a
        healthy-but-idle node reads as "understood", not "broken/stuck". Read-only +
        best-effort: returns None (stay silent) on any error, and None for the paused/
        degraded states the endpoint already surfaces via 423. Codes: no_pending_work ·
        between_rounds · reserved_elsewhere · model_benched · insufficient_ram."""
        try:
            if (
                worker.paused_at is not None
                or worker_is_degraded(worker)
                or worker_is_self_paused(worker)
            ):
                return None  # already surfaced by the endpoint's own 423 paths
            approved = self._experiments.list_all(status=ExperimentStatus.APPROVED)
            pending = [e for e in approved if self._has_offerable_work(e.experiment_id)]
            if not pending:
                return {
                    "code": "no_pending_work",
                    "message": "No work is waiting on the network right now — nothing to do.",
                }
            if (
                self._reservations is not None
                and self._reservations.experiment_for_worker(worker.worker_id) is not None
            ):
                return {
                    "code": "between_rounds",
                    "message": "Assigned to an experiment; waiting for its next round of work.",
                }
            fp, oom, recovered = (
                self._fleet_model_footprints(),
                self._oom(),
                self._recovered(),
            )
            if any(self._fits(worker, e, fp, oom, recovered) for e in pending):
                return {
                    "code": "reserved_elsewhere",
                    "message": (
                        "Work you can run is reserved to other workers right now; "
                        "you'll be assigned as capacity frees up."
                    ),
                }
            # Nothing fits this worker — surface the most useful SPECIFIC reason.
            wram = self._worker_usable(worker)
            benched: str | None = None
            too_big: tuple[str, float] | None = None
            for e in pending:
                caps = e.required_capabilities or {}
                declared = caps.get("model_ram_gb") or {}
                for mid in caps.get("models") or []:
                    thr = oom.get(mid)
                    if thr is not None and wram <= thr and (worker.worker_id, mid) not in recovered:
                        benched = mid
                    needed = fp.get(mid) or declared.get(mid)
                    if needed and wram < float(needed):
                        too_big = (mid, float(needed))
            if benched is not None:
                return {
                    "code": "model_benched",
                    "model_id": benched,
                    "message": (
                        f"'{benched}' is paused on this node after repeated out-of-memory — it "
                        "will retry automatically. Freeing memory (sudo sync && drop_caches) or a "
                        "serve-stack restart lets it retry right away."
                    ),
                }
            if too_big is not None:
                mid, needed = too_big
                return {
                    "code": "insufficient_ram",
                    "model_id": mid,
                    "message": (
                        f"The waiting work needs about {needed:.1f} GB to serve '{mid}'; this "
                        f"worker has ~{wram:.1f} GB, so it runs on larger workers."
                    ),
                }
            return {
                "code": "reserved_elsewhere",
                "message": "No waiting work fits this worker right now.",
            }
        except Exception:
            return None

    def _pick_unit_from(self, experiment, worker: Worker) -> SchedulerPick | None:
        """The first eligible unit of `experiment` for `worker`, or None — capability +
        capacity + re-offer eligibility. Reused by the reservation path (the worker's
        reserved experiment) and the legacy walk."""
        # #30 (M1): the worker must hold (or auto-acquire) the experiment's models — sized
        # against the fleet-authoritative footprint (same as routing), so a worker too small
        # to SERVE the model is never actually assigned it even if it holds the file on disk.
        if not self._fits(worker, experiment, self._fleet_model_footprints(), self._oom()):
            return None
        per_job_db = self._per_job_factory.get(experiment.experiment_id)
        if per_job_db is None:
            return None
        work_units = WorkUnitRepository(per_job_db)
        assignments = AssignmentRepository(per_job_db)
        if (
            experiment.max_concurrent_assignments is not None
            and assignments.count_active_for_experiment() >= experiment.max_concurrent_assignments
        ):
            return None
        candidates: list[WorkUnit] = []
        candidates.extend(work_units.list_all(status=WorkUnitStatus.PENDING))
        candidates.extend(work_units.list_all(status=WorkUnitStatus.IN_PROGRESS))
        # Still pulling a required model? An active row on it is provisioning, not a
        # lost offer — don't re-deliver (churn) while the multi-GB first-serve finishes.
        worker_prov = worker_is_provisioning(
            worker, (experiment.required_capabilities or {}).get("models") or []
        )
        for unit in candidates:
            # M4-tail pin: a pinned unit is offered ONLY to its pinned worker.
            if unit.pinned_worker_id is not None and unit.pinned_worker_id != worker.worker_id:
                continue
            # §2.1 #8 (dispatch-retry): an active/terminal row blocks re-offer; a
            # retryable refusal under the attempt cap stays eligible.
            existing = assignments.get_for_unit_and_worker(unit.unit_id, worker.worker_id)
            if existing is not None and not reoffer_eligible(
                existing, worker_provisioning=worker_prov
            ):
                continue
            # C16: a stale-ACTIVE re-offer already occupies its replication slot, so the
            # capacity check applies only to NEW pairings and refused-row re-arms.
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
