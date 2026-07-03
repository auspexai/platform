"""Firewall #2 — the governance footprint (apparatus provenance on the evidence).

See `firewall_2_apparatus_footprint_design.md`. A coordinator-asserted,
COSE-signed block embedded in the attestation predicate (and the EB-1 bundle that
echoes it), researcher-facing. Two halves:

  - RECOMPUTABLE — the integrity_basis distribution + per-unit corroborating
    workers; a verifier re-derives them from the signed receipts/results and they
    must match (F6). `assert_footprint_recomputable` is the coordinator's
    sign-time guard against an internally-inconsistent footprint (D1-family:
    never sign a claim that diverges from the data).
  - COORDINATOR-ASSERTED — tenant tier + identity gate, replication policy +
    A'/force provenance, the auto-vs-human approval/promotion path, and
    account-level consensus-set independence. Trustworthy because COSE-signed.

Records, does NOT enforce: independence *thresholds* are firewall #3; the trust
decoupling is firewall #1; this only states the conditions.
"""

from __future__ import annotations

import json
from typing import Any

from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    IntegrityPolicy,
    TrustTier,
)
from auspexai_platform.receipts.attestation import (
    INTEGRITY_BASIS_DIVERGED,
    INTEGRITY_BASIS_EXACT,
    INTEGRITY_BASIS_PROCESS_ONLY,
    INTEGRITY_BASIS_TOLERANCE,
)
from auspexai_platform.scheduler import is_sub_floor_policy, policy_floor_for_tier

FOOTPRINT_SCHEMA_VERSION = 1

# Account-level independence is the honest axis today: a worker binds to an
# account, not to an attested distinct host. Host-attested operator identity is a
# firewall #3 addition — the footprint never over-claims host diversity.
INDEPENDENCE_BASIS_ACCOUNT = "account-level"


class FootprintRecomputeError(Exception):
    """The footprint's recomputable half (integrity_basis counts) diverges from a
    fresh recount of the attested set — refuse to sign (F6)."""

    def __init__(self, claimed: dict, recounted: dict) -> None:
        self.claimed = claimed
        self.recounted = recounted
        super().__init__(
            f"footprint integrity_basis counts diverge: claimed={claimed} recounted={recounted}"
        )


def integrity_basis_counts(entries, diverged_units) -> dict[str, int]:
    """Recomputable: the per-result corroboration-basis distribution over the
    attested set. Consensus entries carry their basis; each diverged unit counts
    once as `diverged`. Keys are always present (zeros) so the shape is stable."""
    counts = {
        INTEGRITY_BASIS_EXACT: 0,
        INTEGRITY_BASIS_TOLERANCE: 0,
        INTEGRITY_BASIS_PROCESS_ONLY: 0,
        INTEGRITY_BASIS_DIVERGED: 0,
    }
    for e in entries or []:
        if e.integrity_basis in counts:
            counts[e.integrity_basis] += 1
    counts[INTEGRITY_BASIS_DIVERGED] += len(diverged_units or [])
    return counts


def replication_footprint(
    integrity_policy: IntegrityPolicy | str,
    tenant_tier: TrustTier | int,
    *,
    replication_target: int | None = None,
    replication_floor: int | None = None,
) -> dict[str, Any]:
    """The replication policy in force + its firewall-#4 provenance: `tier_floored`
    (the policy sits exactly at the tenant tier's floor — A') and `sub_floor` (the
    policy is below the floor, only reachable via an audited force override).

    AUD-5 (A9 audit): the signed `replication_target`/`replication_floor` now report
    the experiment's ACTUAL values (C14 migration 0040 — the decoupled source of
    truth), not the coarse `INTEGRITY_POLICY_REPLICATION` map (which signed e.g. 3
    for a repl-2 experiment). `integrity_policy` stays the descriptive label;
    `replication_factor` is kept as a back-compat alias = the real target. The
    policy-map is the fallback only when a target wasn't supplied (legacy callers)."""
    policy = IntegrityPolicy(integrity_policy)
    target = (
        replication_target
        if replication_target is not None
        else INTEGRITY_POLICY_REPLICATION.get(policy)
    )
    return {
        "integrity_policy": policy.value,
        "replication_target": target,
        "replication_floor": replication_floor,
        "replication_factor": target,  # back-compat alias; now the real target, not the map
        "tier_floored": policy == policy_floor_for_tier(tenant_tier),
        "sub_floor": is_sub_floor_policy(policy, tenant_tier),
    }


def generation_footprint(manifest: dict[str, Any] | None) -> dict[str, Any]:
    """Firewall #2 / v0.2 M1 Inc 3: the generation policy the SIGNED MANIFEST
    declared — `greedy` vs `seeded_sampling` plus the declared params — so a
    researcher can interpret agreement/divergence in kind (sampled replicas
    legitimately differ; greedy replicas should not). Coordinator-asserted from
    the stored manifest; the worker enforces the same declaration per-request,
    so declared == actual for any result that ingressed. Always present, stable
    shape: mode + (params only when a block was declared)."""
    det = (manifest or {}).get("inference_determinism")
    det = det if isinstance(det, dict) else {}
    try:
        is_sampling = float(det.get("temperature", 0) or 0) > 0
    except (TypeError, ValueError):
        is_sampling = False
    out: dict[str, Any] = {"mode": "seeded_sampling" if is_sampling else "greedy"}
    params = {
        k: det[k]
        for k in ("temperature", "seed", "top_p", "top_k", "min_p", "serving_version_pin")
        if det.get(k) is not None
    }
    if params:
        out["params"] = params
    return out


def compute_independence(per_job_db, worker_account_resolver) -> dict[str, Any]:
    """Account-level consensus-set independence over the AGREEING results (every
    result of a consensus unit — they all agreed; `promote_consensus` just picks a
    durable copy). `distinct_workers` is recomputable (distinct pubkeys);
    `distinct_accounts`/`distinct_served_models` are coordinator-asserted (need the
    control worker→account map + the environment snapshot). `worker_account_resolver`
    maps worker_id → account_id (None for unlinked T0 workers)."""
    rows = per_job_db.execute(
        "SELECT unit_id, worker_id, worker_pubkey_hex, environment_json FROM results "
        "WHERE unit_id IN (SELECT unit_id FROM results WHERE is_consensus = 1)"
    )
    pubkeys: set[str] = set()
    accounts: set[str] = set()
    served: set[str] = set()
    per_unit_workers: dict[str, set[str]] = {}
    per_unit_accounts: dict[str, set[str]] = {}
    for r in rows:
        uid = r["unit_id"]
        pk = (r["worker_pubkey_hex"] or "").lower()
        pubkeys.add(pk)
        per_unit_workers.setdefault(uid, set()).add(pk)
        acct = worker_account_resolver(r["worker_id"])
        if acct:
            accounts.add(acct)
            per_unit_accounts.setdefault(uid, set()).add(acct)
        digest = _served_model_digest(r["environment_json"])
        if digest:
            served.add(digest)
    return {
        "basis": INDEPENDENCE_BASIS_ACCOUNT,
        "distinct_accounts": len(accounts),
        "distinct_workers": len(pubkeys),
        "distinct_served_models": len(served),
        "per_unit": {
            "min_distinct_accounts": min((len(v) for v in per_unit_accounts.values()), default=0),
            "min_distinct_workers": min((len(v) for v in per_unit_workers.values()), default=0),
        },
    }


def _served_model_digest(environment_json: str | None) -> str | None:
    """Best-effort served-weights identity from the environment snapshot — the
    #13a `served_model_digests`/`gguf_sha256` field if present. Absent ⇒ skipped
    (served-model independence is best-effort until #13a is enforced fleet-wide)."""
    if not environment_json:
        return None
    try:
        env = json.loads(environment_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(env, dict):
        return None
    val = env.get("served_model_digests") or env.get("gguf_sha256")
    if isinstance(val, dict):
        return json.dumps(val, sort_keys=True)
    return str(val) if val else None


def collect_ran_under_containment(per_job_db, policy_resolver) -> list[str]:
    """§41 / firewall #2: the distinct sandbox policies the consensus workers
    actually ran this experiment under — so the footprint records WHICH
    containment produced the evidence, not just the consensus. `policy_resolver`
    maps worker_id → its reported sandbox policy ('permissive' for an old worker
    that doesn't report one)."""
    rows = per_job_db.execute(
        "SELECT DISTINCT worker_id FROM results "
        "WHERE unit_id IN (SELECT unit_id FROM results WHERE is_consensus = 1)"
    )
    return sorted({policy_resolver(r["worker_id"]) or "permissive" for r in rows})


def tier_label(tenant_tier: TrustTier | int) -> str:
    """`T0`..`T3` from the int-valued TrustTier."""
    return f"T{int(tenant_tier)}"


def assemble_governance_footprint(
    *,
    tenant_tier: TrustTier | int,
    identity_gate: str,
    integrity_policy: IntegrityPolicy | str,
    approval_experiment: str,
    assessment: dict[str, Any] | None,
    promotion_tier_set_by: str | None,
    independence: dict[str, Any],
    containment: dict[str, Any],
    entries,
    diverged_units,
    replication_target: int | None = None,  # AUD-5: the real C14 (target, floor)
    replication_floor: int | None = None,
    generation: dict[str, Any] | None = None,  # v0.2 M1 Inc 3 (None = legacy caller)
) -> dict[str, Any]:
    """Assemble the full `governance_footprint` dict (firewall #2 §4). Pure: the
    caller resolves the asserted inputs from the DBs; the recomputable
    integrity_basis counts come from `entries` + `diverged_units`."""
    footprint = {
        "schema_version": FOOTPRINT_SCHEMA_VERSION,
        "tenant": {"tier": tier_label(tenant_tier), "identity_gate": identity_gate},
        "replication": replication_footprint(
            integrity_policy,
            tenant_tier,
            replication_target=replication_target,
            replication_floor=replication_floor,
        ),
        "approval": {
            "experiment": approval_experiment,  # "auto" | "human"
            "assessment": assessment,  # {research_class, tier, envelope} | None
            "promotion": {"tier_set_by": promotion_tier_set_by},  # "system"|"maintainer"|None
        },
        "independence": independence,
        # §41: the sandbox isolation REQUIRED of this experiment + what it actually
        # RAN under, so a researcher can correct for containment as apparatus.
        "containment": containment,
        "integrity_basis": {"counts": integrity_basis_counts(entries, diverged_units)},
    }
    # v0.2 M1 Inc 3: the declared generation policy (greedy vs seeded-sampling),
    # so agreement/divergence is interpretable in kind. Additive + optional so
    # legacy callers/verifiers are untouched.
    if generation is not None:
        footprint["generation"] = generation
    return footprint


def assert_footprint_recomputable(footprint, entries, diverged_units) -> None:
    """F6 sign-time guard: a fresh recount of integrity_basis over the attested set
    must equal the footprint's claim, or refuse to sign (the consumer-side SDK then
    re-checks independently against the signed predicate). No-op when there is no
    footprint."""
    if not footprint:
        return
    claimed = ((footprint.get("integrity_basis") or {}).get("counts")) or {}
    recounted = integrity_basis_counts(entries, diverged_units)
    if {k: claimed.get(k, 0) for k in recounted} != recounted:
        raise FootprintRecomputeError(claimed=claimed, recounted=recounted)
