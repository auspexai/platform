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
    integrity_policy: IntegrityPolicy | str, tenant_tier: TrustTier | int
) -> dict[str, Any]:
    """The replication policy in force + its firewall-#4 provenance: `tier_floored`
    (the policy sits exactly at the tenant tier's floor — A') and `sub_floor` (the
    policy is below the floor, only reachable via an audited force override)."""
    policy = IntegrityPolicy(integrity_policy)
    return {
        "integrity_policy": policy.value,
        "replication_factor": INTEGRITY_POLICY_REPLICATION.get(policy),
        "tier_floored": policy == policy_floor_for_tier(tenant_tier),
        "sub_floor": is_sub_floor_policy(policy, tenant_tier),
    }


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
    entries,
    diverged_units,
) -> dict[str, Any]:
    """Assemble the full `governance_footprint` dict (firewall #2 §4). Pure: the
    caller resolves the asserted inputs from the DBs; the recomputable
    integrity_basis counts come from `entries` + `diverged_units`."""
    return {
        "schema_version": FOOTPRINT_SCHEMA_VERSION,
        "tenant": {"tier": tier_label(tenant_tier), "identity_gate": identity_gate},
        "replication": replication_footprint(integrity_policy, tenant_tier),
        "approval": {
            "experiment": approval_experiment,  # "auto" | "human"
            "assessment": assessment,  # {research_class, tier, envelope} | None
            "promotion": {"tier_set_by": promotion_tier_set_by},  # "system"|"maintainer"|None
        },
        "independence": independence,
        "integrity_basis": {"counts": integrity_basis_counts(entries, diverged_units)},
    }


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
