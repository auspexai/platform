"""Firewall #5 — self-observation instrumentation (A5 substrate).

The network instruments *itself* to detect integrity drift (consensus losing
independence, trust over-concentrating, autonomy creeping, vouch-graph capture).
It is OBSERVATIONAL, never a gate — mirrors `footprint.py` (firewall #2): compute
+ return a signal, never enforce policy.

The charter (§4) requires firewall-#5 signals to be **reward-independent** and
**externally verifiable**. Both are met the same way: every signal is computed
**deterministically from data the system already records** (audit_log, accounts,
vouches, workers) — so an external auditor with that data recomputes the same
numbers (verifiable), and the apparatus can't dial a self-asserted figure without
tampering audited records (reward-independent). This module makes NO writes.

This is the SUBSTRATE: the control-DB network signals computable now. Several
return honest empties at single-maintainer scale and grow as the account/tenant
pool does (a5_instrumentation_design.md). DEFERRED (reviewer #4, until there's
signal to measure): cross-experiment aggregation of consensus-independence /
divergence health (per-job scans), time-series persistence, a signed+published
self-observation report, and all dashboards.
"""

from __future__ import annotations

import json
from typing import Any

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import PromotionPolicyRepository

# capabilities_json keys we count diversity over. Worker-declared + opaque to the
# coordinator, so we read defensively (missing/malformed → skipped). Reconcile
# against the worker `Capabilities` dataclass if the set changes.
_DIVERSITY_KEYS = ("os", "arch", "sandbox_policy", "flavor")


def autonomy_signal(db: Database) -> dict[str, Any]:
    """Auto vs manual trust autonomy. Distinguishes `account.auto_promote`
    (SYSTEM) from `account.promote` (MAINTAINER) in the audit log; the ratio is
    the share of T1→T2 promotions made WITHOUT a human. 0.0 when none/manual-mode
    — which is the honest reading while the §9 #48 gate is OFF."""
    rows = db.execute(
        """
        SELECT action, COUNT(*) AS n FROM audit_log
        WHERE action IN ('account.promote', 'account.auto_promote')
        GROUP BY action
        """
    )
    counts = {r["action"]: int(r["n"]) for r in rows}
    auto = counts.get("account.auto_promote", 0)
    manual = counts.get("account.promote", 0)
    total = auto + manual
    return {
        "account_promotions_auto": auto,
        "account_promotions_manual": manual,
        "autonomy_ratio": (auto / total) if total else 0.0,
        "promotion_gate_mode": PromotionPolicyRepository(db).get().t1_t2_mode,
    }


def fleet_diversity_signal(db: Database) -> dict[str, Any]:
    """Diversity of the active worker fleet over worker-declared capability keys.
    Monoculture (all workers identical) is an integrity risk for cross-check; this
    counts distinct values per key. Trivial at one worker, meaningful as the fleet
    grows."""
    rows = db.execute("SELECT capabilities_json FROM workers WHERE retired_at IS NULL")
    distinct: dict[str, set[str]] = {k: set() for k in _DIVERSITY_KEYS}
    active = 0
    for r in rows:
        active += 1
        try:
            caps = json.loads(r["capabilities_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(caps, dict):
            continue
        for k in _DIVERSITY_KEYS:
            v = caps.get(k)
            if isinstance(v, str) and v:
                distinct[k].add(v)
    out: dict[str, Any] = {"active_workers": active}
    for k in _DIVERSITY_KEYS:
        out[f"distinct_{k}"] = len(distinct[k])
    return out


def trust_flow_signal(db: Database) -> dict[str, Any]:
    """Trust-tier distribution across active accounts + the trusted-share
    concentration (T2+ / active). Detects trust over-concentrating in few hands."""
    rows = db.execute(
        "SELECT trust_tier, COUNT(*) AS n FROM accounts WHERE retired_at IS NULL GROUP BY trust_tier"
    )
    histogram = {str(int(r["trust_tier"])): int(r["n"]) for r in rows}
    active = sum(histogram.values())
    trusted = sum(n for tier, n in histogram.items() if int(tier) >= 2)
    return {
        "tier_histogram": histogram,
        "active_accounts": active,
        "trusted_share": (trusted / active) if active else 0.0,
    }


def vouch_topology_signal(db: Database) -> dict[str, Any]:
    """Active vouch-graph shape. Edge/vertex counts plus two capture flags:
    self-vouches (a voucher vouching for itself — shouldn't happen) and mutual
    pairs (A↔B reciprocal vouches — the seed of clique capture). Deep graph
    analysis (SCCs, cycles) is deferred; this is empty until tenant-#2 brings a
    second account into the graph."""
    rows = db.execute(
        "SELECT voucher_account_id, target_account_id FROM vouches WHERE revoked_at IS NULL"
    )
    edges = [(r["voucher_account_id"], r["target_account_id"]) for r in rows]
    edge_set = set(edges)
    self_vouches = sum(1 for v, t in edges if v == t)
    mutual = sum(1 for v, t in edge_set if v < t and (t, v) in edge_set)
    return {
        "active_vouches": len(edges),
        "distinct_vouchers": len({v for v, _ in edges}),
        "distinct_targets": len({t for _, t in edges}),
        "self_vouches": self_vouches,
        "mutual_pairs": mutual,
    }


def divergence_health_signal(db: Database) -> dict[str, Any]:
    """Firewall #5: the network's divergence-vs-agreement rate. A LOW rate can mean
    genuine agreement OR the apparatus SUPPRESSING disagreement (the convergence
    gradient the equal-trust flip removes) — so it is THE metric to watch around the
    flip: removing the trust penalty should let real divergence surface rather than
    be discouraged. Counts DISTINCT units that reached consensus (`receipt_index`)
    vs diverged (`divergence_index`, the #32 trust-index), network-wide — control-DB,
    so no per-job scans; reward-independent + externally verifiable. (Per-experiment
    breakdown lives in the firewall-#2 footprint's `integrity_basis` counts; this is
    the network rollup.)"""
    agree = db.execute(
        "SELECT COUNT(DISTINCT COALESCE(unit_id, receipt_id)) AS n FROM receipt_index"
    )
    diverge = db.execute("SELECT COUNT(DISTINCT unit_id) AS n FROM divergence_index")
    strict_div = db.execute(
        "SELECT COUNT(DISTINCT unit_id) AS n FROM divergence_index WHERE ran_under_strict = 1"
    )
    agreement_units = int(agree[0]["n"]) if agree else 0
    divergence_units = int(diverge[0]["n"]) if diverge else 0
    strict_divergence_units = int(strict_div[0]["n"]) if strict_div else 0
    total = agreement_units + divergence_units
    return {
        "agreement_units": agreement_units,
        "divergence_units": divergence_units,
        "strict_divergence_units": strict_divergence_units,
        "total_terminal_units": total,
        "divergence_rate": (divergence_units / total) if total else 0.0,
    }


def compute_self_observation(db: Database) -> dict[str, Any]:
    """The firewall-#5 self-observation snapshot — the control-DB network signals,
    computed deterministically from recorded data, no writes, no enforcement.
    (Per-experiment consensus-independence aggregation stays deferred; it lives in
    `footprint.compute_independence` per-experiment until cross-experiment rollup is
    built. Divergence health is now a network control-DB signal via the #32
    `divergence_index`.)"""
    return {
        "autonomy": autonomy_signal(db),
        "fleet_diversity": fleet_diversity_signal(db),
        "trust_flow": trust_flow_signal(db),
        "vouch_topology": vouch_topology_signal(db),
        "divergence_health": divergence_health_signal(db),
    }
