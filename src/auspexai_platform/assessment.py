"""§9 #48 — experiment admission policy: class x tenant-tier auto-approval.

Pure functions, no DB/IO. The `POST /experiments/{id}/assessment` endpoint and
(later) the operator console call these so the decision + its provenance are
computed in ONE place. The taxonomy mirrors the ratified §11 research classes;
a drift-guard test asserts equality with `api.tenant_applications.RESEARCH_CLASSES`.

The construction guarantee: an elevated-ethics class or a sub-threshold tenant
can NEVER yield `auto` here — and the endpoint re-runs `decide()` server-side,
so the (future) agent cannot widen the gate by proposing a decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from auspexai_platform.db.models import ResearchStanding, TrustTier

# The §11 taxonomy (single source = api.tenant_applications.RESEARCH_CLASSES;
# duplicated here for clean layering, guarded by a drift test).
RESEARCH_CLASSES: tuple[str, ...] = (
    "behavioral_drift",
    "eval_sweeps",
    "refusal_boundary_mapping",
    "cross_model_comparison",
    "quantization_effects",
    "prompt_sensitivity",
    "other",
)
# Routine = auto-approvable for a trusted tenant after envelope checks. NB
# cross_model_comparison auto-approves for BEHAVIORAL scope only (§11 amd 2);
# performance-ranking is gated behind served-weights-digest enforcement (#13).
ROUTINE_CLASSES: frozenset[str] = frozenset(
    {
        "behavioral_drift",
        "eval_sweeps",
        "quantization_effects",
        "prompt_sensitivity",
        "cross_model_comparison",
    }
)
# Elevated-ethics = ALWAYS human review (§11 amd 1); never auto-approve.
ELEVATED_CLASSES: frozenset[str] = frozenset({"refusal_boundary_mapping"})

# Ratified 2026-06-13: auto-approval requires the tenant's account at >= T2.
AUTO_APPROVE_TIER: TrustTier = TrustTier.T2_TRUSTED


def class_track(research_class: str | None) -> str:
    """`routine` | `elevated` | `unknown` — `unknown` covers None, "other", and
    any unrecognized value (all → human review)."""
    if research_class in ELEVATED_CLASSES:
        return "elevated"
    if research_class in ROUTINE_CLASSES:
        return "routine"
    return "unknown"


@dataclass(frozen=True)
class EnvelopeCheck:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class EnvelopeResult:
    checks: list[EnvelopeCheck]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[str]:
        return [c.name for c in self.checks if not c.passed]

    def as_json(self) -> list[dict[str, Any]]:
        return [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks]


def assess_envelope(
    *,
    manifest_json: dict[str, Any],
    research_class: str | None,
    tenant_approved_classes: list[str] | None,
    served_model_ids: set[str] | None = None,
    max_units_cap: int | None = None,
) -> EnvelopeResult:
    """Mechanical, deterministic gates evaluated before any agent reasoning. A
    failed check forces human review (never a silent auto-approve). Optional
    inputs (`served_model_ids`, `max_units_cap`) are recorded as not-evaluated
    when absent rather than silently passing a missing gate."""
    checks: list[EnvelopeCheck] = []

    known = research_class in RESEARCH_CLASSES
    checks.append(
        EnvelopeCheck("class_known", known, "" if known else f"{research_class!r} not in taxonomy")
    )

    # Bounded by the tenant's approved application classes (a tenant cleared only
    # for drift cannot sail a jailbreak study through). No recorded approved set
    # (legacy tenants) ⇒ not evaluated.
    if tenant_approved_classes:
        in_scope = research_class in tenant_approved_classes
        checks.append(
            EnvelopeCheck(
                "class_in_tenant_scope",
                bool(in_scope),
                "" if in_scope else f"{research_class!r} not in approved {tenant_approved_classes}",
            )
        )
    else:
        checks.append(EnvelopeCheck("class_in_tenant_scope", True, "tenant has no recorded scope"))

    pkg = (manifest_json.get("executor") or {}).get("package_sha256")
    pinned = isinstance(pkg, str) and len(pkg) == 64
    checks.append(
        EnvelopeCheck("package_pinned", pinned, "" if pinned else "missing package_sha256")
    )

    flags = manifest_json.get("sensitive_content_flags") or []
    routine = class_track(research_class) == "routine"
    no_sensitive = not (routine and flags)
    checks.append(
        EnvelopeCheck(
            "routine_no_sensitive_flags",
            no_sensitive,
            "" if no_sensitive else f"routine class carries {flags}",
        )
    )

    model_ids = [m.get("id") for m in (manifest_json.get("models") or [])]
    if served_model_ids is not None:
        servable = bool(model_ids) and all(mid in served_model_ids for mid in model_ids)
        missing = [m for m in model_ids if m not in served_model_ids]
        checks.append(
            EnvelopeCheck(
                "model_servable", servable, "" if servable else f"no worker serves {missing}"
            )
        )
    else:
        checks.append(EnvelopeCheck("model_servable", True, "catalog not evaluated"))

    if max_units_cap is not None:
        declared = manifest_json.get("max_units")
        within = declared is None or int(declared) <= max_units_cap
        checks.append(
            EnvelopeCheck(
                "within_unit_cap", within, "" if within else f"{declared} > cap {max_units_cap}"
            )
        )
    else:
        checks.append(EnvelopeCheck("within_unit_cap", True, "cap not evaluated"))

    return EnvelopeResult(checks)


@dataclass(frozen=True)
class AssessmentDecision:
    decision: str  # "auto" | "review"
    research_class: str | None
    track: str  # routine | elevated | unknown
    tier: int
    envelope: EnvelopeResult
    rationale: str


def decide(
    *,
    research_class: str | None,
    tenant_tier: int,
    envelope: EnvelopeResult,
    auto_tier: TrustTier | int = AUTO_APPROVE_TIER,
    auto_approval_enabled: bool = True,
    certified: bool = False,
    # D9 Phase 4 (§2). Default R2 so this stays policy-neutral for unit tests; the
    # real caller passes the submitting account's research_standing.
    research_standing: int = int(ResearchStanding.R2_ESTABLISHED),
) -> AssessmentDecision:
    """The authoritative admission decision. `auto` requires every envelope check
    to pass, AND one of two INDEPENDENT paths:

      - **certified path** — a certified profile (Ethics §6.7.5 standing approval);
        OR
      - **routine-tier path** — the maintainer's auto-approval gate ON + a routine
        class + tenant tier >= auto_tier.

    The two are deliberately DECOUPLED. Certification is a per-profile, signed,
    standing approval — it is self-sufficient (certify = on, revoke = off) and does
    NOT ride `auto_approval_enabled`. That global switch exists only for the
    *un-vetted* routine-tier path, which trusts a tenant's accrued tier to auto-run
    arbitrary routine experiments and so needs a coarse master enable; a certified
    run, individually vetted + signed, does not. The "safe default" still holds:
    certifying a profile is itself the deliberate, audited maintainer act (a
    signature), so it needs no second global lock.

    `auto_approval_enabled` is the §9 #48-inc4 runtime gate (sourced from
    `AssessmentPolicyRepository`). Default True keeps this pure function
    policy-neutral for unit tests; the SAFE default (OFF) lives in the storage
    row + the endpoint's no-reader fallback, so the routine-tier path can never
    auto-approve until a maintainer turns the gate on."""
    track = class_track(research_class)
    tier_ok = int(tenant_tier) >= int(auto_tier)
    # D9 Phase 4 (§2, warn-but-allow): the routine-tier path runs UNCERTIFIED (own /
    # frontier) code, so it requires research-standing R2 (BYOT). Below R2 → no
    # auto-approval; routed to human review (the maintainer promotes to R2, or
    # approves per-experiment). The CERTIFIED path is EXEMPT — a certified starter
    # auto-clears for any R1+. R-standing is "necessary, never sufficient": it gates
    # auto-approval; the §6 review still decides.
    byot_ok = int(research_standing) >= int(ResearchStanding.R2_ESTABLISHED)
    routine_auto = auto_approval_enabled and track == "routine" and tier_ok and byot_ok
    auto = envelope.passed and (certified or routine_auto)

    if not envelope.passed:
        rationale = f"envelope checks failed ({', '.join(envelope.failures)}) → human review"
    elif certified:
        rationale = "certified profile (§6.7.5 standing approval) → auto-approve (independent of the tier gate)"
    elif not auto_approval_enabled:
        rationale = "routine-tier auto-approval gate is off (maintainer) → human review"
    elif track == "elevated":
        rationale = f"{research_class} is elevated-ethics → human review"
    elif track == "unknown":
        rationale = f"class {research_class!r} is not routine → human review"
    elif not tier_ok:
        rationale = f"tenant tier T{tenant_tier} below T{int(auto_tier)} → human review"
    elif not byot_ok:
        rationale = (
            f"research-standing R{research_standing} below R2 → bringing own "
            "(uncertified) code is BYOT (R2+); routed to human review (promote to R2, "
            "or approve per-experiment)"
        )
    else:
        rationale = (
            f"{research_class} routine + tier T{tenant_tier} >= T{int(auto_tier)} + envelope pass "
            "→ auto-approve"
        )

    return AssessmentDecision(
        decision="auto" if auto else "review",
        research_class=research_class,
        track=track,
        tier=int(tenant_tier),
        envelope=envelope,
        rationale=rationale,
    )
