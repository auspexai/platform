"""Tier-eligibility calculator (M7f).

Implements the §6.2 "tier promotion logic [that] inspects receipt history
at thresholds" — as a **read-only signal**, not as an auto-promotion
mechanism.

Per Principles & Scope §6.2 (revised 2026-05-24), T2 promotion requires
both receipt-history thresholds AND an identity gate (§6.2.1 Maintainer
verification OR §6.2.2 vouching by T2+) AND Maintainer approval. This
module produces the read-only eligibility signal; the actual tier-bump
is performed by the §6.2.3 promote endpoint.

Eligibility shape returned for each future tier:

    {
        "tier": 2,
        "tier_name": "T2 vouched",
        "receipt_threshold_met": bool,
        "distinct_experiments_threshold_met": bool,
        "thresholds": {"receipts": int, "distinct_experiments": int},
        "actuals": {"receipts": int, "distinct_experiments": int},
        "identity_check_pending": True,   # always True pre-§6.1 milestones
        "vouching_pending": True,         # always True pre-vouching milestone
        "ready_for_human_review": bool,
            # True iff all *automated* gates pass AND no automatic blockers
            # (currently == receipt + distinct-experiments gates). The
            # identity / vouching gates are NEVER auto-satisfied; the
            # human review step verifies them.
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field

from auspexai_platform.db.models import Account, TrustTier, Vouch
from auspexai_platform.db.repositories import ReceiptIndexRepository


@dataclass(frozen=True)
class EligibilityThresholds:
    """Threshold values per tier, sourced from Config."""

    t2_receipt_threshold: int
    t2_distinct_experiments: int


@dataclass(frozen=True)
class IdentityGateStatus:
    """Status of the §6.2.1 / §6.2.2 identity gate for one account."""

    satisfied: bool
    method: str | None = None  # "verified" or "vouched"
    verified_by: str | None = None
    verification_method: str | None = None
    vouched_by: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TierEligibility:
    """Eligibility status for one specific tier.

    A maintainer reads this to decide whether to perform the tier bump
    via POST /accounts/{id}/actions/promote (§6.2.3).
    """

    tier: int
    tier_name: str
    receipt_threshold_met: bool
    distinct_experiments_threshold_met: bool
    thresholds: dict[str, int]
    actuals: dict[str, int]
    identity_check_pending: bool
    vouching_pending: bool
    identity_gate: IdentityGateStatus
    ready_for_human_review: bool


@dataclass(frozen=True)
class ReceiptStats:
    """Aggregate stats for one account's receipt history, plus eligibility
    readouts for each future tier."""

    account_id: str
    current_tier: int
    current_tier_name: str
    total_receipts: int
    distinct_experiments: int
    distinct_tenants: int
    first_receipt_at: str | None  # ISO 8601 or None if no receipts
    last_receipt_at: str | None
    eligibility_by_tier: list[TierEligibility] = field(default_factory=list)


_TIER_NAMES = {
    0: "T0 anonymous",
    1: "T1 authenticated",
    2: "T2 trusted",
    3: "T3 vetted",
}


def _tier_name(tier: int) -> str:
    return _TIER_NAMES.get(tier, f"T{tier}")


def _compute_identity_gate(
    account: Account | None,
    active_vouches: list[Vouch],
) -> IdentityGateStatus:
    """Determine whether the identity gate is satisfied for an account."""
    if account is not None and account.identity_verified_at is not None:
        return IdentityGateStatus(
            satisfied=True,
            method="verified",
            verified_by=account.identity_verified_by,
            verification_method=(
                account.identity_verification_method.value
                if account.identity_verification_method
                else None
            ),
        )
    if active_vouches:
        return IdentityGateStatus(
            satisfied=True,
            method="vouched",
            vouched_by=[v.voucher_account_id for v in active_vouches],
        )
    return IdentityGateStatus(satisfied=False)


def compute_t2_eligibility(
    *,
    receipt_count: int,
    distinct_experiments: int,
    thresholds: EligibilityThresholds,
    account: Account | None = None,
    active_vouches: list[Vouch] | None = None,
) -> TierEligibility:
    """Compute T1→T2 eligibility given an account's aggregates + identity state."""
    receipt_met = receipt_count >= thresholds.t2_receipt_threshold
    distinct_met = distinct_experiments >= thresholds.t2_distinct_experiments
    identity_gate = _compute_identity_gate(account, active_vouches or [])
    return TierEligibility(
        tier=int(TrustTier.T2_TRUSTED),
        tier_name=_tier_name(int(TrustTier.T2_TRUSTED)),
        receipt_threshold_met=receipt_met,
        distinct_experiments_threshold_met=distinct_met,
        thresholds={
            "receipts": thresholds.t2_receipt_threshold,
            "distinct_experiments": thresholds.t2_distinct_experiments,
        },
        actuals={
            "receipts": receipt_count,
            "distinct_experiments": distinct_experiments,
        },
        identity_check_pending=account is None or account.identity_verified_at is None,
        vouching_pending=not bool(active_vouches),
        identity_gate=identity_gate,
        ready_for_human_review=(
            receipt_met and distinct_met and identity_gate.satisfied
        ),
    )


def compute_receipt_stats(
    *,
    account_id: str,
    current_tier: int,
    receipt_index_repository: ReceiptIndexRepository,
    thresholds: EligibilityThresholds,
    account: Account | None = None,
    active_vouches: list[Vouch] | None = None,
) -> ReceiptStats:
    """Aggregate one account's receipt history + render the eligibility readout
    for every future tier (currently just T2; T3 lands when T3-bound vetting
    machinery is designed).
    """
    entries = receipt_index_repository.list_for_account(account_id)
    distinct_experiment_ids = {e.experiment_id for e in entries}
    distinct_tenant_count = len(distinct_experiment_ids)  # upper-bound placeholder

    first_at = entries[-1].issued_at.isoformat() if entries else None
    last_at = entries[0].issued_at.isoformat() if entries else None

    eligibility_by_tier: list[TierEligibility] = []
    if current_tier < int(TrustTier.T2_TRUSTED):
        eligibility_by_tier.append(
            compute_t2_eligibility(
                receipt_count=len(entries),
                distinct_experiments=len(distinct_experiment_ids),
                thresholds=thresholds,
                account=account,
                active_vouches=active_vouches,
            )
        )

    return ReceiptStats(
        account_id=account_id,
        current_tier=current_tier,
        current_tier_name=_tier_name(current_tier),
        total_receipts=len(entries),
        distinct_experiments=len(distinct_experiment_ids),
        distinct_tenants=distinct_tenant_count,
        first_receipt_at=first_at,
        last_receipt_at=last_at,
        eligibility_by_tier=eligibility_by_tier,
    )
