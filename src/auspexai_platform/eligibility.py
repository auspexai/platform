"""Tier-eligibility calculator (M7f).

Implements the §6.2 "tier promotion logic [that] inspects receipt history
at thresholds" — as a **read-only signal**, not as an auto-promotion
mechanism.

Per Principles & Scope §6.1, T2 promotion requires a real-identity check
OR vouching by an existing T2+ — neither of which is built yet. Per §6.2,
T2+ promotions "may require human review." So this module produces a
structured eligibility readout that lets maintainers (or, later, the
Approver pool) see at a glance which receipt-history gates are satisfied
and which §6.1 identity gates remain.

The actual tier-bump action lives in a future milestone bundled with the
vouching / identity-verification work. M7f does not write to the
accounts table.

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

from auspexai_platform.db.models import TrustTier
from auspexai_platform.db.repositories import ReceiptIndexRepository


@dataclass(frozen=True)
class EligibilityThresholds:
    """Threshold values per tier, sourced from Config."""

    t2_receipt_threshold: int
    t2_distinct_experiments: int


@dataclass(frozen=True)
class TierEligibility:
    """Eligibility status for one specific tier.

    A maintainer reads this to decide whether to perform the §6.1 identity
    check + tier bump (via a future endpoint that does NOT exist yet).
    """

    tier: int
    tier_name: str
    receipt_threshold_met: bool
    distinct_experiments_threshold_met: bool
    thresholds: dict[str, int]
    actuals: dict[str, int]
    identity_check_pending: bool  # always True until §6.1 machinery ships
    vouching_pending: bool  # always True until vouching machinery ships
    ready_for_human_review: bool  # True iff all automatic gates pass


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
    1: "T1 verified",
    2: "T2 vouched",
    3: "T3 trusted",
    4: "T4 maintainer",
}


def _tier_name(tier: int) -> str:
    return _TIER_NAMES.get(tier, f"T{tier}")


def compute_t2_eligibility(
    *,
    receipt_count: int,
    distinct_experiments: int,
    thresholds: EligibilityThresholds,
) -> TierEligibility:
    """Compute T1→T2 eligibility given an account's aggregates.

    The receipt + distinct-experiments thresholds are the only AUTOMATIC
    gates per §6.2. The §6.1 identity / vouching gates are listed as
    `_pending=True` to signal the maintainer still has work to do; they
    never flip to False from automatic checks.
    """
    receipt_met = receipt_count >= thresholds.t2_receipt_threshold
    distinct_met = distinct_experiments >= thresholds.t2_distinct_experiments
    return TierEligibility(
        tier=int(TrustTier.T2_VOUCHED),
        tier_name=_tier_name(int(TrustTier.T2_VOUCHED)),
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
        # Always pending — §6.1 identity check / vouching milestones not yet shipped.
        identity_check_pending=True,
        vouching_pending=True,
        ready_for_human_review=receipt_met and distinct_met,
    )


def compute_receipt_stats(
    *,
    account_id: str,
    current_tier: int,
    receipt_index_repository: ReceiptIndexRepository,
    thresholds: EligibilityThresholds,
) -> ReceiptStats:
    """Aggregate one account's receipt history + render the eligibility readout
    for every future tier (currently just T2; T3 lands when T3-bound vetting
    machinery is designed).
    """
    entries = receipt_index_repository.list_for_account(account_id)
    distinct_experiment_ids = {e.experiment_id for e in entries}
    # `tenant_id` isn't stored on the receipt_index row (intentional — keeps
    # the index small). At the M7f reporting layer we'd need a JOIN through
    # experiments to compute distinct_tenants. For Phase 1 lab altitude we
    # report distinct_experiments (which is a stricter cut anyway — multiple
    # experiments per tenant means distinct_tenants ≤ distinct_experiments).
    # Wiring distinct_tenants properly is a small follow-up if needed.
    distinct_tenant_count = len(distinct_experiment_ids)  # upper-bound placeholder

    first_at = entries[-1].issued_at.isoformat() if entries else None
    last_at = entries[0].issued_at.isoformat() if entries else None

    eligibility_by_tier: list[TierEligibility] = []
    if current_tier < int(TrustTier.T2_VOUCHED):
        eligibility_by_tier.append(
            compute_t2_eligibility(
                receipt_count=len(entries),
                distinct_experiments=len(distinct_experiment_ids),
                thresholds=thresholds,
            )
        )
    # T3 eligibility deliberately omitted at M7f — the §6.1 T3 requirement
    # ("personally vetted, often institutional affiliation") doesn't yet
    # have a thresholded shape we can report on. The T3 milestone designs
    # its own readout.

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
