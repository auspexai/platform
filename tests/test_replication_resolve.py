"""C14: resolve_replication — (target, floor) decoupled from the {1,3,5} ladder.

repl-2 is now expressible (the old ladder rounded it to 3, stalling a 2-worker fleet);
the tier floor still floors both; integrity_policy is a derived coarse label.
"""

from __future__ import annotations

from auspexai_platform.db.models import IntegrityPolicy, TrustTier
from auspexai_platform.scheduler import resolve_replication


def test_repl_2_is_expressible_no_roundup() -> None:
    # T2 tenant (floor 1) requesting repl-2 → exactly 2 (the old ladder rounded to 3).
    assert resolve_replication(
        requested_target=2, requested_floor=None, tenant_tier=TrustTier.T2_TRUSTED
    ) == (2, 2, IntegrityPolicy.STANDARD)


def test_tier_floor_floors_both() -> None:
    # T0 (floor 3) requesting repl-2 → floored to 3 (anonymous work needs more corroboration).
    assert resolve_replication(
        requested_target=2, requested_floor=None, tenant_tier=TrustTier.T0_ANONYMOUS
    ) == (3, 3, IntegrityPolicy.STANDARD)


def test_t1_default_is_the_floor_not_rounded() -> None:
    # T1 (floor 2), default request (1) → 2, NOT rounded up to 3 (the decouple's point).
    assert resolve_replication(
        requested_target=1, requested_floor=None, tenant_tier=TrustTier.T1_AUTHENTICATED
    ) == (2, 2, IntegrityPolicy.STANDARD)


def test_floor_never_exceeds_target() -> None:
    target, floor, _ = resolve_replication(
        requested_target=2, requested_floor=5, tenant_tier=TrustTier.T2_TRUSTED
    )
    assert (target, floor) == (2, 2)


def test_derived_labels() -> None:
    assert (
        resolve_replication(
            requested_target=5, requested_floor=3, tenant_tier=TrustTier.T2_TRUSTED
        )[2]
        is IntegrityPolicy.HIGH
    )
    assert (
        resolve_replication(
            requested_target=1, requested_floor=1, tenant_tier=TrustTier.T2_TRUSTED
        )[2]
        is IntegrityPolicy.TRUSTED
    )
