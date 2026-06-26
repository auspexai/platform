"""AUD-5 (A9 audit): the firewall-#2 governance footprint signs the experiment's
ACTUAL (replication_target, replication_floor), not the coarse
INTEGRITY_POLICY_REPLICATION map.

Before the fix, a repl-2 experiment whose derived policy label is "standard" signed
replication_factor=3 (the map value) — contradicting the C14 (target, floor) source
of truth (migration 0040). Confirmed live on the keystone exp-_LtpfHNh (signed 3,
DB target=2).
"""

from __future__ import annotations

from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    IntegrityPolicy,
    TrustTier,
)
from auspexai_platform.footprint import replication_footprint


def test_footprint_reports_real_target_not_policy_map():
    # A repl-2 experiment whose derived policy label ("standard") maps to 3 in the
    # old coarse map. The footprint must report the real target (2), not 3.
    fp = replication_footprint(
        IntegrityPolicy.STANDARD,
        TrustTier.T1_AUTHENTICATED,
        replication_target=2,
        replication_floor=2,
    )
    assert fp["replication_target"] == 2
    assert fp["replication_floor"] == 2
    assert fp["replication_factor"] == 2  # back-compat alias = real target, NOT the map's 3
    assert fp["integrity_policy"] == "standard"  # descriptive label preserved


def test_footprint_falls_back_to_policy_map_for_legacy_callers():
    # No target supplied (a pre-C14 caller) → fall back to the coarse map, unchanged.
    fp = replication_footprint(IntegrityPolicy.STANDARD, TrustTier.T1_AUTHENTICATED)
    assert fp["replication_factor"] == INTEGRITY_POLICY_REPLICATION[IntegrityPolicy.STANDARD]
    assert fp["replication_target"] == INTEGRITY_POLICY_REPLICATION[IntegrityPolicy.STANDARD]
