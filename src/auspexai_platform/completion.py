"""Completion predicates shared by the auto-complete paths.

An experiment's compute is *done* when it reaches its maintainer-set `max_units`
cap — the coordinator won't accept more work units past it, so the fleet goes
idle. This is a clean quota end, distinct from a genuinely-short run whose driver
died mid-feed. Historically completion depended on the driver calling
`finalize_submissions`; when the driver died at the cap the run stranded in
APPROVED forever. Making "reached the cap" a first-class completion trigger keeps
wrap-up a coordinator responsibility that never depends on a live driver.

Single source of truth so the view layer (`api/activity.py` phase badge), the
result-submit auto-complete (`api/assignments.py`), and the settle-sweep backstop
(`maintenance.py`) all agree on what "capped" means.
"""

from __future__ import annotations

# A run stops at the last full round that fits under the cap, so its final
# submitted-unit count lands within one round *below* max_units — never exactly
# at it. Treat "within a round of the cap" as capped. Generous per-round
# allowance; the `> 2 * MARGIN` floor keeps a genuinely tiny run (whose whole
# quota is within a round of zero) from ever reading capped.
CAP_ROUND_MARGIN = 24


def reached_unit_cap(max_units: int | None, total_units: int) -> bool:
    """True when `total_units` submitted work units sits within a final round of
    the maintainer-set `max_units` cap — the quota-reached end state.

    False when no cap is set, the cap is too small to distinguish a round from
    the whole run, or the submitted count falls short of the cap by more than a
    round (a genuinely-short run — its driver stopped early, not at the cap)."""
    return bool(
        max_units
        and max_units > 2 * CAP_ROUND_MARGIN
        and total_units >= max_units - CAP_ROUND_MARGIN
    )
