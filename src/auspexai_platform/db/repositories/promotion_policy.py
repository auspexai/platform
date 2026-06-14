"""PromotionPolicyRepository — the §6.2 per-transition promotion mode.

Single-row table (id = 1, seeded `manual` by migration 0032 — human-in-the-loop
is the ratified default, governance charter §6 decision 3). `_maybe_auto_promote`
reads `t1_t2_mode` server-authoritatively; the operator console writes it. The
mode is the ONLY runtime knob — the numeric thresholds the gates compare against
are versioned config (AUSPEXAI_TIER_T2_*), so "what T2 means" changes only via a
reviewable deploy, while the operational manual/auto switch is a console click.

`get()` is fail-safe toward human control: a missing row (older DB, pre-0032)
reads as `manual`, so the absence of the table never silently enables
auto-promotion — when in doubt, the human decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.database import Database

# The two ratified §6.2 promotion modes for T1->T2. T2->T3 is always manual and
# is not represented in this table.
PROMOTION_MODE_MANUAL = "manual"
PROMOTION_MODE_AUTO = "auto_with_override"
PROMOTION_MODES = frozenset({PROMOTION_MODE_MANUAL, PROMOTION_MODE_AUTO})


@dataclass(frozen=True)
class PromotionPolicy:
    t1_t2_mode: str
    updated_at: datetime | None = None
    updated_by: str | None = None
    update_reason: str | None = None

    @property
    def auto_promote_t1_t2(self) -> bool:
        return self.t1_t2_mode == PROMOTION_MODE_AUTO


# Fail-safe default when the row is absent: human-in-the-loop (charter §6
# decision 3) — when in doubt, do NOT auto-promote.
_DEFAULT = PromotionPolicy(t1_t2_mode=PROMOTION_MODE_MANUAL)


class PromotionPolicyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self) -> PromotionPolicy:
        rows = self.db.execute(
            "SELECT t1_t2_mode, updated_at, updated_by, update_reason "
            "FROM promotion_policy WHERE id = 1"
        )
        if not rows:
            return _DEFAULT
        row = rows[0]
        return PromotionPolicy(
            t1_t2_mode=row["t1_t2_mode"],
            updated_at=_parse_ts(row["updated_at"]) if row["updated_at"] else None,
            updated_by=row["updated_by"],
            update_reason=row["update_reason"],
        )

    def set(
        self,
        *,
        t1_t2_mode: str,
        updated_by: str,
        reason: str | None = None,
    ) -> PromotionPolicy:
        """Upsert the single policy row. Raises ValueError on an unknown mode.
        The audit trail (written by the route) records who/what/when/state."""
        if t1_t2_mode not in PROMOTION_MODES:
            raise ValueError(
                f"invalid t1_t2_mode {t1_t2_mode!r}; expected one of {sorted(PROMOTION_MODES)}"
            )
        self.db.execute(
            """
            INSERT INTO promotion_policy (id, t1_t2_mode, updated_at, updated_by, update_reason)
            VALUES (1, ?, CURRENT_TIMESTAMP, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                t1_t2_mode    = excluded.t1_t2_mode,
                updated_at    = excluded.updated_at,
                updated_by    = excluded.updated_by,
                update_reason = excluded.update_reason
            """,
            (t1_t2_mode, updated_by, reason),
        )
        return self.get()


def _parse_ts(raw: str) -> datetime:
    # SQLite CURRENT_TIMESTAMP yields "YYYY-MM-DD HH:MM:SS"; isoformat writes use "T".
    if " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)
