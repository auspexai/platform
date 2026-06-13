"""AssessmentPolicyRepository — the runtime-tunable §9 #48 auto-approval gate.

A single-row table (id = 1, seeded disabled by migration 0031). `decide()` reads
this server-authoritatively (via a reader injected into the experiments router)
and the operator console writes it. The DEFAULT is disabled: autonomy is opt-in
by the maintainer, never on by deploy.

`get()` is fail-safe: a missing row (older DB, pre-0031) reads as DISABLED, so
the absence of the gate never silently turns auto-approval on.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import TrustTier


@dataclass(frozen=True)
class AssessmentPolicy:
    enabled: bool
    min_tier: int
    updated_at: datetime | None = None
    updated_by: str | None = None
    update_reason: str | None = None


# Fail-safe default when the row is absent: auto-approval OFF, bar at T2.
_DISABLED = AssessmentPolicy(enabled=False, min_tier=int(TrustTier.T2_TRUSTED))


class AssessmentPolicyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self) -> AssessmentPolicy:
        rows = self.db.execute(
            "SELECT auto_approval_enabled, auto_approve_min_tier, updated_at, "
            "updated_by, update_reason FROM assessment_policy WHERE id = 1"
        )
        if not rows:
            return _DISABLED
        row = rows[0]
        return AssessmentPolicy(
            enabled=bool(row["auto_approval_enabled"]),
            min_tier=int(row["auto_approve_min_tier"]),
            updated_at=_parse_ts(row["updated_at"]) if row["updated_at"] else None,
            updated_by=row["updated_by"],
            update_reason=row["update_reason"],
        )

    def set(
        self,
        *,
        enabled: bool,
        min_tier: int,
        updated_by: str,
        reason: str,
    ) -> AssessmentPolicy:
        """Upsert the single policy row. `reason` is mandatory (governance
        action — mirrors every other trust action's recorded reason)."""
        self.db.execute(
            """
            INSERT INTO assessment_policy
                (id, auto_approval_enabled, auto_approve_min_tier, updated_at, updated_by, update_reason)
            VALUES (1, ?, ?, CURRENT_TIMESTAMP, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                auto_approval_enabled = excluded.auto_approval_enabled,
                auto_approve_min_tier = excluded.auto_approve_min_tier,
                updated_at            = excluded.updated_at,
                updated_by            = excluded.updated_by,
                update_reason         = excluded.update_reason
            """,
            (1 if enabled else 0, int(min_tier), updated_by, reason),
        )
        return self.get()


def _parse_ts(raw: str) -> datetime:
    # SQLite CURRENT_TIMESTAMP yields "YYYY-MM-DD HH:MM:SS"; isoformat writes use "T".
    if " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)
