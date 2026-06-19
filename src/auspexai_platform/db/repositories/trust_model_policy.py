"""TrustModelPolicyRepository — the firewall #1 equal-trust FLIP toggle (A2).

Single-row table (id = 1, seeded DISABLED by migration 0036). The trust-accrual
path reads `equal_trust_enabled` server-authoritatively: FALSE (the default) =
trust from agreement only (current convergence-gradient model); TRUE = trust from
process-attestation guarded by STRICT containment OR the reputation floor, with
divergent-but-guarded results earning divergence receipts
(a2_equal_trust_flip_design.md).

`get()` is fail-safe toward the CURRENT model: a missing row (older DB, pre-0036)
reads as DISABLED, so the absence of the table never silently flips trust
semantics — the flip is only ever an explicit maintainer action gated on A7.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class TrustModelPolicy:
    equal_trust_enabled: bool
    updated_at: datetime | None = None
    updated_by: str | None = None
    update_reason: str | None = None


# Fail-safe default when the row is absent: the current convergence-gradient
# model (the flip is OFF until an explicit, A7-gated activation).
_DEFAULT = TrustModelPolicy(equal_trust_enabled=False)


class TrustModelPolicyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self) -> TrustModelPolicy:
        rows = self.db.execute(
            "SELECT equal_trust_enabled, updated_at, updated_by, update_reason "
            "FROM trust_model_policy WHERE id = 1"
        )
        if not rows:
            return _DEFAULT
        row = rows[0]
        return TrustModelPolicy(
            equal_trust_enabled=bool(row["equal_trust_enabled"]),
            updated_at=_parse_ts(row["updated_at"]) if row["updated_at"] else None,
            updated_by=row["updated_by"],
            update_reason=row["update_reason"],
        )

    def set(
        self,
        *,
        equal_trust_enabled: bool,
        updated_by: str,
        reason: str | None = None,
    ) -> TrustModelPolicy:
        """Upsert the single policy row. The audit trail (written by the route)
        records who/what/when/state; enabling additionally requires a reason and
        carries a gate-warning (the flip is the A7-gated firewall-#1 activation)."""
        self.db.execute(
            """
            INSERT INTO trust_model_policy
                (id, equal_trust_enabled, updated_at, updated_by, update_reason)
            VALUES (1, ?, CURRENT_TIMESTAMP, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                equal_trust_enabled = excluded.equal_trust_enabled,
                updated_at          = excluded.updated_at,
                updated_by          = excluded.updated_by,
                update_reason       = excluded.update_reason
            """,
            (1 if equal_trust_enabled else 0, updated_by, reason),
        )
        return self.get()


def _parse_ts(raw: str) -> datetime:
    # SQLite CURRENT_TIMESTAMP yields "YYYY-MM-DD HH:MM:SS"; isoformat writes use "T".
    if " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)
