"""AnchorOutcomeRepository — Rekor-anchoring retry / terminal state (0058, A11).

Records per-artifact anchoring FAILURES so the backfill can give up on a
genuinely un-anchorable row (Rekor structurally rejects the kind — a permanent
4xx) while NEVER abandoning one for a transient outage. `terminal` is reached
only after N confirmed PERMANENT rejections; transient failures track `attempts`
for visibility but never go terminal. Cleared on a successful anchor. Mirrors the
receipt_outcomes sibling-table pattern (0057).
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.database import Database


@dataclass(frozen=True)
class AnchorOutcome:
    artifact_type: str
    artifact_id: str
    attempts: int
    permanent_failures: int
    terminal: bool
    last_error: str | None
    first_attempt_at: str
    last_attempt_at: str


class AnchorOutcomeRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record_failure(
        self,
        artifact_type: str,
        artifact_id: str,
        *,
        permanent: bool,
        error: str,
        now: str,
        terminal_after: int,
    ) -> bool:
        """Record one failed anchor attempt. `permanent` = a confirmed Rekor
        rejection (a 4xx that isn't 408/429). The row goes `terminal` once its
        permanent_failures reach `terminal_after`; transient failures increment
        `attempts` only. Returns True iff the row is (now) terminal."""
        err = (error or "")[:500]
        rows = self.db.execute(
            "SELECT attempts, permanent_failures, terminal FROM anchor_outcomes "
            "WHERE artifact_type = ? AND artifact_id = ?",
            (artifact_type, artifact_id),
        )
        if rows:
            attempts = rows[0]["attempts"] + 1
            perm = rows[0]["permanent_failures"] + (1 if permanent else 0)
            terminal = 1 if (rows[0]["terminal"] or perm >= terminal_after) else 0
            self.db.execute(
                "UPDATE anchor_outcomes SET attempts = ?, permanent_failures = ?, terminal = ?, "
                "last_error = ?, last_attempt_at = ? WHERE artifact_type = ? AND artifact_id = ?",
                (attempts, perm, terminal, err, now, artifact_type, artifact_id),
            )
        else:
            perm = 1 if permanent else 0
            terminal = 1 if perm >= terminal_after else 0
            self.db.execute(
                "INSERT INTO anchor_outcomes (artifact_type, artifact_id, attempts, "
                "permanent_failures, terminal, last_error, first_attempt_at, last_attempt_at) "
                "VALUES (?, ?, 1, ?, ?, ?, ?, ?)",
                (artifact_type, artifact_id, perm, terminal, err, now, now),
            )
        return terminal == 1

    def terminal_ids(self, artifact_type: str) -> set[str]:
        """The artifact_ids the backfill has given up on — skip them so they are
        not re-submitted to Rekor forever."""
        rows = self.db.execute(
            "SELECT artifact_id FROM anchor_outcomes WHERE artifact_type = ? AND terminal = 1",
            (artifact_type,),
        )
        return {r["artifact_id"] for r in rows}

    def clear(self, artifact_type: str, artifact_id: str) -> None:
        """Drop retry state after a successful anchor (transient state self-heals)."""
        self.db.execute(
            "DELETE FROM anchor_outcomes WHERE artifact_type = ? AND artifact_id = ?",
            (artifact_type, artifact_id),
        )

    def list_terminal(self) -> list[AnchorOutcome]:
        """All terminally-un-anchorable artifacts (for an operator report)."""
        rows = self.db.execute(
            "SELECT * FROM anchor_outcomes WHERE terminal = 1 ORDER BY last_attempt_at DESC"
        )
        return [
            AnchorOutcome(
                artifact_type=r["artifact_type"],
                artifact_id=r["artifact_id"],
                attempts=r["attempts"],
                permanent_failures=r["permanent_failures"],
                terminal=bool(r["terminal"]),
                last_error=r["last_error"],
                first_attempt_at=r["first_attempt_at"],
                last_attempt_at=r["last_attempt_at"],
            )
            for r in rows
        ]
