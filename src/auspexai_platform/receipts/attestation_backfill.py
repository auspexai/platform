"""Rekor backfill sweep (A2) — anchor persisted attestations out-of-band.

The completion path persists the canonical attestation with the NoOp Rekor
placeholder: anchoring inline would block the coordinator's async request path
on a network call (the result-submission route runs synchronously on the event
loop). This sweep is therefore the SOLE Rekor-calling path. It walks the
persisted attestations still carrying the placeholder, submits each one's
COSE-signed blob to Rekor, and records the returned log index + entry UUID.

Idempotent (re-running anchors only what's still un-anchored), resumable, and
per-row fault-tolerant — one Rekor hiccup leaves that row for the next run
instead of aborting the batch. Run from a systemd timer (mirrors the age-off
sweep) or on demand via `auspexai-coordinator attestation backfill-rekor`.

Anchoring the AGGREGATE (one entry per completed-experiment attestation), not
the atom (per receipt) — receipts inherit immutability via the Merkle root the
attestation commits to (plan L2).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import AttestationRepository
from auspexai_platform.receipts.rekor import (
    REKOR_PLACEHOLDER_UUID,
    NoOpRekorClient,
    RekorClient,
)

logger = logging.getLogger(__name__)


@dataclass
class BackfillReport:
    applied: bool
    candidates: int = 0
    anchored: list[str] = field(default_factory=list)  # attestation_ids newly anchored
    failed: list[str] = field(default_factory=list)  # left un-anchored for next run

    def summary(self) -> str:
        verb = "anchored" if self.applied else "would anchor"
        head = (
            f"rekor backfill ({'APPLIED' if self.applied else 'DRY-RUN'}): "
            f"{self.candidates} un-anchored attestation(s); {verb} {len(self.anchored)}"
        )
        if self.failed:
            head += f", {len(self.failed)} failed (left un-anchored)"
        lines = [head]
        lines += [f"  - {aid}: anchored" for aid in self.anchored]
        lines += [f"  - {aid}: FAILED (left un-anchored for next run)" for aid in self.failed]
        return "\n".join(lines)


def backfill_rekor_anchors(
    control_db: Database,
    *,
    rekor_client: RekorClient | NoOpRekorClient,
    apply: bool,
) -> BackfillReport:
    """Anchor every persisted attestation still carrying the NoOp placeholder.

    DRY-RUN by default (apply=False): reports the candidate count without
    contacting Rekor. apply=True submits each candidate's COSE blob and records
    the anchor. A per-row failure is logged and the row left un-anchored (the
    next run retries). A client returning the placeholder (NoOpRekorClient, or a
    degraded response) is treated as a no-op — the row is NOT stamped with a
    placeholder, so it stays a candidate for the next real run.
    """
    repo = AttestationRepository(control_db)
    candidates = repo.list_unanchored()
    report = BackfillReport(applied=apply, candidates=len(candidates))
    if not apply:
        return report
    for rec in candidates:
        try:
            entry = rekor_client.record(rec.cose_signed_blob)
        except Exception:
            logger.exception(
                "rekor backfill failed for %s; leaving un-anchored", rec.attestation_id
            )
            report.failed.append(rec.attestation_id)
            continue
        if entry.entry_uuid == REKOR_PLACEHOLDER_UUID:
            # NoOp / degraded — don't overwrite with a placeholder.
            report.failed.append(rec.attestation_id)
            continue
        repo.set_rekor(rec.attestation_id, log_index=entry.log_index, entry_uuid=entry.entry_uuid)
        report.anchored.append(rec.attestation_id)
    return report
