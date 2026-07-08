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

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import AnchorOutcomeRepository, AttestationRepository
from auspexai_platform.receipts.rekor import (
    REKOR_PLACEHOLDER_UUID,
    NoOpRekorClient,
    RekorClient,
)

logger = logging.getLogger(__name__)

# A11: give up on a row only after this many CONFIRMED permanent rejections (a
# 4xx that is not 408/429). Transient failures never count toward this, so a long
# Rekor outage is ridden out rather than abandoned.
TERMINAL_AFTER_PERMANENT = 3


def _is_permanent_rejection(exc: Exception) -> bool:
    """A Rekor rejection that will NOT succeed on retry (vs a transient outage).
    The known un-anchorable case is a 400 'unsupported algorithm ed25519' on the
    cose/hashedrekord kinds. 408 (timeout) and 429 (rate-limit) are 4xx but
    transient; 5xx / connection / anything else is transient."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return 400 <= code < 500 and code not in (408, 429)
    return False


def _attempt_anchor(
    rekor_client: RekorClient | NoOpRekorClient,
    blob: bytes,
    outcomes: AnchorOutcomeRepository,
    *,
    artifact_type: str,
    artifact_id: str,
    terminal_ids: set[str],
    now: str,
):
    """Try to anchor one artifact, tracking failure state. Returns (entry, note):
    `entry` is a real RekorEntry on success (the caller records it), else None.
    `note` ∈ skipped_terminal | ok | failed_transient | failed_permanent |
    newly_terminal. A row is never abandoned for a transient failure; only a
    confirmed permanent rejection (x TERMINAL_AFTER_PERMANENT) goes terminal."""
    if artifact_id in terminal_ids:
        return None, "skipped_terminal"
    try:
        entry = rekor_client.record(blob)
    except Exception as exc:
        permanent = _is_permanent_rejection(exc)
        logger.warning("rekor anchor failed for %s %s: %s", artifact_type, artifact_id, exc)
        became_terminal = outcomes.record_failure(
            artifact_type,
            artifact_id,
            permanent=permanent,
            error=str(exc),
            now=now,
            terminal_after=TERMINAL_AFTER_PERMANENT,
        )
        if became_terminal:
            logger.warning(
                "rekor anchoring GAVE UP on %s %s (permanently un-anchorable after %d rejections)",
                artifact_type,
                artifact_id,
                TERMINAL_AFTER_PERMANENT,
            )
            return None, "newly_terminal"
        return None, "failed_permanent" if permanent else "failed_transient"
    if entry.entry_uuid == REKOR_PLACEHOLDER_UUID:
        # NoOp / degraded response — transient; don't overwrite with a placeholder.
        outcomes.record_failure(
            artifact_type,
            artifact_id,
            permanent=False,
            error="rekor placeholder / degraded response",
            now=now,
            terminal_after=TERMINAL_AFTER_PERMANENT,
        )
        return None, "failed_transient"
    outcomes.clear(artifact_type, artifact_id)  # success — drop any prior failure state
    return entry, "ok"


@dataclass
class BackfillReport:
    applied: bool
    candidates: int = 0
    anchored: list[str] = field(default_factory=list)  # attestation_ids newly anchored
    failed: list[str] = field(default_factory=list)  # left un-anchored for next run
    # D16.2: submit-time pre-registration anchors swept by the same run (Q1:
    # reuse the hourly timer). Keyed by experiment_id.
    prereg_candidates: int = 0
    prereg_anchored: list[str] = field(default_factory=list)
    prereg_failed: list[str] = field(default_factory=list)
    # A11: artifacts newly marked terminally un-anchorable this run ("type:id").
    terminal_now: list[str] = field(default_factory=list)

    def summary(self) -> str:
        verb = "anchored" if self.applied else "would anchor"
        # Dry-run never simulates per-row, so "would anchor" reports the
        # candidate count, not the (always-empty) anchored list.
        count = len(self.anchored) if self.applied else self.candidates
        head = (
            f"rekor backfill ({'APPLIED' if self.applied else 'DRY-RUN'}): "
            f"{self.candidates} un-anchored attestation(s); {verb} {count}"
        )
        if self.failed:
            head += f", {len(self.failed)} failed (left un-anchored)"
        pcount = len(self.prereg_anchored) if self.applied else self.prereg_candidates
        head += f"; {self.prereg_candidates} un-anchored pre-registration(s), {verb} {pcount}"
        if self.prereg_failed:
            head += f", {len(self.prereg_failed)} failed"
        lines = [head]
        lines += [f"  - {aid}: anchored" for aid in self.anchored]
        lines += [f"  - {aid}: FAILED (left un-anchored for next run)" for aid in self.failed]
        lines += [f"  - pre-registration {eid}: anchored" for eid in self.prereg_anchored]
        lines += [
            f"  - pre-registration {eid}: FAILED (left un-anchored for next run)"
            for eid in self.prereg_failed
        ]
        if self.terminal_now:
            lines[0] += f"; {len(self.terminal_now)} newly TERMINAL (permanently un-anchorable)"
        lines += [
            f"  - {t}: TERMINAL — permanently un-anchorable, stopped retrying"
            for t in self.terminal_now
        ]
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
    from auspexai_platform.db.repositories import (
        PreRegistrationDeviationRepository,
        PreRegistrationRepository,
    )

    repo = AttestationRepository(control_db)
    prereg_repo = PreRegistrationRepository(control_db)
    deviation_repo = PreRegistrationDeviationRepository(control_db)
    candidates = repo.list_unanchored()
    prereg_candidates = prereg_repo.list_unanchored()
    deviation_candidates = deviation_repo.list_unanchored()
    report = BackfillReport(
        applied=apply, candidates=len(candidates), prereg_candidates=len(prereg_candidates)
    )
    if not apply:
        return report

    outcomes = AnchorOutcomeRepository(control_db)
    now = datetime.now(UTC).isoformat()
    prereg_terminal = outcomes.terminal_ids("pre_registration")
    dev_terminal = outcomes.terminal_ids("deviation")
    att_terminal = outcomes.terminal_ids("attestation")

    # D16.2 ORDERING INVARIANT: pre-registrations anchor FIRST. A fast run's
    # pre-registration AND result attestation can pend the SAME sweep (submit
    # and completion within one timer interval); Rekor log indexes are assigned
    # in submission order, so anchoring attestations first would give the
    # attestation the LOWER index and a genuinely pre-registered run would read
    # `design ≺ data` = FALSE — forever (anchors are immutable). The prereg row
    # always exists strictly before its attestation, so prereg-first preserves
    # the true ordering in every case (same-sweep and cross-sweep alike).
    for prec in prereg_candidates:
        entry, note = _attempt_anchor(
            rekor_client,
            prec.cose_signed_blob,
            outcomes,
            artifact_type="pre_registration",
            artifact_id=prec.experiment_id,
            terminal_ids=prereg_terminal,
            now=now,
        )
        if entry is None:
            if note == "newly_terminal":
                report.terminal_now.append(f"pre_registration:{prec.experiment_id}")
            elif note != "skipped_terminal":
                report.prereg_failed.append(prec.experiment_id)
            continue
        prereg_repo.set_rekor(
            prec.experiment_id,
            log_index=entry.log_index,
            entry_uuid=entry.entry_uuid,
            inclusion_proof=entry.inclusion_proof or None,
        )
        report.prereg_anchored.append(prec.experiment_id)

    # D16.2-D: deviation anchors ride the same design-side phase.
    for drec in deviation_candidates:
        entry, note = _attempt_anchor(
            rekor_client,
            drec.cose_signed_blob,
            outcomes,
            artifact_type="deviation",
            artifact_id=drec.deviation_id,
            terminal_ids=dev_terminal,
            now=now,
        )
        if entry is None:
            if note == "newly_terminal":
                report.terminal_now.append(f"deviation:{drec.deviation_id}")
            continue
        deviation_repo.set_rekor(
            drec.deviation_id,
            log_index=entry.log_index,
            entry_uuid=entry.entry_uuid,
            inclusion_proof=entry.inclusion_proof or None,
        )

    for rec in candidates:
        entry, note = _attempt_anchor(
            rekor_client,
            rec.cose_signed_blob,
            outcomes,
            artifact_type="attestation",
            artifact_id=rec.attestation_id,
            terminal_ids=att_terminal,
            now=now,
        )
        if entry is None:
            if note == "newly_terminal":
                report.terminal_now.append(f"attestation:{rec.attestation_id}")
            elif note != "skipped_terminal":
                report.failed.append(rec.attestation_id)
            continue
        repo.set_rekor(
            rec.attestation_id,
            log_index=entry.log_index,
            entry_uuid=entry.entry_uuid,
            # EB-1: persist the inclusion proof when the anchor response carried
            # one — the evidence bundle ships it for offline verification.
            inclusion_proof_json=(
                json.dumps(entry.inclusion_proof) if entry.inclusion_proof else None
            ),
        )
        report.anchored.append(rec.attestation_id)
    return report
