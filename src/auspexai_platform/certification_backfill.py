"""Rekor backfill for promotion-gate certifications (the §6.7.4 "publish" half).

A certification is signed + registered at `certification issue`; anchoring it in
the transparency log makes it publicly auditable and contestable — the
independence mechanism for low-risk certs (sign + publish + contest, §6.7.4). The
issue path anchors inline (best-effort); this sweep catches anything left
un-anchored (a Rekor hiccup, or a cert issued before anchoring shipped).

Idempotent (anchors only certs with no rekor_log_index), per-row fault-tolerant —
one Rekor hiccup leaves that row for the next run instead of aborting the batch.
Run via `auspexai-coordinator certification backfill-rekor` or a systemd timer,
mirroring the attestation backfill.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import CertifiedProfileRepository
from auspexai_platform.receipts.rekor import NoOpRekorClient, RekorClient

logger = logging.getLogger(__name__)


@dataclass
class CertBackfillReport:
    applied: bool
    candidates: int = 0
    anchored: list[str] = field(default_factory=list)  # package digests newly anchored
    failed: list[str] = field(default_factory=list)  # left un-anchored for next run

    def summary(self) -> str:
        verb = "anchored" if self.applied else "would anchor"
        count = len(self.anchored) if self.applied else self.candidates
        head = (
            f"cert rekor backfill ({'APPLIED' if self.applied else 'DRY-RUN'}): "
            f"{self.candidates} un-anchored certification(s); {verb} {count}"
        )
        if self.failed:
            head += f", {len(self.failed)} failed (left un-anchored)"
        lines = [head]
        lines += [f"  - {p[:16]}…: anchored" for p in self.anchored]
        lines += [f"  - {p[:16]}…: FAILED (left un-anchored for next run)" for p in self.failed]
        return "\n".join(lines)


def backfill_cert_rekor(
    control_db: Database,
    *,
    rekor_client: RekorClient | NoOpRekorClient,
    apply: bool,
) -> CertBackfillReport:
    """Anchor every certification still missing a Rekor log index. DRY-RUN by
    default (apply=False): reports the candidate count without contacting Rekor.
    apply=True submits each candidate's COSE blob and records the returned index."""
    repo = CertifiedProfileRepository(control_db)
    candidates = repo.list_unanchored()
    report = CertBackfillReport(applied=apply, candidates=len(candidates))
    if not apply:
        return report
    for cert in candidates:
        try:
            entry = rekor_client.record(cert.cose_signed_blob)
            repo.set_rekor(cert.package_sha256, log_index=entry.log_index)
            report.anchored.append(cert.package_sha256)
        except Exception:
            logger.exception("cert rekor anchor failed for %s", cert.package_sha256)
            report.failed.append(cert.package_sha256)
    return report
