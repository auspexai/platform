"""model_serve_failures — observed serve-OOM ground truth (the "learn from failures"
half of the sizing fix).

When a worker OOMs serving a model (Layer-1 refusal "insufficient GPU memory to
serve <model>"), that's proof the model does not fit a worker with that much usable
memory. Record the LARGEST usable-GB observed to OOM per model; the catalog then
labels the model too_big for any worker with usable <= that, regardless of the
a-priori estimate. Ground truth beats a guess."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from auspexai_platform.db.database import Database

# An OOM excludes a worker size only while it's RECENT — the fleet must have OOM'd the
# model within this window. A stale record (no reproduced OOM since) lifts, so the model
# is retried: a transient/one-off OOM can't bench a worker forever, and it breaks the
# chicken-and-egg (an excluded model can't serve to earn the successes that would clear it).
OOM_EXCLUSION_COOLDOWN = timedelta(hours=6)

# Exclude only when OOMs DOMINATE. A worker that OOMs less than this fraction of its
# (oom + success) attempts is fit-but-flaky, not too-small — don't bench it. 0.5 = "OOMs at
# least as often as it succeeds."
OOM_RATE_CUTOFF = 0.5

# ...and only once there are enough failures to conclude "too small", not on a one-off. A
# flaky model needs RUNWAY: benching it on the first OOM would release the worker before it
# can serve and earn the successes that keep it eligible (a chicken-and-egg). Below this
# floor the model is retried; a genuinely-too-small model reaches it in a few OOMs.
OOM_MIN_OBSERVATIONS = 3


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


class ModelServeFailureRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record_oom(self, model_id: str, worker_usable_gb: float, *, now: str) -> None:
        """A worker with `worker_usable_gb` usable memory OOM'd serving `model_id`.
        Upsert, keeping the LARGEST usable-GB seen (a bigger box that also OOM'd
        tightens the bound) and bumping the observation count.

        RESET-ON-STALE-BURST: if the previous OOM was longer ago than the cooldown, this is a
        NEW burst under possibly-changed conditions — restart the (oom, success) rate window
        fresh (count = 1, successes = 0) instead of carrying the old history. Without this, a
        model that was flaky under a transient condition (e.g. memory pressure since cleared)
        stays rate-penalised forever by failures that no longer reflect reality."""
        now_dt = _parse_iso(now)
        existing = self.db.execute(
            "SELECT last_observed_at FROM model_serve_failures WHERE model_id = ?", (model_id,)
        )
        if existing:
            prev = _parse_iso(existing[0]["last_observed_at"])
            if prev is not None and now_dt is not None and (now_dt - prev) > OOM_EXCLUSION_COOLDOWN:
                self.db.execute(
                    """
                    UPDATE model_serve_failures
                    SET max_ooomd_usable_gb = MAX(max_ooomd_usable_gb, ?),
                        last_observed_at = ?, observation_count = 1, success_count = 0
                    WHERE model_id = ?
                    """,
                    (float(worker_usable_gb), now, model_id),
                )
                return
        self.db.execute(
            """
            INSERT INTO model_serve_failures
                (model_id, max_ooomd_usable_gb, last_observed_at, observation_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(model_id) DO UPDATE SET
                max_ooomd_usable_gb = MAX(max_ooomd_usable_gb, excluded.max_ooomd_usable_gb),
                last_observed_at = excluded.last_observed_at,
                observation_count = observation_count + 1
            """,
            (model_id, float(worker_usable_gb), now),
        )

    def record_serve_success(self, model_id: str, worker_usable_gb: float, *, now: str) -> None:
        """A worker with `worker_usable_gb` usable memory SUCCESSFULLY served `model_id`
        (it delivered a result). This TEMPERS an existing serve-OOM exclusion for the
        too-small class: only a worker at or below the OOM'd size counts (a big box serving
        the model says nothing about whether a small one can). No-op when there is no OOM
        record to temper — we don't track successes for un-excluded models."""
        self.db.execute(
            """
            UPDATE model_serve_failures
            SET success_count = success_count + 1, last_success_at = ?
            WHERE model_id = ? AND ? <= max_ooomd_usable_gb
            """,
            (now, model_id, float(worker_usable_gb)),
        )

    def oom_thresholds(self, *, now: datetime | None = None) -> dict[str, float]:
        """{model_id: largest usable-GB observed to OOM} — but ONLY for models whose OOM is
        both RECENT (within `OOM_EXCLUSION_COOLDOWN`) and DOMINANT (oom rate >=
        `OOM_RATE_CUTOFF`). A worker with usable <= a returned value cannot serve the model.
        Stale or flaky-but-mostly-succeeding records are omitted, so a borderline model isn't
        permanently benched by a transient OOM (rate-aware + success-tempered, migration 0063)."""
        now = now or datetime.now(UTC)
        rows = self.db.execute(
            "SELECT model_id, max_ooomd_usable_gb, observation_count, "
            "success_count, last_observed_at FROM model_serve_failures"
        )
        out: dict[str, float] = {}
        for r in rows:
            last = _parse_iso(r["last_observed_at"])
            if last is None or (now - last) > OOM_EXCLUSION_COOLDOWN:
                continue  # stale → retry it
            ooms = int(r["observation_count"] or 0)
            if ooms < OOM_MIN_OBSERVATIONS:
                continue  # too few failures to conclude too-small → give it runway
            total = ooms + int(r["success_count"] or 0)
            if total > 0 and ooms / total < OOM_RATE_CUTOFF:
                continue  # fit-but-flaky → don't bench it
            out[r["model_id"]] = float(r["max_ooomd_usable_gb"])
        return out

    def note_worker_recovered(self, worker_id: str, model_id: str, *, now: str) -> None:
        """A specific worker's operator REMEDIATED its serve condition (freed memory /
        restarted the backend) after `model_id` OOM'd on it. Lets THIS worker retry the
        model despite the model-level exclusion — surgical recovery, so one node's fix never
        re-offers the model to other, un-remediated nodes. Upsert the latest recovery time."""
        self.db.execute(
            "INSERT INTO worker_serve_recovery (worker_id, model_id, recovered_at) "
            "VALUES (?, ?, ?) ON CONFLICT(worker_id, model_id) DO UPDATE SET "
            "recovered_at = excluded.recovered_at",
            (worker_id, model_id, now),
        )

    def recovery_shadows(self, *, now: datetime | None = None) -> set[tuple[str, str]]:
        """{(worker_id, model_id)} pairs where the worker signalled serve-recovery AFTER the
        model's most recent OOM — so serve_fits lets it retry despite the model-level
        exclusion (a one-shot probe: a serve success tempers the shared record; a re-OOM
        writes a newer last_observed_at and the shadow lifts). Only while the OOM is still
        recent (past the cooldown the model isn't excluded at all → the shadow is moot)."""
        now = now or datetime.now(UTC)
        rows = self.db.execute(
            "SELECT r.worker_id, r.model_id, r.recovered_at, f.last_observed_at "
            "FROM worker_serve_recovery r JOIN model_serve_failures f ON r.model_id = f.model_id"
        )
        out: set[tuple[str, str]] = set()
        for r in rows:
            rec = _parse_iso(r["recovered_at"])
            last = _parse_iso(r["last_observed_at"])
            if rec is None or last is None:
                continue
            if rec > last and (now - last) <= OOM_EXCLUSION_COOLDOWN:
                out.add((r["worker_id"], r["model_id"]))
        return out

    def recent_oom_sizes(self, *, now: datetime | None = None) -> dict[str, float]:
        """{model_id: largest usable-GB RECENTLY observed to OOM} — a SOFT placement signal,
        distinct from the hard `oom_thresholds`. A worker at/below this size has OOM'd this
        model lately and is a LESS-RELIABLE place to run it, even when it's below the
        exclusion runway (not benched). The scheduler uses it to PREFER a worker the model
        doesn't OOM on when one is free — so a flaky-on-small model is placed on the big box
        that idles rather than maximising its OOM exposure. Staleness-gated (a forgiven, stale
        OOM stops biasing placement) but NOT rate/runway-gated (any recent OOM is a hint)."""
        now = now or datetime.now(UTC)
        rows = self.db.execute(
            "SELECT model_id, max_ooomd_usable_gb, last_observed_at FROM model_serve_failures"
        )
        out: dict[str, float] = {}
        for r in rows:
            last = _parse_iso(r["last_observed_at"])
            if last is None or (now - last) > OOM_EXCLUSION_COOLDOWN:
                continue
            out[r["model_id"]] = float(r["max_ooomd_usable_gb"])
        return out
