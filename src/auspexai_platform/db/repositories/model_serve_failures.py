"""model_serve_failures — observed serve-OOM ground truth (the "learn from failures"
half of the sizing fix).

When a worker OOMs serving a model (Layer-1 refusal "insufficient GPU memory to
serve <model>"), that's proof the model does not fit a worker with that much usable
memory. Record the LARGEST usable-GB observed to OOM per model; the catalog then
labels the model too_big for any worker with usable <= that, regardless of the
a-priori estimate. Ground truth beats a guess."""

from __future__ import annotations

from auspexai_platform.db.database import Database


class ModelServeFailureRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record_oom(self, model_id: str, worker_usable_gb: float, *, now: str) -> None:
        """A worker with `worker_usable_gb` usable memory OOM'd serving `model_id`.
        Upsert, keeping the LARGEST usable-GB seen (a bigger box that also OOM'd
        tightens the bound) and bumping the observation count."""
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

    def oom_thresholds(self) -> dict[str, float]:
        """{model_id: largest usable-GB observed to OOM}. A worker with usable <=
        this value cannot serve the model (observed, not estimated)."""
        rows = self.db.execute("SELECT model_id, max_ooomd_usable_gb FROM model_serve_failures")
        return {r["model_id"]: float(r["max_ooomd_usable_gb"]) for r in rows}
