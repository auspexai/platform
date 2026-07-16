"""model_serve_failures — the observed-OOM ground-truth store (#1 of the sizing fix)."""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories.model_serve_failures import ModelServeFailureRepository


def test_empty_by_default(db: Database) -> None:
    assert ModelServeFailureRepository(db).oom_thresholds() == {}


def test_records_and_keeps_largest_ooomd_capacity(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # phi OOM'd first on a 5.44 GB Jetson, then also on a (hypothetical) 6.0 GB box.
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    repo.record_oom("phi-3.5-mini-instruct-q4", 6.0, now="2026-07-16T00:05:00+00:00")
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:10:00+00:00")

    thr = repo.oom_thresholds()
    assert thr == {"phi-3.5-mini-instruct-q4": 6.0}  # the LARGEST box that OOM'd wins


def test_distinct_models_tracked_independently(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    repo.record_oom("qwen3-4b-instruct-2507-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds()
    assert thr["phi-3.5-mini-instruct-q4"] == 5.44
    assert thr["qwen3-4b-instruct-2507-q4"] == 5.44


def test_threshold_semantics_a_worker_no_bigger_cannot_serve(db: Database) -> None:
    # The catalog uses `worker_capacity > threshold` to allow the model. A worker at
    # exactly the OOM'd size is excluded; a bigger one (the Mac) is not.
    repo = ModelServeFailureRepository(db)
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds()["phi-3.5-mini-instruct-q4"]
    assert not (5.44 > thr)  # the Jetson that OOM'd: excluded
    assert not (5.0 > thr)  # a smaller box: excluded
    assert 22.0 > thr  # the Mac: still allowed
