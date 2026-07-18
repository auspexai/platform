"""model_serve_failures — the observed-OOM ground-truth store.

Rate-aware + success-tempered + staleness-gated (migration 0063): an OOM excludes a
worker size only while it's RECENT and OOMs DOMINATE; a fit-but-flaky model that mostly
serves (successes recorded) or hasn't reproduced its OOM lately is not benched.
"""

from __future__ import annotations

from datetime import datetime

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories.model_serve_failures import ModelServeFailureRepository

# A time shortly after the recorded OOMs (well within OOM_EXCLUSION_COOLDOWN = 6 h) so the
# staleness gate keeps them active for the "records the OOM" tests.
_RECENT = datetime.fromisoformat("2026-07-16T00:15:00+00:00")


def test_empty_by_default(db: Database) -> None:
    assert ModelServeFailureRepository(db).oom_thresholds() == {}


def test_records_and_keeps_largest_ooomd_capacity(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # phi OOM'd first on a 5.44 GB Jetson, then also on a (hypothetical) 6.0 GB box.
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    repo.record_oom("phi-3.5-mini-instruct-q4", 6.0, now="2026-07-16T00:05:00+00:00")
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:10:00+00:00")

    thr = repo.oom_thresholds(now=_RECENT)
    assert thr == {"phi-3.5-mini-instruct-q4": 6.0}  # the LARGEST box that OOM'd wins


def test_distinct_models_tracked_independently(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    repo.record_oom("qwen3-4b-instruct-2507-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds(now=_RECENT)
    assert thr["phi-3.5-mini-instruct-q4"] == 5.44
    assert thr["qwen3-4b-instruct-2507-q4"] == 5.44


def test_threshold_semantics_a_worker_no_bigger_cannot_serve(db: Database) -> None:
    # The catalog uses `worker_capacity > threshold` to allow the model. A worker at
    # exactly the OOM'd size is excluded; a bigger one (the Mac) is not.
    repo = ModelServeFailureRepository(db)
    repo.record_oom("phi-3.5-mini-instruct-q4", 5.44, now="2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds(now=_RECENT)["phi-3.5-mini-instruct-q4"]
    assert not (5.44 > thr)  # the Jetson that OOM'd: excluded
    assert not (5.0 > thr)  # a smaller box: excluded
    assert 22.0 > thr  # the Mac: still allowed


# ---- staleness (migration 0063) ----


def test_stale_oom_no_longer_excludes(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    repo.record_oom("m", 4.44, now="2026-07-16T00:00:00+00:00")
    # < cooldown after → still excludes.
    assert repo.oom_thresholds(now=datetime.fromisoformat("2026-07-16T05:00:00+00:00")) == {
        "m": 4.44
    }
    # > cooldown after → stale → omitted → the worker gets retried.
    assert repo.oom_thresholds(now=datetime.fromisoformat("2026-07-16T07:00:00+00:00")) == {}


# ---- rate-aware / success-tempered (migration 0063) ----


def test_success_tempers_a_flaky_model(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # A borderline model: OOMs 12x on a 4.44 GB box but ALSO serves 36x there.
    for _ in range(12):
        repo.record_oom("qwen3-1.7b-q4", 4.44, now="2026-07-16T00:00:00+00:00")
    for _ in range(36):
        repo.record_serve_success("qwen3-1.7b-q4", 4.44, now="2026-07-16T00:10:00+00:00")
    # rate 12/48 = 0.25 < cutoff → NOT benched (fit-but-flaky).
    assert repo.oom_thresholds(now=_RECENT) == {}


def test_dominant_ooms_still_exclude(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # Genuinely too-big: OOMs every time, no successes → rate 1.0 → excluded.
    for _ in range(5):
        repo.record_oom("huge-model", 4.44, now="2026-07-16T00:00:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {"huge-model": 4.44}


def test_success_only_counts_the_too_small_class(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    repo.record_oom("m", 4.44, now="2026-07-16T00:00:00+00:00")
    # A BIG worker (Mac) serving the model says nothing about a small one → does NOT temper.
    repo.record_serve_success("m", 21.0, now="2026-07-16T00:10:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {"m": 4.44}  # still excluded
    # A same-class (4.0 <= 4.44) success DOES temper (now 1 oom : 1 success → rate 0.5 == cutoff,
    # still excluded); add a couple more to cross below the cutoff.
    for _ in range(2):
        repo.record_serve_success("m", 4.0, now="2026-07-16T00:11:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {}  # 1 oom : 3 successes → 0.25 < cutoff
