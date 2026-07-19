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


def _oom_n(repo: ModelServeFailureRepository, model: str, usable: float, n: int, now: str) -> None:
    for _ in range(n):
        repo.record_oom(model, usable, now=now)


def test_distinct_models_tracked_independently(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "phi-3.5-mini-instruct-q4", 5.44, 3, "2026-07-16T00:00:00+00:00")
    _oom_n(repo, "qwen3-4b-instruct-2507-q4", 5.44, 3, "2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds(now=_RECENT)
    assert thr["phi-3.5-mini-instruct-q4"] == 5.44
    assert thr["qwen3-4b-instruct-2507-q4"] == 5.44


def test_threshold_semantics_a_worker_no_bigger_cannot_serve(db: Database) -> None:
    # The catalog uses `worker_capacity > threshold` to allow the model. A worker at
    # exactly the OOM'd size is excluded; a bigger one (the Mac) is not.
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "phi-3.5-mini-instruct-q4", 5.44, 3, "2026-07-16T00:00:00+00:00")
    thr = repo.oom_thresholds(now=_RECENT)["phi-3.5-mini-instruct-q4"]
    assert not (5.44 > thr)  # the Jetson that OOM'd: excluded
    assert not (5.0 > thr)  # a smaller box: excluded
    assert 22.0 > thr  # the Mac: still allowed


# ---- min-observations runway (migration 0063) ----


def test_a_couple_of_ooms_do_not_bench_below_the_runway(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "m", 4.44, 2, "2026-07-16T00:00:00+00:00")  # 2 < OOM_MIN_OBSERVATIONS
    assert repo.oom_thresholds(now=_RECENT) == {}  # runway — retried, not benched
    repo.record_oom("m", 4.44, now="2026-07-16T00:01:00+00:00")  # the 3rd crosses the floor
    assert repo.oom_thresholds(now=_RECENT) == {"m": 4.44}


# ---- staleness (migration 0063) ----


def test_stale_oom_no_longer_excludes(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "m", 4.44, 3, "2026-07-16T00:00:00+00:00")
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


def test_stale_burst_resets_the_rate_window(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # A big burst of OOMs under old conditions (12 failures) that then went quiet...
    for _ in range(12):
        repo.record_oom("m", 4.44, now="2026-07-16T00:00:00+00:00")
    # ...a FRESH burst > cooldown later forgives the 12 stale failures — the count restarts,
    # so 3 fresh OOMs, not 15, decide the rate (no permanent headwind).
    _oom_n(repo, "m", 4.44, 3, "2026-07-16T08:00:00+00:00")
    assert repo.oom_thresholds(now=datetime.fromisoformat("2026-07-16T08:05:00+00:00")) == {
        "m": 4.44
    }  # 3 fresh ooms, 0 success → excluded
    # Four same-class successes now flip it (3 oom : 4 success → 0.43 < cutoff) — which would
    # have needed 13+ successes to overcome the un-forgiven 12.
    for _ in range(4):
        repo.record_serve_success("m", 4.44, now="2026-07-16T08:06:00+00:00")
    assert repo.oom_thresholds(now=datetime.fromisoformat("2026-07-16T08:07:00+00:00")) == {}


def test_dominant_ooms_still_exclude(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    # Genuinely too-big: OOMs every time, no successes → rate 1.0 → excluded.
    for _ in range(5):
        repo.record_oom("huge-model", 4.44, now="2026-07-16T00:00:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {"huge-model": 4.44}


def test_success_only_counts_the_too_small_class(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "m", 4.44, 3, "2026-07-16T00:00:00+00:00")
    # A BIG worker (Mac) serving the model says nothing about a small one → does NOT temper.
    repo.record_serve_success("m", 21.0, now="2026-07-16T00:10:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {
        "m": 4.44
    }  # still excluded (3 oom, 0 counted success)
    # Same-class (4.0 <= 4.44) successes DO temper: 3 oom : 4 success → 0.43 < cutoff.
    for _ in range(4):
        repo.record_serve_success("m", 4.0, now="2026-07-16T00:11:00+00:00")
    assert repo.oom_thresholds(now=_RECENT) == {}


# ── per-worker serve-recovery (migration 0064): surgical recovery ─────────────


def test_recovery_shadows_only_when_recovered_after_the_oom(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "smollm2-1.7b-instruct-q4", 4.44, 3, "2026-07-16T00:00:00+00:00")
    # a worker remediated AFTER the OOM shadows the model-level exclusion for ITSELF
    repo.note_worker_recovered("wkr-A", "smollm2-1.7b-instruct-q4", now="2026-07-16T00:05:00+00:00")
    # a worker whose recovery PREDATES the OOM does not (its fix was before the failure)
    repo.note_worker_recovered("wkr-B", "smollm2-1.7b-instruct-q4", now="2026-07-15T23:00:00+00:00")
    shadows = repo.recovery_shadows(now=_RECENT)
    assert ("wkr-A", "smollm2-1.7b-instruct-q4") in shadows
    assert ("wkr-B", "smollm2-1.7b-instruct-q4") not in shadows


def test_recovery_shadow_is_moot_once_the_oom_is_stale(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "smollm2-1.7b-instruct-q4", 4.44, 3, "2026-07-16T00:00:00+00:00")
    repo.note_worker_recovered("wkr-A", "smollm2-1.7b-instruct-q4", now="2026-07-16T00:05:00+00:00")
    # far past the 6h cooldown → the model isn't excluded at all, so the shadow is moot
    stale = datetime.fromisoformat("2026-07-17T00:00:00+00:00")
    assert repo.recovery_shadows(now=stale) == set()


def test_note_worker_recovered_is_idempotent(db: Database) -> None:
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "m-model-q4", 4.44, 3, "2026-07-16T00:00:00+00:00")
    repo.note_worker_recovered("wkr-A", "m-model-q4", now="2026-07-16T00:05:00+00:00")
    repo.note_worker_recovered("wkr-A", "m-model-q4", now="2026-07-16T00:06:00+00:00")  # upsert
    assert repo.recovery_shadows(now=_RECENT) == {("wkr-A", "m-model-q4")}


def test_re_oom_after_recovery_lifts_the_shadow(db: Database) -> None:
    # A remediated worker retries and OOMs AGAIN → a newer last_observed_at → its earlier
    # recovery no longer shadows the exclusion (it's back to benched, correctly).
    repo = ModelServeFailureRepository(db)
    _oom_n(repo, "smollm2-1.7b-instruct-q4", 4.44, 3, "2026-07-16T00:00:00+00:00")
    repo.note_worker_recovered("wkr-A", "smollm2-1.7b-instruct-q4", now="2026-07-16T00:05:00+00:00")
    assert ("wkr-A", "smollm2-1.7b-instruct-q4") in repo.recovery_shadows(now=_RECENT)
    repo.record_oom("smollm2-1.7b-instruct-q4", 4.44, now="2026-07-16T00:10:00+00:00")  # re-OOM
    assert repo.recovery_shadows(now=_RECENT) == set()  # recovery predates the new OOM
