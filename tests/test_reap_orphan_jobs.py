"""A11 orphan per-job DB reaper — removes jobs/<eid>.db (+ sidecars) whose
experiment row is gone, never touches a live experiment's record, honors grace."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from auspexai_platform.maintenance import reap_orphan_jobs


def _mkfile(path: Path, *, age: timedelta | None = None, now: datetime) -> None:
    path.write_text("x")  # reaper only stat()s + unlink()s — content is irrelevant
    if age is not None:
        ts = (now - age).timestamp()
        os.utime(path, (ts, ts))


def test_removes_old_orphans_keeps_fresh(db, tmp_path: Path) -> None:
    # Empty experiments table → every file is an orphan.
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    now = datetime.now(UTC)
    old = jobs / "exp-orphan-old.db"
    _mkfile(old, age=timedelta(days=2), now=now)
    _mkfile(jobs / "exp-orphan-old.db-wal", age=timedelta(days=2), now=now)
    _mkfile(jobs / "exp-orphan-old.db-shm", age=timedelta(days=2), now=now)
    fresh = jobs / "exp-orphan-fresh.db"
    _mkfile(fresh, now=now)  # mtime = now → inside grace
    grace = timedelta(hours=24)

    # Dry-run: reports the stale orphan, deletes nothing.
    r = reap_orphan_jobs(jobs, db, now=now, grace=grace, apply=False)
    assert r.removed == ["exp-orphan-old"]
    assert r.skipped_recent == 1
    assert old.exists() and fresh.exists()

    # Apply: removes the stale orphan + BOTH sidecars; the fresh orphan survives.
    r = reap_orphan_jobs(jobs, db, now=now, grace=grace, apply=True)
    assert r.removed == ["exp-orphan-old"]
    assert not old.exists()
    assert not (jobs / "exp-orphan-old.db-wal").exists()
    assert not (jobs / "exp-orphan-old.db-shm").exists()
    assert fresh.exists()  # within grace — never reaped


def test_never_touches_a_live_experiment(db, approved_experiment, tmp_path: Path) -> None:
    _, _, experiment, _ = approved_experiment
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    now = datetime.now(UTC)
    # A per-job DB for the LIVE experiment, even ancient, is the permanent record.
    live = jobs / f"{experiment.experiment_id}.db"
    _mkfile(live, age=timedelta(days=90), now=now)
    orphan = jobs / "exp-gone.db"
    _mkfile(orphan, age=timedelta(days=90), now=now)

    r = reap_orphan_jobs(jobs, db, now=now, grace=timedelta(hours=24), apply=True)
    assert r.removed == ["exp-gone"]
    assert live.exists()  # the existing experiment's record is preserved
    assert not orphan.exists()


def test_missing_jobs_dir_is_a_noop(db, tmp_path: Path) -> None:
    r = reap_orphan_jobs(
        tmp_path / "nope", db, now=datetime.now(UTC), grace=timedelta(hours=24), apply=True
    )
    assert r.removed == [] and r.skipped_recent == 0
