"""PerJobDatabaseFactory tests — lazy per-experiment DB lifecycle."""

from __future__ import annotations

from pathlib import Path

from auspexai_platform.db.per_job import PerJobDatabaseFactory


def test_get_or_create_creates_db_file(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    db = factory.get_or_create("exp-1")
    assert db is not None
    assert (tmp_path / "jobs" / "exp-1.db").exists()


def test_get_or_create_applies_schema(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    db = factory.get_or_create("exp-1")
    # work_units table exists after schema is applied.
    rows = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='work_units'")
    assert len(rows) == 1


def test_get_or_create_returns_cached_db(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    first = factory.get_or_create("exp-1")
    second = factory.get_or_create("exp-1")
    assert first is second


def test_different_experiments_get_different_dbs(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    a = factory.get_or_create("exp-a")
    b = factory.get_or_create("exp-b")
    assert a is not b
    assert (tmp_path / "jobs" / "exp-a.db").exists()
    assert (tmp_path / "jobs" / "exp-b.db").exists()


def test_get_returns_none_when_no_file(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    assert factory.get("exp-never") is None


def test_get_returns_cached_after_create(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    created = factory.get_or_create("exp-1")
    assert factory.get("exp-1") is created


def test_get_loads_existing_file_on_cold_factory(tmp_path: Path) -> None:
    """Coordinator restart case: file exists on disk, factory is fresh."""
    first_factory = PerJobDatabaseFactory(tmp_path / "jobs")
    first_factory.get_or_create("exp-1")
    first_factory.close_all()

    # Fresh factory, same dir.
    second_factory = PerJobDatabaseFactory(tmp_path / "jobs")
    loaded = second_factory.get("exp-1")
    assert loaded is not None
    rows = loaded.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='work_units'")
    assert len(rows) == 1
