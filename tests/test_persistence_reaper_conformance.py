"""A11 persistence conformance — every persistent table must carry a bounded-
growth decision in `persistence_registry` (REAPED or GROWS_BY_DESIGN).

The D22-B leak (243 results polled forever) was a persistent artifact with no
reaper that the behavior suite never caught. This test generalizes the fix: it
fails the moment a migration adds a table not classified in the registry, so a
new persistent table CANNOT ship without someone making the bounded-growth
decision. Mirrors the A6 firewall-conformance named-index pattern.
"""

from __future__ import annotations

from pathlib import Path

from auspexai_platform.db.database import Database
from auspexai_platform.db.migrations import MigrationRunner
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.persistence_registry import (
    CONTROL_DB_PERSISTENCE,
    NON_TABLE_ARTIFACTS,
    PER_JOB_DB_PERSISTENCE,
)

_TABLES_Q = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"


def _tables(database: Database) -> set[str]:
    return {r["name"] for r in database.execute(_TABLES_Q)}


def test_control_schema_exactly_matches_registry(tmp_path: Path) -> None:
    db = Database(tmp_path / "coordinator.db")
    MigrationRunner(db).apply_all()
    live = _tables(db)
    registered = set(CONTROL_DB_PERSISTENCE)
    unregistered = live - registered
    stale = registered - live
    assert not unregistered, (
        "NEW persistent control table(s) shipped without a bounded-growth decision — "
        f"classify in persistence_registry (REAPED or GROWS_BY_DESIGN): {sorted(unregistered)}"
    )
    assert not stale, (
        f"persistence_registry lists control table(s) that no longer exist: {sorted(stale)}"
    )


def test_perjob_schema_exactly_matches_registry(tmp_path: Path) -> None:
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    pj = factory.get_or_create("exp-conformance")
    live = _tables(pj)
    factory.close_all()
    registered = set(PER_JOB_DB_PERSISTENCE)
    assert live == registered, (
        "per-job schema ↔ registry mismatch — "
        f"new (classify me): {sorted(live - registered)}; stale: {sorted(registered - live)}"
    )


def test_every_entry_is_a_valid_bounded_growth_decision() -> None:
    everything = {**CONTROL_DB_PERSISTENCE, **PER_JOB_DB_PERSISTENCE, **NON_TABLE_ARTIFACTS}
    for name, p in everything.items():
        # Exactly one of reaper / grows_by_design (also enforced at construction).
        assert bool(p.reaper) != bool(p.grows_by_design), name
        rationale = p.reaper or p.grows_by_design or ""
        assert len(rationale.strip()) >= 10, f"{name}: rationale is too thin to be a real decision"
