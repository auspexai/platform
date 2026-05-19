"""Tests for the migration runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from auspexai_platform.db import Database, MigrationError, MigrationRunner


def _write_migration(directory: Path, name: str, sql: str) -> None:
    (directory / name).write_text(sql)


def test_apply_all_runs_one_migration(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")

    runner = MigrationRunner(db, migrations)
    applied = runner.apply_all()
    assert applied == [1]
    # Table exists.
    db.execute("INSERT INTO t VALUES (42)")
    assert db.execute("SELECT a FROM t")[0]["a"] == 42
    db.close()


def test_apply_all_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")

    runner = MigrationRunner(db, migrations)
    assert runner.apply_all() == [1]
    assert runner.apply_all() == []
    db.close()


def test_apply_all_records_schema_migrations(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")
    _write_migration(migrations, "0002_add_b.sql", "ALTER TABLE t ADD COLUMN b TEXT")

    runner = MigrationRunner(db, migrations)
    runner.apply_all()
    rows = db.execute("SELECT version, name FROM schema_migrations ORDER BY version")
    assert [(r["version"], r["name"]) for r in rows] == [(1, "init"), (2, "add_b")]
    db.close()


def test_applied_versions_reflects_history(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")
    _write_migration(migrations, "0002_add_b.sql", "ALTER TABLE t ADD COLUMN b TEXT")

    runner = MigrationRunner(db, migrations)
    assert runner.applied_versions() == []
    runner.apply_all()
    assert runner.applied_versions() == [1, 2]
    db.close()


def test_pending_versions_lists_unapplied(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")
    runner = MigrationRunner(db, migrations)

    assert runner.pending_versions() == [1]
    runner.apply_all()
    assert runner.pending_versions() == []

    _write_migration(migrations, "0002_add_b.sql", "ALTER TABLE t ADD COLUMN b TEXT")
    assert runner.pending_versions() == [2]
    db.close()


def test_missing_directory_raises(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    runner = MigrationRunner(db, tmp_path / "does-not-exist")
    with pytest.raises(MigrationError, match="not found"):
        runner.apply_all()
    db.close()


def test_non_sequential_versions_rejected(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "0001_init.sql", "CREATE TABLE t (a INTEGER)")
    _write_migration(migrations, "0003_skipped.sql", "ALTER TABLE t ADD COLUMN c TEXT")
    runner = MigrationRunner(db, migrations)
    with pytest.raises(MigrationError, match="sequential"):
        runner.apply_all()
    db.close()


def test_malformed_filename_rejected(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    _write_migration(migrations, "no_version_prefix.sql", "CREATE TABLE t (a INTEGER)")
    runner = MigrationRunner(db, migrations)
    with pytest.raises(MigrationError, match="pattern"):
        runner.apply_all()
    db.close()


def test_bundled_initial_migration_creates_tenants_and_audit(tmp_path: Path) -> None:
    """The shipped 0001_init.sql creates the tables the rest of the system expects."""
    db = Database(tmp_path / "test.db")
    runner = MigrationRunner(db)  # use default migrations_sql/ dir
    applied = runner.apply_all()
    assert applied == [1]
    # Tables exist + accept the expected columns.
    db.execute(
        """
        INSERT INTO tenants (tenant_id, maintainer_pubkey, registered_at)
        VALUES (?, ?, '2026-05-18T00:00:00+00:00')
        """,
        ("synth-doubler", "a" * 64),
    )
    rows = db.execute("SELECT tenant_id, maintainer_pubkey, revision FROM tenants")
    assert rows[0]["tenant_id"] == "synth-doubler"
    assert rows[0]["revision"] == 1
    db.execute(
        """
        INSERT INTO audit_log (
            occurred_at, actor_class, action
        ) VALUES ('2026-05-18T00:00:00+00:00', 'maintainer', 'tenant.register')
        """
    )
    audit_rows = db.execute("SELECT action FROM audit_log")
    assert audit_rows[0]["action"] == "tenant.register"
    db.close()
