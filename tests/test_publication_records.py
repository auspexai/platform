"""G6+F4 substrate: publication records — coordinator facts beside researcher
claims, and the benchmark-before-DOI prerequisite."""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.migrations import MigrationRunner
from auspexai_platform.db.repositories.publications import PublicationRepository


def _db(tmp_path):
    db = Database(tmp_path / "control.db")
    MigrationRunner(db).apply_all()
    return db


def test_record_roundtrip_and_doi_prereq(tmp_path):
    repo = PublicationRepository(_db(tmp_path))
    assert repo.has_benchmark_publication("exp-a") is False
    rec = repo.record(
        experiment_id="exp-a",
        kind="benchmark",
        tenant_id="vigiles-lab",
        publisher_pubkey="ab" * 32,
        standing_at_issue=2,
        summary={"peak_eu": 6.67, "breadth": 0.33, "reference_experiment_id": "exp-ref"},
        obs_merkle_root="r" * 64,
        obs_rekor_uuid="uuid-obs",
        ref_merkle_root="s" * 64,
        ref_rekor_uuid="uuid-ref",
    )
    assert rec.summary["peak_eu"] == 6.67
    assert rec.obs_rekor_uuid == "uuid-obs"  # coordinator fact rides the record
    assert repo.has_benchmark_publication("exp-a") is True
    assert repo.has_benchmark_publication("exp-b") is False
    rows = repo.list_for_experiment("exp-a")
    assert len(rows) == 1 and rows[0].kind == "benchmark"
