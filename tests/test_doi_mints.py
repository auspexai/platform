"""DoiMintRepository (0060) — the crash-safe bookkeeping that makes the Zenodo
DOI mint idempotent/resumable. Pins the upsert semantics: a reserved draft is
recorded before publish, mark_published is terminal, and a stray re-reserve after
publish can never walk the row back to 'draft'."""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.migrations import MigrationRunner
from auspexai_platform.db.repositories.doi_mints import DoiMintRepository
from auspexai_platform.db.repositories.experiments import ExperimentRepository
from auspexai_platform.db.repositories.manifests import ManifestRepository
from auspexai_platform.db.repositories.tenants import TenantRepository


def _db(tmp_path):
    db = Database(tmp_path / "control.db")
    MigrationRunner(db).apply_all()
    return db


def _experiment(db) -> str:
    # Satisfy the FK chain: tenant → manifest → experiment.
    TenantRepository(db).register(tenant_id="vigiles-lab", maintainer_pubkey="aa" * 32)
    m = ManifestRepository(db).insert(
        tenant_id="vigiles-lab",
        manifest_json={"tenant_id": "vigiles-lab", "experiment_id": "doi-mint-test", "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    exp = ExperimentRepository(db).create(
        tenant_id="vigiles-lab",
        tenant_experiment_label="doi-mint-test",
        manifest_hash=m.manifest_hash,
    )
    return exp.experiment_id


def test_draft_then_published_roundtrip(tmp_path):
    db = _db(tmp_path)
    repo = DoiMintRepository(db)
    exp = _experiment(db)
    assert repo.get(exp) is None

    repo.record_draft(
        exp,
        attestation_id="att-1",
        record_id="rec-1",
        reserved_doi="10.5072/zenodo.1",
        mode="sandbox",
    )
    m = repo.get(exp)
    assert m.status == "draft"
    assert m.record_id == "rec-1"
    assert m.reserved_doi == "10.5072/zenodo.1"
    assert m.doi is None  # not published yet

    repo.mark_published(exp, doi="10.5072/zenodo.1", record_url="https://x/1", mode="sandbox")
    m = repo.get(exp)
    assert m.status == "published"
    assert m.doi == "10.5072/zenodo.1"
    assert m.record_url == "https://x/1"


def test_published_row_never_walks_back_to_draft(tmp_path):
    # A stray retry that re-reserves a draft after the mint already published must
    # NOT downgrade the terminal row — that would re-open the double-mint window.
    db = _db(tmp_path)
    repo = DoiMintRepository(db)
    exp = _experiment(db)
    repo.record_draft(
        exp, attestation_id="att-1", record_id="rec-1", reserved_doi="d", mode="sandbox"
    )
    repo.mark_published(exp, doi="10.5072/zenodo.1", record_url=None)

    repo.record_draft(
        exp, attestation_id="att-1", record_id="rec-2", reserved_doi="d2", mode="sandbox"
    )
    m = repo.get(exp)
    assert m.status == "published"  # stayed terminal
    assert m.doi == "10.5072/zenodo.1"
