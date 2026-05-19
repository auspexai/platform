"""Tests for the ManifestRepository."""

from __future__ import annotations

import pytest

from auspexai_platform.db.repositories import ManifestRepository, TenantRepository
from auspexai_platform.db.repositories.manifests import DuplicateManifestError


def _sample_manifest() -> dict:
    return {
        "tenant_id": "synth-doubler",
        "experiment_id": "doubler-001",
        "models": [],
        "replication_factor": 3,
    }


def _sample_signature() -> dict:
    return {
        "maintainer_pubkey_hex": "a" * 64,
        "signature_b64": "dGVzdA==",
    }


@pytest.fixture
def manifest_repository(db) -> ManifestRepository:
    return ManifestRepository(db)


@pytest.fixture
def synth_tenant(tenant_repository: TenantRepository):
    return tenant_repository.register(tenant_id="synth-doubler", maintainer_pubkey="a" * 64)


def test_hash_manifest_is_stable() -> None:
    manifest_a = {"a": 1, "b": 2}
    manifest_b = {"b": 2, "a": 1}
    assert ManifestRepository.hash_manifest(manifest_a) == ManifestRepository.hash_manifest(
        manifest_b
    )


def test_hash_manifest_is_64_hex_chars() -> None:
    digest = ManifestRepository.hash_manifest({"a": 1})
    assert len(digest) == 64
    int(digest, 16)  # must be valid hex


def test_insert_stores_manifest(manifest_repository: ManifestRepository, synth_tenant) -> None:
    manifest = manifest_repository.insert(
        tenant_id="synth-doubler",
        manifest_json=_sample_manifest(),
        signature_json=_sample_signature(),
    )
    assert manifest.tenant_id == "synth-doubler"
    assert manifest.manifest_json == _sample_manifest()
    assert manifest.signature_json == _sample_signature()
    assert len(manifest.manifest_hash) == 64


def test_insert_duplicate_hash_raises(
    manifest_repository: ManifestRepository, synth_tenant
) -> None:
    manifest_repository.insert(
        tenant_id="synth-doubler",
        manifest_json=_sample_manifest(),
        signature_json=_sample_signature(),
    )
    with pytest.raises(DuplicateManifestError):
        manifest_repository.insert(
            tenant_id="synth-doubler",
            manifest_json=_sample_manifest(),
            signature_json=_sample_signature(),
        )


def test_get_returns_manifest(manifest_repository: ManifestRepository, synth_tenant) -> None:
    inserted = manifest_repository.insert(
        tenant_id="synth-doubler",
        manifest_json=_sample_manifest(),
        signature_json=_sample_signature(),
    )
    got = manifest_repository.get(inserted.manifest_hash)
    assert got is not None
    assert got.manifest_hash == inserted.manifest_hash


def test_get_returns_none_when_absent(manifest_repository: ManifestRepository) -> None:
    assert manifest_repository.get("a" * 64) is None


def test_list_for_tenant_filters(
    manifest_repository: ManifestRepository,
    tenant_repository: TenantRepository,
) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    tenant_repository.register(tenant_id="t-b", maintainer_pubkey="b" * 64)
    manifest_repository.insert(
        tenant_id="t-a",
        manifest_json={"experiment_id": "e1"},
        signature_json={},
    )
    manifest_repository.insert(
        tenant_id="t-a",
        manifest_json={"experiment_id": "e2"},
        signature_json={},
    )
    manifest_repository.insert(
        tenant_id="t-b",
        manifest_json={"experiment_id": "e3"},
        signature_json={},
    )
    a_list = manifest_repository.list_for_tenant("t-a")
    b_list = manifest_repository.list_for_tenant("t-b")
    assert len(a_list) == 2
    assert len(b_list) == 1
    assert all(m.tenant_id == "t-a" for m in a_list)
