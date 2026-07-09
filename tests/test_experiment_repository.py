"""Tests for the ExperimentRepository."""

from __future__ import annotations

import pytest

from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.repositories import (
    ExperimentRepository,
    ManifestRepository,
    TenantRepository,
)
from auspexai_platform.db.repositories.experiments import (
    DuplicateExperimentLabelError,
    ExperimentNotFoundError,
    InvalidStatusTransitionError,
)


@pytest.fixture
def manifest_repository(db) -> ManifestRepository:
    return ManifestRepository(db)


@pytest.fixture
def experiment_repository(db) -> ExperimentRepository:
    return ExperimentRepository(db)


@pytest.fixture
def synth_setup(
    tenant_repository: TenantRepository,
    manifest_repository: ManifestRepository,
) -> tuple[str, str]:
    """Returns (tenant_id, manifest_hash) ready to create experiments against."""
    tenant_repository.register(tenant_id="synth-doubler", maintainer_pubkey="a" * 64)
    manifest = manifest_repository.insert(
        tenant_id="synth-doubler",
        manifest_json={"experiment_id": "doubler-001", "x": 1},
        signature_json={},
    )
    return "synth-doubler", manifest.manifest_hash


def test_create_inserts_submitted_experiment(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    exp = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label="doubler-001",
        manifest_hash=manifest_hash,
    )
    assert exp.tenant_id == tenant_id
    assert exp.tenant_experiment_label == "doubler-001"
    assert exp.status is ExperimentStatus.SUBMITTED
    assert exp.experiment_id.startswith("exp-")
    assert exp.started_at is None
    assert exp.completed_at is None
    assert exp.revision == 1


def test_create_generates_unique_experiment_ids(
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
    synth_setup,
) -> None:
    tenant_id, manifest_hash = synth_setup
    # Submit two manifests with different content so they have distinct hashes.
    m2 = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"experiment_id": "doubler-002"},
        signature_json={},
    )
    e1 = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    e2 = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d2", manifest_hash=m2.manifest_hash
    )
    assert e1.experiment_id != e2.experiment_id


def test_create_duplicate_label_within_tenant_raises(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    with pytest.raises(DuplicateExperimentLabelError):
        experiment_repository.create(
            tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
        )


def test_create_same_label_across_tenants_allowed(
    experiment_repository: ExperimentRepository,
    tenant_repository: TenantRepository,
    manifest_repository: ManifestRepository,
) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    tenant_repository.register(tenant_id="t-b", maintainer_pubkey="b" * 64)
    # Manifest content must differ for distinct content-addressed hashes; we
    # include the tenant_id in the manifest body to disambiguate (matches the
    # SDK manifest schema, which carries tenant_id as a field).
    ma = manifest_repository.insert(
        tenant_id="t-a",
        manifest_json={"tenant_id": "t-a", "experiment_id": "shared"},
        signature_json={},
    )
    mb = manifest_repository.insert(
        tenant_id="t-b",
        manifest_json={"tenant_id": "t-b", "experiment_id": "shared"},
        signature_json={},
    )
    ea = experiment_repository.create(
        tenant_id="t-a", tenant_experiment_label="shared", manifest_hash=ma.manifest_hash
    )
    eb = experiment_repository.create(
        tenant_id="t-b", tenant_experiment_label="shared", manifest_hash=mb.manifest_hash
    )
    assert ea.experiment_id != eb.experiment_id


def test_update_status_advances_state(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    approved = experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    assert approved.status is ExperimentStatus.APPROVED
    assert approved.started_at is not None
    assert approved.revision == 2


def test_update_status_invalid_transition_raises(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    with pytest.raises(InvalidStatusTransitionError, match="not an allowed transition"):
        experiment_repository.update_status(exp.experiment_id, ExperimentStatus.ARCHIVED)


def test_update_status_aborted_then_archived(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    aborted = experiment_repository.update_status(exp.experiment_id, ExperimentStatus.ABORTED)
    assert aborted.completed_at is not None
    archived = experiment_repository.update_status(exp.experiment_id, ExperimentStatus.ARCHIVED)
    assert archived.status is ExperimentStatus.ARCHIVED


def test_update_status_revision_mismatch_raises(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    tenant_id, manifest_hash = synth_setup
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    with pytest.raises(InvalidStatusTransitionError, match="revision mismatch"):
        experiment_repository.update_status(
            exp.experiment_id, ExperimentStatus.APPROVED, expected_revision=99
        )


def test_update_status_unknown_id_raises(
    experiment_repository: ExperimentRepository,
) -> None:
    with pytest.raises(ExperimentNotFoundError):
        experiment_repository.update_status("exp-missing", ExperimentStatus.APPROVED)


def test_list_filters_by_tenant(
    experiment_repository: ExperimentRepository,
    tenant_repository: TenantRepository,
    manifest_repository: ManifestRepository,
) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    tenant_repository.register(tenant_id="t-b", maintainer_pubkey="b" * 64)
    ma = manifest_repository.insert(
        tenant_id="t-a", manifest_json={"experiment_id": "e1"}, signature_json={}
    )
    mb = manifest_repository.insert(
        tenant_id="t-b", manifest_json={"experiment_id": "e2"}, signature_json={}
    )
    experiment_repository.create(
        tenant_id="t-a", tenant_experiment_label="e1", manifest_hash=ma.manifest_hash
    )
    experiment_repository.create(
        tenant_id="t-b", tenant_experiment_label="e2", manifest_hash=mb.manifest_hash
    )
    assert len(experiment_repository.list_all(tenant_id="t-a")) == 1
    assert len(experiment_repository.list_all(tenant_id="t-b")) == 1
    assert len(experiment_repository.list_all()) == 2


def test_list_filters_by_status(experiment_repository: ExperimentRepository, synth_setup) -> None:
    tenant_id, manifest_hash = synth_setup
    exp_a = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="d1", manifest_hash=manifest_hash
    )
    # Make a second manifest + experiment so the listing has variety.
    # Then approve the first one so listings differ.
    experiment_repository.update_status(exp_a.experiment_id, ExperimentStatus.APPROVED)
    submitted = experiment_repository.list_all(status=ExperimentStatus.SUBMITTED)
    approved = experiment_repository.list_all(status=ExperimentStatus.APPROVED)
    assert len(submitted) == 0
    assert len(approved) == 1


def test_create_and_read_back_required_capabilities_with_model_ram_gb(
    experiment_repository: ExperimentRepository, synth_setup
) -> None:
    """Regression: `required_capabilities` carries `model_ram_gb` (a dict, from the
    fleet-fit routing gate) alongside `models` (a list). The field must accept the
    heterogeneous value and READ BACK without a validation error — the row round-trip
    that a raw `dict[str, list[str]]` type broke with a 500 on submit + list."""
    tenant_id, manifest_hash = synth_setup
    caps = {
        "models": ["mistral-7b-instruct-v0.3-q4"],
        "model_ram_gb": {"mistral-7b-instruct-v0.3-q4": 5.24},
    }
    exp = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label="fleet-fit-roundtrip",
        manifest_hash=manifest_hash,
        required_capabilities=caps,
    )
    assert exp.required_capabilities == caps
    # The read-back path that 500'd: list_all + get re-validate the Experiment row.
    got = next(e for e in experiment_repository.list_all() if e.experiment_id == exp.experiment_id)
    assert got.required_capabilities["model_ram_gb"] == {"mistral-7b-instruct-v0.3-q4": 5.24}
    assert got.required_capabilities["models"] == ["mistral-7b-instruct-v0.3-q4"]
