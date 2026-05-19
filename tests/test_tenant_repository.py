"""Tests for the TenantRepository."""

from __future__ import annotations

import pytest

from auspexai_platform.db.repositories import TenantRepository
from auspexai_platform.db.repositories.tenants import DuplicateTenantError


def test_register_inserts_minimal_tenant(tenant_repository: TenantRepository) -> None:
    tenant = tenant_repository.register(
        tenant_id="synth-doubler",
        maintainer_pubkey="a" * 64,
    )
    assert tenant.tenant_id == "synth-doubler"
    assert tenant.maintainer_pubkey == "a" * 64
    assert tenant.display_name is None
    assert tenant.revision == 1
    assert tenant.registered_at is not None


def test_register_inserts_full_tenant(tenant_repository: TenantRepository) -> None:
    tenant = tenant_repository.register(
        tenant_id="synth-doubler",
        maintainer_pubkey="a" * 64,
        display_name="Synthetic doubler",
        contact_email="contact@example.network",
        contact_public="https://example.network/about",
        description="Integer-doubling synthetic tenant used for SDK testing.",
    )
    assert tenant.display_name == "Synthetic doubler"
    assert tenant.contact_email == "contact@example.network"
    assert tenant.contact_public == "https://example.network/about"
    assert tenant.description.startswith("Integer-doubling")


def test_register_lowercases_pubkey(tenant_repository: TenantRepository) -> None:
    tenant = tenant_repository.register(
        tenant_id="synth-doubler",
        maintainer_pubkey="ABCDEF" + "0" * 58,
    )
    assert tenant.maintainer_pubkey == "abcdef" + "0" * 58


def test_register_duplicate_tenant_id_raises(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    with pytest.raises(DuplicateTenantError):
        tenant_repository.register(tenant_id="t-a", maintainer_pubkey="b" * 64)


def test_register_duplicate_pubkey_raises(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    with pytest.raises(DuplicateTenantError):
        tenant_repository.register(tenant_id="t-b", maintainer_pubkey="a" * 64)


def test_get_by_id_returns_tenant(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    got = tenant_repository.get_by_id("t-a")
    assert got is not None
    assert got.tenant_id == "t-a"


def test_get_by_id_returns_none_when_absent(tenant_repository: TenantRepository) -> None:
    assert tenant_repository.get_by_id("missing") is None


def test_get_by_pubkey_returns_tenant(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    got = tenant_repository.get_by_pubkey("a" * 64)
    assert got is not None
    assert got.tenant_id == "t-a"


def test_get_by_pubkey_lookup_is_case_insensitive(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    got = tenant_repository.get_by_pubkey(("a" * 64).upper())
    assert got is not None


def test_list_all_returns_in_registration_order(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    tenant_repository.register(tenant_id="t-b", maintainer_pubkey="b" * 64)
    tenant_repository.register(tenant_id="t-c", maintainer_pubkey="c" * 64)
    listed = tenant_repository.list_all()
    assert [t.tenant_id for t in listed] == ["t-a", "t-b", "t-c"]


def test_unregister_removes_tenant(tenant_repository: TenantRepository) -> None:
    tenant_repository.register(tenant_id="t-a", maintainer_pubkey="a" * 64)
    assert tenant_repository.unregister("t-a") is True
    assert tenant_repository.get_by_id("t-a") is None


def test_unregister_returns_false_when_absent(tenant_repository: TenantRepository) -> None:
    assert tenant_repository.unregister("missing") is False
