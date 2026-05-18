"""Tests for the tenant pubkey → tenant_id registry."""

from __future__ import annotations

import pytest

from auspexai_platform.auth.tenant_registry import TenantRegistry


def _valid_hex() -> str:
    return "a" * 64


def _other_hex() -> str:
    return "b" * 64


def test_register_returns_binding() -> None:
    reg = TenantRegistry()
    binding = reg.register("tenant-a", _valid_hex())
    assert binding.tenant_id == "tenant-a"
    assert binding.pubkey_hex == _valid_hex()


def test_register_is_idempotent_for_same_pair() -> None:
    reg = TenantRegistry()
    first = reg.register("tenant-a", _valid_hex())
    second = reg.register("tenant-a", _valid_hex())
    assert first == second


def test_register_rejects_pubkey_owned_by_different_tenant() -> None:
    reg = TenantRegistry()
    reg.register("tenant-a", _valid_hex())
    with pytest.raises(ValueError, match="pubkey already bound"):
        reg.register("tenant-b", _valid_hex())


def test_register_rejects_second_pubkey_for_existing_tenant() -> None:
    reg = TenantRegistry()
    reg.register("tenant-a", _valid_hex())
    with pytest.raises(ValueError, match="already has pubkey"):
        reg.register("tenant-a", _other_hex())


def test_get_returns_none_for_unknown_pubkey() -> None:
    reg = TenantRegistry()
    assert reg.get_tenant_for_pubkey(_valid_hex()) is None


def test_get_lookup_is_case_insensitive() -> None:
    reg = TenantRegistry()
    reg.register("tenant-a", _valid_hex())
    upper = _valid_hex().upper()
    assert reg.get_tenant_for_pubkey(upper) is not None


def test_unregister_returns_true_when_present() -> None:
    reg = TenantRegistry()
    reg.register("tenant-a", _valid_hex())
    assert reg.unregister(_valid_hex()) is True
    assert reg.get_tenant_for_pubkey(_valid_hex()) is None


def test_unregister_returns_false_when_absent() -> None:
    reg = TenantRegistry()
    assert reg.unregister(_valid_hex()) is False


def test_register_rejects_wrong_length_pubkey() -> None:
    reg = TenantRegistry()
    with pytest.raises(ValueError, match="64 hex chars"):
        reg.register("tenant-a", "a" * 32)


def test_register_rejects_non_hex_pubkey() -> None:
    reg = TenantRegistry()
    with pytest.raises(ValueError, match="not valid hex"):
        reg.register("tenant-a", "z" * 64)
