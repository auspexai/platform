"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.tenant_registry import TenantBinding, TenantRegistry
from auspexai_platform.config import Config
from auspexai_platform.main import create_app


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Isolated state directory per test."""
    d = tmp_path / "state"
    d.mkdir()
    return d


@pytest.fixture
def config(state_dir: Path) -> Config:
    return Config(state_dir=state_dir)


@pytest.fixture
def token_store(config: Config) -> TokenStore:
    """Initialized TokenStore with one active maintainer token."""
    store = TokenStore(config.maintainer_token_path)
    store.initialize()
    return store


@pytest.fixture
def maintainer_token(token_store: TokenStore) -> str:
    """The active maintainer token from `token_store`."""
    return token_store.active_tokens()[0]


@pytest.fixture
def tenant_registry() -> TenantRegistry:
    return TenantRegistry()


@pytest.fixture
def tenant_keypair() -> tuple[Ed25519PrivateKey, str]:
    """(privkey, pubkey_hex) — fresh Ed25519 keypair per test."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes.hex()


@pytest.fixture
def registered_tenant(
    tenant_registry: TenantRegistry,
    tenant_keypair: tuple[Ed25519PrivateKey, str],
) -> tuple[Ed25519PrivateKey, TenantBinding]:
    """A tenant pre-registered with the registry. Returns (privkey, binding)."""
    priv, pubkey_hex = tenant_keypair
    binding = tenant_registry.register(tenant_id="synth-doubler", pubkey_hex=pubkey_hex)
    return priv, binding


@pytest.fixture
def client(
    config: Config,
    token_store: TokenStore,
    tenant_registry: TenantRegistry,
) -> Generator[TestClient, None, None]:
    """TestClient with all M2 layers wired up."""
    app = create_app(config=config, token_store=token_store, tenant_registry=tenant_registry)
    with TestClient(app) as c:
        yield c
