"""Tenant pubkey → tenant_id lookup, used by the RFC 9421 signature verifier.

M2 shipped this as an in-memory dict. M5 swaps the implementation to a façade
over `TenantRepository` so the auth path now reads from the SQLite control
DB. The public surface stays stable so callers in `signature.py` /
`dependency.py` are unaffected.

Why keep the façade rather than have callers use the repository directly:
the surface `signature.py` actually needs is narrow — one method,
`get_tenant_for_pubkey`. The repository has a wider surface (CRUD, listing,
etc.). Keeping a small façade keeps the auth layer's seam small.

For convenient construction from tests + CLI, the registry accepts either:
  - A `TenantRepository` (production path)
  - An optional in-process dict (legacy convenience for tests that don't want
    to spin up a DB — discouraged for new tests)

Tests that need both auth and DB use the standard fixtures in `conftest.py`,
which constructs a DB-backed registry. Tests that need just the registry's
API surface should depend on the repository directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from auspexai_platform.db.repositories.tenants import (
    DuplicateTenantError,
    TenantRepository,
)


@dataclass(frozen=True)
class TenantBinding:
    """Auth-layer representation of a registered tenant.

    Narrower than the DB `Tenant` model: the auth path only needs the
    identifying pair, not the metadata fields.
    """

    tenant_id: str
    pubkey_hex: str  # lowercase, 64 hex chars (32-byte Ed25519 pubkey)


class TenantRegistry:
    """DB-backed pubkey → tenant_id lookup.

    Always backed by a `TenantRepository`. The repository must already be
    bound to a migrated `Database` (call `MigrationRunner.apply_all()` first).
    """

    def __init__(self, repository: TenantRepository):
        self._repo = repository

    def register(self, tenant_id: str, pubkey_hex: str) -> TenantBinding:
        """Bind a tenant_id to a maintainer pubkey.

        Pre-M5 the registry validated pubkey shape; the repository now owns
        validation (lowercases, accepts as-is). We retain a length+hex check
        here so an obvious caller mistake surfaces before reaching the DB.
        """
        pubkey_hex = pubkey_hex.lower()
        self._validate_pubkey_hex(pubkey_hex)
        try:
            tenant = self._repo.register(tenant_id=tenant_id, maintainer_pubkey=pubkey_hex)
        except DuplicateTenantError as e:
            # Preserve the ValueError-shaped contract from the M2 surface so
            # callers that catch ValueError keep working.
            raise ValueError(str(e)) from e
        return TenantBinding(tenant_id=tenant.tenant_id, pubkey_hex=tenant.maintainer_pubkey)

    def get_tenant_for_pubkey(self, pubkey_hex: str) -> TenantBinding | None:
        tenant = self._repo.get_by_pubkey(pubkey_hex)
        if tenant is None:
            return None
        return TenantBinding(tenant_id=tenant.tenant_id, pubkey_hex=tenant.maintainer_pubkey)

    def unregister(self, pubkey_hex: str) -> bool:
        tenant = self._repo.get_by_pubkey(pubkey_hex)
        if tenant is None:
            return False
        return self._repo.unregister(tenant.tenant_id)

    def all_bindings(self) -> list[TenantBinding]:
        return [
            TenantBinding(tenant_id=t.tenant_id, pubkey_hex=t.maintainer_pubkey)
            for t in self._repo.list_all()
        ]

    @staticmethod
    def _validate_pubkey_hex(pubkey_hex: str) -> None:
        if len(pubkey_hex) != 64:
            raise ValueError(f"pubkey_hex must be 64 hex chars (32 bytes); got {len(pubkey_hex)}")
        try:
            bytes.fromhex(pubkey_hex)
        except ValueError as e:
            raise ValueError(f"pubkey_hex is not valid hex: {e}") from e
