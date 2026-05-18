"""Tenant pubkey → tenant_id registry.

Researcher requests sign with the tenant's Ed25519 maintainer key (the same
key the SDK generates via `auspexai-tenant key generate`). The coordinator
looks up the pubkey to resolve which tenant the signature came from.

M2 implementation: in-memory dict, seeded by configuration or test fixtures.
M4-M5 moves this to the SQLite `tenants` table (`tenant_id`, `maintainer_pubkey`,
`registered_at`, ...) with this module wrapping the repository lookup. The
public API surface (`get_tenant_for_pubkey`) stays stable across that swap.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TenantBinding:
    """Maps a maintainer Ed25519 pubkey to the tenant that owns it."""

    tenant_id: str
    pubkey_hex: str  # lowercase, 64 hex chars (32 bytes)


class TenantRegistry:
    """In-memory pubkey → tenant_id lookup.

    The M2 surface intentionally matches the M4-M5 DB-backed shape so swapping
    is a constructor change. Reads are constant-time-ish (dict lookup); writes
    are infrequent (tenant registration is an operator action).
    """

    def __init__(self) -> None:
        self._bindings: dict[str, TenantBinding] = {}  # pubkey_hex → binding

    def register(self, tenant_id: str, pubkey_hex: str) -> TenantBinding:
        """Bind a tenant's maintainer pubkey. Raises if either the pubkey is
        already bound (to any tenant) or the tenant already has a different
        pubkey registered."""
        pubkey_hex = pubkey_hex.lower()
        self._validate_pubkey_hex(pubkey_hex)
        if pubkey_hex in self._bindings:
            existing = self._bindings[pubkey_hex]
            if existing.tenant_id == tenant_id:
                return existing
            raise ValueError(
                f"pubkey already bound to tenant {existing.tenant_id!r}; "
                f"rejected re-binding to {tenant_id!r}"
            )
        for existing in self._bindings.values():
            if existing.tenant_id == tenant_id:
                raise ValueError(
                    f"tenant {tenant_id!r} already has pubkey {existing.pubkey_hex} registered; "
                    "rotate via the tenant-management API rather than registering a second key"
                )
        binding = TenantBinding(tenant_id=tenant_id, pubkey_hex=pubkey_hex)
        self._bindings[pubkey_hex] = binding
        return binding

    def get_tenant_for_pubkey(self, pubkey_hex: str) -> TenantBinding | None:
        """Lookup by pubkey. Returns None if no tenant is bound to this key."""
        return self._bindings.get(pubkey_hex.lower())

    def unregister(self, pubkey_hex: str) -> bool:
        """Remove a binding. Returns True if a binding existed."""
        return self._bindings.pop(pubkey_hex.lower(), None) is not None

    def all_bindings(self) -> list[TenantBinding]:
        return list(self._bindings.values())

    @staticmethod
    def _validate_pubkey_hex(pubkey_hex: str) -> None:
        if len(pubkey_hex) != 64:
            raise ValueError(f"pubkey_hex must be 64 hex chars (32 bytes); got {len(pubkey_hex)}")
        try:
            bytes.fromhex(pubkey_hex)
        except ValueError as e:
            raise ValueError(f"pubkey_hex is not valid hex: {e}") from e
