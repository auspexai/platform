"""CredentialResolver — resolves an RFC 9421 keyid to a Credential.

Phase 1 has two RFC-9421-using credential classes: `researcher` (keyid
matches a tenant's maintainer_pubkey) and `worker` (keyid matches an
enrolled worker's pubkey). The signature verifier in `auth/signature.py`
calls `resolve()` exactly once per request to turn a keyid into the
credential that flows to routes.

A pubkey should never be registered as both a tenant maintainer pubkey
AND a worker pubkey — they're different roles. Enforcement is at
worker-enrollment time (the worker route checks both registries before
inserting). The resolver tries tenants first for defense-in-depth: if a
collision somehow exists, tenant takes precedence.
"""

from __future__ import annotations

from auspexai_platform.auth.account_key_registry import AccountKeyRegistry
from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.auth.worker_registry import WorkerRegistry


class CredentialResolver:
    def __init__(
        self,
        tenant_registry: TenantRegistry,
        worker_registry: WorkerRegistry,
        account_key_registry: AccountKeyRegistry | None = None,
    ):
        self._tenants = tenant_registry
        self._workers = worker_registry
        self._accounts = account_key_registry

    def resolve(self, pubkey_hex: str) -> Credential | None:
        """Resolve a keyid to a Credential, or None if unknown.

        Tries tenant registry first, then worker registry. Returns None if
        the pubkey is not registered in either (the verifier turns that
        into InvalidSignatureError).
        """
        tenant = self._tenants.get_tenant_for_pubkey(pubkey_hex)
        if tenant is not None:
            return Credential.researcher(
                tenant_id=tenant.tenant_id,
                pubkey_hex=pubkey_hex,
                account_id=tenant.account_id,
            )
        worker = self._workers.get_worker_for_pubkey(pubkey_hex)
        if worker is not None:
            return Credential.worker(
                worker_id=worker.worker_id,
                pubkey_hex=pubkey_hex,
                account_id=worker.account_id,
                trust_tier=int(worker.trust_tier),
            )
        # Tier-1: a connected researcher's key bound directly to an account (no
        # tenant). Last — a tenant owner (Tier-2) takes precedence above.
        if self._accounts is not None:
            account_id = self._accounts.get_account_id_for_pubkey(pubkey_hex)
            if account_id is not None:
                return Credential.account(account_id=account_id, pubkey_hex=pubkey_hex)
        return None
