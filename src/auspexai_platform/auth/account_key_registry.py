"""Account-key pubkey → account_id lookup, used by the CredentialResolver.

A connected researcher (Tier-1) binds their dashboard key to an account with NO
tenant. This registry is the resolver's third lookup — after tenants + workers —
yielding a CredentialClass.ACCOUNT. A façade over AccountRepository keeps the
auth seam narrow (one method), mirroring TenantRegistry / WorkerRegistry.
"""

from __future__ import annotations

from auspexai_platform.db.repositories import AccountRepository


class AccountKeyRegistry:
    def __init__(self, repository: AccountRepository):
        self._repo = repository

    def get_account_id_for_pubkey(self, pubkey_hex: str) -> str | None:
        return self._repo.get_account_id_for_key(pubkey_hex)
