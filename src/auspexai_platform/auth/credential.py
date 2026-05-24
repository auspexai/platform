"""Credential type — the result of authenticating a request.

Set by the auth dependency; consumed by routes and (M3+) by the field-exposure
filter. The structure carries enough information for filtering: the class
tells us which exposure tags are visible, and `tenant_id` / `worker_id` /
`account_id` resolve scope-specific queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CredentialClass(StrEnum):
    """The six Phase 1+ credential classes.

    Phase 1 (M1-M6) implements five: maintainer (bearer), researcher (RFC
    9421 signed; tenant-pubkey-resolved), anonymous-public, worker (RFC
    9421 signed; worker-pubkey-resolved), and system (M6e: coordinator-
    driven actions like auto-complete; never bound to an HTTP request,
    appears only in audit_log entries).

    ACCOUNT lands Phase 2-3 once accounts authenticate directly rather
    than via a worker they are bound to.
    """

    MAINTAINER = "maintainer"
    RESEARCHER = "researcher"
    ANONYMOUS = "anonymous"
    WORKER = "worker"
    SYSTEM = "system"
    # Phase 2-3:
    ACCOUNT = "account"


@dataclass(frozen=True)
class Credential:
    """An authenticated request's credential context.

    `kind` chooses which exposure tags are visible. Scope fields populated
    per credential class:

      - researcher: tenant_id + pubkey_hex
      - worker: worker_id + pubkey_hex; account_id is set iff the worker has
        upgraded from T0 to T1+ by binding to an account; trust_tier is the
        worker's current tier
      - maintainer / anonymous: all scope fields are None
    """

    kind: CredentialClass
    tenant_id: str | None = None
    pubkey_hex: str | None = None
    worker_id: str | None = None
    account_id: str | None = None
    trust_tier: int | None = None
    maintainer_login: str | None = None

    @classmethod
    def anonymous(cls) -> Credential:
        return cls(kind=CredentialClass.ANONYMOUS)

    @classmethod
    def maintainer(cls, maintainer_login: str | None = None) -> Credential:
        return cls(kind=CredentialClass.MAINTAINER, maintainer_login=maintainer_login)

    @classmethod
    def researcher(cls, tenant_id: str, pubkey_hex: str) -> Credential:
        return cls(
            kind=CredentialClass.RESEARCHER,
            tenant_id=tenant_id,
            pubkey_hex=pubkey_hex,
        )

    @classmethod
    def worker(
        cls,
        *,
        worker_id: str,
        pubkey_hex: str,
        account_id: str | None,
        trust_tier: int,
    ) -> Credential:
        return cls(
            kind=CredentialClass.WORKER,
            pubkey_hex=pubkey_hex,
            worker_id=worker_id,
            account_id=account_id,
            trust_tier=trust_tier,
        )

    def is_maintainer(self) -> bool:
        return self.kind is CredentialClass.MAINTAINER

    def is_researcher(self) -> bool:
        return self.kind is CredentialClass.RESEARCHER

    def is_anonymous(self) -> bool:
        return self.kind is CredentialClass.ANONYMOUS

    def is_worker(self) -> bool:
        return self.kind is CredentialClass.WORKER
