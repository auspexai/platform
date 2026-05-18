"""Credential type — the result of authenticating a request.

Set by the auth dependency; consumed by routes and (M3+) by the field-exposure
filter. The structure carries enough information for filtering: the class
tells us which exposure tags are visible, and `tenant_id` resolves tenant-
scoped queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CredentialClass(StrEnum):
    """The four Phase 1+ credential classes.

    Three are implemented in Phase 1 (maintainer, researcher, anonymous); the
    fourth (T1+ account) lands Phase 2-3 as a filter addition. Defined here
    so other modules can reference it without forward-references.
    """

    MAINTAINER = "maintainer"
    RESEARCHER = "researcher"
    ANONYMOUS = "anonymous"
    # Phase 2-3:
    ACCOUNT = "account"


@dataclass(frozen=True)
class Credential:
    """An authenticated request's credential context.

    `kind` chooses which exposure tags are visible. `tenant_id` is set for
    researcher credentials (used by tenant-scoped queries); None for the others.
    `pubkey_hex` is the hex-encoded Ed25519 pubkey that signed the request, set
    for researcher credentials so the audit log can attribute the action.
    """

    kind: CredentialClass
    tenant_id: str | None = None
    pubkey_hex: str | None = None

    @classmethod
    def anonymous(cls) -> Credential:
        return cls(kind=CredentialClass.ANONYMOUS)

    @classmethod
    def maintainer(cls) -> Credential:
        return cls(kind=CredentialClass.MAINTAINER)

    @classmethod
    def researcher(cls, tenant_id: str, pubkey_hex: str) -> Credential:
        return cls(kind=CredentialClass.RESEARCHER, tenant_id=tenant_id, pubkey_hex=pubkey_hex)

    def is_maintainer(self) -> bool:
        return self.kind is CredentialClass.MAINTAINER

    def is_researcher(self) -> bool:
        return self.kind is CredentialClass.RESEARCHER

    def is_anonymous(self) -> bool:
        return self.kind is CredentialClass.ANONYMOUS
