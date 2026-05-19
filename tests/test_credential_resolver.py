"""CredentialResolver tests — keyid → credential dispatch (tenant or worker)."""

from __future__ import annotations

from auspexai_platform.auth.resolver import CredentialResolver
from auspexai_platform.db.models import TrustTier
from auspexai_platform.db.repositories import WorkerRepository


def test_resolve_unknown_returns_none(credential_resolver: CredentialResolver) -> None:
    assert credential_resolver.resolve("a" * 64) is None


def test_resolve_returns_researcher_for_tenant_pubkey(
    registered_tenant,
    credential_resolver: CredentialResolver,
) -> None:
    _, binding = registered_tenant
    credential = credential_resolver.resolve(binding.pubkey_hex)
    assert credential is not None
    assert credential.is_researcher()
    assert credential.tenant_id == binding.tenant_id
    assert credential.pubkey_hex == binding.pubkey_hex


def test_resolve_returns_worker_for_enrolled_pubkey(
    enrolled_worker,
    credential_resolver: CredentialResolver,
) -> None:
    _, worker = enrolled_worker
    credential = credential_resolver.resolve(worker.pubkey_hex)
    assert credential is not None
    assert credential.is_worker()
    assert credential.worker_id == worker.worker_id
    assert credential.pubkey_hex == worker.pubkey_hex
    assert credential.account_id is None  # T0 anonymous
    assert credential.trust_tier == int(TrustTier.T0_ANONYMOUS)


def test_resolve_skips_retired_workers(
    enrolled_worker,
    credential_resolver: CredentialResolver,
    worker_repository: WorkerRepository,
) -> None:
    _, worker = enrolled_worker
    worker_repository.retire(worker.worker_id)
    assert credential_resolver.resolve(worker.pubkey_hex) is None


def test_resolve_tenant_takes_precedence_over_worker(
    registered_tenant,
    worker_repository: WorkerRepository,
    credential_resolver: CredentialResolver,
) -> None:
    """Defense in depth: even if a pubkey somehow appears in both tables
    (enrollment-time guard normally prevents this), the resolver returns the
    researcher credential, not the worker. Tests that tenant-first ordering
    is honored."""
    _, binding = registered_tenant
    # Force-enroll a worker with the *same* pubkey at the repo layer (bypasses
    # the route's cross-table check). This is an internal-only path used only
    # to exercise the resolver's precedence rule.
    worker_repository.enroll(worker_id="wkr-collide", pubkey_hex=binding.pubkey_hex)
    credential = credential_resolver.resolve(binding.pubkey_hex)
    assert credential is not None
    assert credential.is_researcher()
