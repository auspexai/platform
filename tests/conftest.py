"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.resolver import CredentialResolver
from auspexai_platform.auth.tenant_registry import TenantBinding, TenantRegistry
from auspexai_platform.auth.worker_registry import WorkerRegistry
from auspexai_platform.config import Config
from auspexai_platform.db import Database, MigrationRunner
from auspexai_platform.db.models import IdentityProvider, Worker
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
    RetiredKeyRepository,
    TenantRepository,
    WorkerRepository,
)
from auspexai_platform.main import create_app
from auspexai_platform.oauth.identity import (
    IdentityClaim,
    InvalidAccessTokenError,
)


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


# ---- M4: storage layer fixtures --------------------------------------------


@pytest.fixture
def db(config: Config) -> Generator[Database, None, None]:
    """Migrated, isolated control DB per test."""
    database = Database(config.control_db_path)
    MigrationRunner(database).apply_all()
    yield database
    database.close()


@pytest.fixture
def tenant_repository(db: Database) -> TenantRepository:
    return TenantRepository(db)


@pytest.fixture
def audit_repository(db: Database) -> AuditRepository:
    return AuditRepository(db)


@pytest.fixture
def account_repository(db: Database) -> AccountRepository:
    return AccountRepository(db)


@pytest.fixture
def worker_repository(db: Database) -> WorkerRepository:
    return WorkerRepository(db)


@pytest.fixture
def retired_key_repository(db: Database) -> RetiredKeyRepository:
    return RetiredKeyRepository(db)


@pytest.fixture
def receipt_index_repository(db: Database):
    from auspexai_platform.db.repositories import ReceiptIndexRepository

    return ReceiptIndexRepository(db)


@pytest.fixture
def worker_registry(worker_repository: WorkerRepository) -> WorkerRegistry:
    return WorkerRegistry(worker_repository)


@pytest.fixture
def credential_resolver(
    tenant_registry: TenantRegistry,
    worker_registry: WorkerRegistry,
) -> CredentialResolver:
    """Resolver wired up to both registries (M6b: tenants + workers)."""
    return CredentialResolver(tenant_registry, worker_registry)


@pytest.fixture
def worker_keypair() -> tuple[Ed25519PrivateKey, str]:
    """(privkey, pubkey_hex) — fresh Ed25519 keypair for a worker."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes.hex()


@pytest.fixture
def enrolled_worker(
    worker_repository: WorkerRepository,
    worker_keypair: tuple[Ed25519PrivateKey, str],
) -> tuple[Ed25519PrivateKey, Worker]:
    """A worker pre-enrolled (T0). Returns (privkey, worker)."""
    priv, pubkey_hex = worker_keypair
    worker = worker_repository.enroll(
        worker_id="wkr-test01",
        pubkey_hex=pubkey_hex,
        capabilities={"os": "linux"},
    )
    return priv, worker


# ---- M6c: per-job DB fixtures ----------------------------------------------


@pytest.fixture
def per_job_factory(config: Config) -> PerJobDatabaseFactory:
    return PerJobDatabaseFactory(config.jobs_dir)


@pytest.fixture
def manifest_repository(db: Database) -> ManifestRepository:
    return ManifestRepository(db)


@pytest.fixture
def experiment_repository(db: Database) -> ExperimentRepository:
    return ExperimentRepository(db)


@pytest.fixture
def approved_experiment(
    registered_tenant,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
):
    """An approved experiment + its researcher privkey, ready for work-unit
    submission. Returns (privkey, tenant_binding, experiment, manifest_hash)."""
    from auspexai_platform.db.models import ExperimentStatus

    privkey, tenant_binding = registered_tenant
    manifest = manifest_repository.insert(
        tenant_id=tenant_binding.tenant_id,
        manifest_json={
            "tenant_id": tenant_binding.tenant_id,
            "experiment_id": "exp-label",
        },
        signature_json={},
    )
    experiment = experiment_repository.create(
        tenant_id=tenant_binding.tenant_id,
        tenant_experiment_label="exp-label",
        manifest_hash=manifest.manifest_hash,
    )
    experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.APPROVED)
    experiment = experiment_repository.get_by_id(experiment.experiment_id)
    return privkey, tenant_binding, experiment, manifest.manifest_hash


# ---- M6a: OAuth identity-verifier fixtures ---------------------------------


class FakeIdentityVerifier:
    """Test double that returns a pre-canned IdentityClaim for a known token,
    and raises `InvalidAccessTokenError` for anything else.

    Tests prime the verifier by calling `register(token, claim)`. The fake
    bypasses any IdP HTTP calls — production verifiers (GitHubVerifier) get
    their own tests in `test_oauth_github.py`.
    """

    def __init__(self):
        self._claims: dict[tuple[IdentityProvider, str], IdentityClaim] = {}

    def register(
        self,
        access_token: str,
        claim: IdentityClaim,
    ) -> None:
        self._claims[(claim.idp, access_token)] = claim

    def verify(self, idp: IdentityProvider, access_token: str) -> IdentityClaim:
        claim = self._claims.get((idp, access_token))
        if claim is None:
            raise InvalidAccessTokenError(
                f"fake verifier: no claim registered for ({idp.value}, <token>)"
            )
        return claim


@pytest.fixture
def identity_verifier() -> FakeIdentityVerifier:
    return FakeIdentityVerifier()


@pytest.fixture
def tenant_registry(tenant_repository: TenantRepository) -> TenantRegistry:
    """DB-backed registry (M5+). Same surface as the M2 in-memory version
    so existing tests keep working."""
    return TenantRegistry(tenant_repository)


@pytest.fixture
def client(
    config: Config,
    token_store: TokenStore,
    tenant_registry: TenantRegistry,
    db: Database,
    identity_verifier: FakeIdentityVerifier,
) -> Generator[TestClient, None, None]:
    """TestClient with all M2-M6 layers wired up."""
    app = create_app(
        config=config,
        token_store=token_store,
        tenant_registry=tenant_registry,
        db=db,
        identity_verifier=identity_verifier,
    )
    with TestClient(app) as c:
        yield c
