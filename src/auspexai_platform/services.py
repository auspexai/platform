"""FastAPI-free factory for the coordinator's data / integrity wiring.

`create_app()` (the FastAPI composition root in `main.py`) and any out-of-band
maintenance job (e.g. a future settle-sweep) both need the exact same set of
repositories, the persistent receipt-signing key, the eligibility thresholds,
and the small family of decision closures that read trust state from the DB.

`build_coordinator_services()` constructs that bundle once, with no FastAPI /
web dependency, so the serving layer and an offline job stay byte-identical in
how they wire the integrity-bearing pieces.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from auspexai_platform.config import Config
from auspexai_platform.db import Database, MigrationRunner
from auspexai_platform.db.models import TrustTier
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AccountRepository,
    AssessmentPolicyRepository,
    AttestationRepository,
    AuditRepository,
    CertifiedProfileRepository,
    ExperimentRepository,
    ManifestRepository,
    ModelPrestageRepository,
    ModelRequestRepository,
    PromotionPolicyRepository,
    ReceiptIndexRepository,
    ReleaseRepository,
    ResultTransferRepository,
    RetiredKeyRepository,
    SoftwareRequestRepository,
    TenantApplicationRepository,
    TenantRepository,
    TrustModelPolicyRepository,
    WorkerRepository,
)
from auspexai_platform.db.repositories.vouches import VouchRepository
from auspexai_platform.eligibility import EligibilityThresholds
from auspexai_platform.receipts import load_or_generate_signing_key
from auspexai_platform.receipts.signing import SigningKey


@dataclass(frozen=True)
class CoordinatorServices:
    """The coordinator's data / integrity wiring, FastAPI-free.

    Carries the control-DB connection, every repository, the per-job DB
    factory, the persistent receipt-signing key, the eligibility thresholds,
    and the six decision closures (exposed without the leading underscore the
    nested defs use inside `create_app`).
    """

    config: Config
    db: Database
    account_repository: AccountRepository
    assessment_policy_repository: AssessmentPolicyRepository
    promotion_policy_repository: PromotionPolicyRepository
    trust_model_policy_repository: TrustModelPolicyRepository
    tenant_repository: TenantRepository
    manifest_repository: ManifestRepository
    experiment_repository: ExperimentRepository
    audit_repository: AuditRepository
    worker_repository: WorkerRepository
    retired_key_repository: RetiredKeyRepository
    receipt_index_repository: ReceiptIndexRepository
    attestation_repository: AttestationRepository
    certified_profile_repository: CertifiedProfileRepository
    result_transfer_repository: ResultTransferRepository
    model_request_repository: ModelRequestRepository
    model_prestage_repository: ModelPrestageRepository
    software_request_repository: SoftwareRequestRepository
    tenant_application_repository: TenantApplicationRepository
    release_repository: ReleaseRepository
    vouch_repository: VouchRepository
    per_job_factory: PerJobDatabaseFactory
    receipt_signing_key: SigningKey
    eligibility_thresholds: EligibilityThresholds
    account_suspended_for_tenant: Callable[[str], bool]
    tenant_tier: Callable[[str], int]
    approved_classes: Callable[[str], list[str] | None]
    auto_approval_gate: Callable[[], tuple[bool, int]]
    governance_footprint_for: Callable
    promotion_auto_t1_t2: Callable[[], bool]


def build_coordinator_services(
    config: Config, *, db: Database | None = None
) -> CoordinatorServices:
    """Construct the coordinator's data / integrity wiring.

    Args:
        config: runtime configuration.
        db: control-DB connection. If None, opened at `config.control_db_path`.
            Migrations are applied unconditionally (idempotent).
    """
    db = db or Database(config.control_db_path)

    # Apply pending migrations on every startup. Idempotent: no-op if
    # already up-to-date.
    MigrationRunner(db).apply_all()

    account_repository = AccountRepository(db)
    assessment_policy_repository = AssessmentPolicyRepository(db)
    promotion_policy_repository = PromotionPolicyRepository(db)
    trust_model_policy_repository = TrustModelPolicyRepository(db)
    tenant_repository = TenantRepository(db)
    manifest_repository = ManifestRepository(db)
    experiment_repository = ExperimentRepository(db)
    audit_repository = AuditRepository(db)
    worker_repository = WorkerRepository(db)
    retired_key_repository = RetiredKeyRepository(db)
    receipt_index_repository = ReceiptIndexRepository(db)
    attestation_repository = AttestationRepository(db)
    certified_profile_repository = CertifiedProfileRepository(db)
    result_transfer_repository = ResultTransferRepository(db)
    model_request_repository = ModelRequestRepository(db)
    model_prestage_repository = ModelPrestageRepository(db)
    software_request_repository = SoftwareRequestRepository(db)
    tenant_application_repository = TenantApplicationRepository(db)
    release_repository = ReleaseRepository(db)
    vouch_repository = VouchRepository(db)
    per_job_factory = PerJobDatabaseFactory(config.jobs_dir)

    # M7b: load or generate the persistent receipt-signing key. The same
    # key file is used in both `dev` and `operational` receipts_mode; the
    # mode flag controls how the verifier endpoint (M7d) renders the trust
    # posture of the resulting receipts, not which key signs them.
    receipt_signing_key = load_or_generate_signing_key(config.receipt_signing_key_path)

    def _account_suspended_for_tenant(tenant_id: str) -> bool:
        # F5: tenant → account → suspended? (legacy tenants without an account
        # have no accountability root, so they never cascade.)
        tenant = tenant_repository.get_by_id(tenant_id)
        if tenant is None or tenant.account_id is None:
            return False
        account = account_repository.get_by_id(tenant.account_id)
        return account is not None and account.suspended_at is not None

    def _tenant_tier(tenant_id: str) -> int:
        # §9 #48: tenant → account → trust_tier. A tenant without an account
        # (legacy) has no earned trust, so it floors at T1 — below the T2
        # auto-approval threshold, i.e. it always routes to human review.
        tenant = tenant_repository.get_by_id(tenant_id)
        if tenant is None or tenant.account_id is None:
            return int(TrustTier.T1_AUTHENTICATED)
        account = account_repository.get_by_id(tenant.account_id)
        return int(account.trust_tier) if account is not None else int(TrustTier.T1_AUTHENTICATED)

    def _approved_classes(tenant_id: str) -> list[str] | None:
        # §9 #48 envelope scope check: the classes the tenant was approved for.
        return tenant_application_repository.approved_classes_for_tenant(tenant_id)

    def _auto_approval_gate() -> tuple[bool, int]:
        # §9 #48 inc-4: the maintainer's runtime auto-approval gate, read at
        # decision time so the console toggle is authoritative. Default DISABLED.
        policy = assessment_policy_repository.get()
        return policy.enabled, policy.min_tier

    def _governance_footprint_for(experiment, entries, diverged_units, per_job_db):
        # Firewall #2: assemble the COSE-signed governance footprint for an
        # experiment's attestation from control + per-job state (the asserted half;
        # the recomputable integrity_basis half comes from entries/diverged_units).
        from auspexai_platform.footprint import (
            assemble_governance_footprint,
            collect_ran_under_containment,
            compute_independence,
        )

        tenant = tenant_repository.get_by_id(experiment.tenant_id)
        account = (
            account_repository.get_by_id(tenant.account_id)
            if tenant is not None and tenant.account_id is not None
            else None
        )
        tier = int(account.trust_tier) if account is not None else int(TrustTier.T1_AUTHENTICATED)
        identity_gate = (
            "verified"
            if account is not None and account.identity_verified_at is not None
            else "unsatisfied"
        )
        decision = experiment.assessment_decision
        assessment = (
            {
                "research_class": experiment.research_class,
                "tier": experiment.assessment_tier,
                "envelope": experiment.assessment_envelope,
            }
            if decision is not None
            else None
        )

        def _resolver(worker_id):
            w = worker_repository.get_by_id(worker_id)
            return w.account_id if w is not None else None

        def _policy_resolver(worker_id):
            # §41: a worker that doesn't report a sandbox policy (old worker) reads
            # as permissive — the fail-safe assumption.
            w = worker_repository.get_by_id(worker_id)
            return (w.capabilities.get("sandbox_policy") if w is not None else None) or "permissive"

        return assemble_governance_footprint(
            tenant_tier=tier,
            identity_gate=identity_gate,
            integrity_policy=experiment.integrity_policy,
            # 'auto' only when #48 auto-approved; review/None both routed through a human.
            approval_experiment="auto" if decision == "auto" else "human",
            assessment=assessment,
            promotion_tier_set_by=account.tier_set_by_class if account is not None else None,
            independence=compute_independence(per_job_db, _resolver),
            containment={
                "required": experiment.required_containment,
                "ran_under": collect_ran_under_containment(per_job_db, _policy_resolver),
            },
            entries=entries,
            diverged_units=diverged_units,
        )

    def _promotion_auto_t1_t2() -> bool:
        # §6.2: read the mode server-authoritatively at promotion time so the
        # console toggle is the authority. Default = `manual` (human-in-the-loop,
        # charter §6 decision 3): qualifying accounts wait in the promotion queue.
        # Only `auto_with_override` lets the coordinator auto-promote.
        return promotion_policy_repository.get().auto_promote_t1_t2

    eligibility_thresholds = EligibilityThresholds(
        t2_receipt_threshold=config.tier_t2_receipt_threshold,
        t2_distinct_tenants=config.tier_t2_distinct_tenants,
        t2_min_account_age_days=config.tier_t2_min_account_age_days,
    )

    return CoordinatorServices(
        config=config,
        db=db,
        account_repository=account_repository,
        assessment_policy_repository=assessment_policy_repository,
        promotion_policy_repository=promotion_policy_repository,
        trust_model_policy_repository=trust_model_policy_repository,
        tenant_repository=tenant_repository,
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        audit_repository=audit_repository,
        worker_repository=worker_repository,
        retired_key_repository=retired_key_repository,
        receipt_index_repository=receipt_index_repository,
        certified_profile_repository=certified_profile_repository,
        attestation_repository=attestation_repository,
        result_transfer_repository=result_transfer_repository,
        model_request_repository=model_request_repository,
        model_prestage_repository=model_prestage_repository,
        software_request_repository=software_request_repository,
        tenant_application_repository=tenant_application_repository,
        release_repository=release_repository,
        vouch_repository=vouch_repository,
        per_job_factory=per_job_factory,
        receipt_signing_key=receipt_signing_key,
        eligibility_thresholds=eligibility_thresholds,
        account_suspended_for_tenant=_account_suspended_for_tenant,
        tenant_tier=_tenant_tier,
        approved_classes=_approved_classes,
        auto_approval_gate=_auto_approval_gate,
        governance_footprint_for=_governance_footprint_for,
        promotion_auto_t1_t2=_promotion_auto_t1_t2,
    )
