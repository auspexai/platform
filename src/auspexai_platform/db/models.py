"""Pydantic models representing DB rows.

Distinct from API response models: these are the *internal* shape of stored
data, used by repositories. API routes convert between these and the route-
specific response models (which carry exposure tags).

Why a separate layer: DB schema evolves (M5+ migrations add columns,
relationships, etc.) but external API contract is stable per the
versioning policy. Mixing the two means schema changes leak into wire
format. Keep them separate.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from auspexai_platform.auth.credential import CredentialClass


class TrustTier(IntEnum):
    """Worker / account trust tiers per §6.1 (revised 2026-05-24).

    Stored as INTEGER in SQL so comparison ops (>=, <=) work naturally for
    tier-floor logic in the scheduler and trust-promotion paths.

    T3 is the maximum worker tier. "Maintainer" is an account-level governance
    role (§6.5), not a worker tier — a maintainer's workers are T3.
    """

    T0_ANONYMOUS = 0
    T1_AUTHENTICATED = 1
    T2_TRUSTED = 2
    T3_VETTED = 3


# K — the R2-review threshold (vigiles_onramp_phase4_design.md §8 D1). Clearing it
# earns the R2 ETHICS REVIEW, never the promotion itself. There is no statistical
# optimum — K is a competence floor + spam-cost lever, not a reliability estimate;
# the rigor is the quality-weighting + the human review, not K's magnitude.
R2_REVIEW_THRESHOLD = 3


class ResearchStanding(IntEnum):
    """Researcher research-standing (R0-R3) — the Vigiles on-ramp ladder (D9 Phase 4).

    ORTHOGONAL to TrustTier (compute): R measures "proposes and sees through
    well-formed, ethics-clean experiments"; T measures "contributes honest
    compute." They must not be collapsed (running many experiments must never
    lower your own experiments' replication floor — that privilege lives on T).

    Stored as INTEGER so >=/<= gating works (R2+ → BYOT; R3 → high-risk eligible).
    R0 is the no-account state (SDK installed, unverified); a bound account is R1+
    (OAuth-verified). R1→R2 and R2→R3 are HUMAN promotions (ethics review /
    maintainer vetting) — NEVER auto-promoted; the standing summary only earns the
    review. See vigiles_onramp_phase4_design.md §0/§1.
    """

    R0_UNVERIFIED = 0
    R1_VERIFIED = 1
    R2_ESTABLISHED = 2
    R3_TRUSTED = 3


class IdentityProvider(StrEnum):
    """Identity providers the coordinator accepts for account binding.

    Phase 1 rooted accounts: GitHub only (auspexai org OAuth App) — rooting an
    account by a new IdP requires a migration to relax the accounts.idp CHECK.
    ORCID (D8) is supported as a *linked* identity (the account stays
    GitHub-rooted; the ORCID iD is a separate column), so it needs no CHECK change.
    """

    GITHUB = "github"
    ORCID = "orcid"


class IntegrityPolicy(StrEnum):
    """Per-experiment integrity policy set by Maintainer at approval time.

    Determines the base replication_target for work units. The scheduler
    enforces per-tier replication floors on top of this base.
    """

    STANDARD = "standard"  # base replication_target=3
    HIGH = "high"  # base replication_target=5
    TRUSTED = "trusted"  # base replication_target=1 (only T2+ via tier floor)


INTEGRITY_POLICY_REPLICATION = {
    IntegrityPolicy.STANDARD: 3,
    IntegrityPolicy.HIGH: 5,
    IntegrityPolicy.TRUSTED: 1,
}


class ExperimentStatus(StrEnum):
    """Experiment lifecycle states.

    Transitions:
      submitted → approved → (paused ⇄ approved) → completed | aborted → archived
    """

    SUBMITTED = "submitted"
    APPROVED = "approved"
    PAUSED = "paused"
    ABORTED = "aborted"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class WorkUnitStatus(StrEnum):
    """Work-unit lifecycle states (M6c+).

    M6c only writes PENDING on insert. M6d's scheduler / result-submission
    path drives the rest:
      pending → in_progress (≥1 assignment outstanding) → completed
                                                       \\→ failed
    """

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkerStatus(StrEnum):
    """Derived, display-facing worker status (not a stored column).

    Computed from a Worker's flags + heartbeat recency by
    `worker_status.derive_worker_status`. Precedence (first match wins):
    retired > quarantined > offline (no recent heartbeat) > active. Surfaced
    to the worker itself and to the worker's own-account researcher; the
    quarantine *reason* travels alongside it (no longer operator-only).
    """

    ACTIVE = "active"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class Tenant(BaseModel):
    """A row in the `tenants` table."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    maintainer_pubkey: str  # 64 lowercase hex chars
    display_name: str | None = None
    contact_email: str | None = None
    contact_public: str | None = None
    description: str | None = None
    # b-lite: operator-set link to an OAuth account (NULL = not linked yet).
    # Reserved now; the OAuth-onboarding path that writes it lands in Phase 2.
    account_id: str | None = None
    registered_at: datetime
    revision: int = 1


class Manifest(BaseModel):
    """A row in the `manifests` table — a tenant-uploaded, signed manifest body.

    The manifest_json and signature_json are stored opaquely in M5 v0 — the
    coordinator extracts only the identifying fields needed to scope the
    experiment to a tenant. Full manifest-schema validation moves into the
    worker (M6) where it can apply per-experiment policy.
    """

    model_config = ConfigDict(extra="forbid")

    manifest_hash: str  # 64 lowercase hex chars (SHA-256 of canonical manifest JSON)
    tenant_id: str
    manifest_json: dict[str, Any]
    signature_json: dict[str, Any]
    uploaded_at: datetime


class Experiment(BaseModel):
    """A row in the `experiments` table — a tenant's submitted experiment with
    lifecycle state."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str  # coordinator-generated: 'exp-<random>'
    tenant_id: str
    tenant_experiment_label: str  # the `experiment_id` from the tenant's manifest
    manifest_hash: str
    status: ExperimentStatus
    submitted_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    revision: int = 1
    error_summary: str | None = None
    # M6e: submission gate + state-change attribution.
    submissions_finalized: bool = False
    last_action_at: datetime | None = None
    last_action_by_class: CredentialClass | None = None
    # C14 replication-model redesign (0040): the replication COUNT, decoupled from
    # the 3-value integrity_policy enum so repl-2 is expressible. `replication_target`
    # is now the SOURCE OF TRUTH for how many distinct-worker completions a unit needs;
    # `integrity_policy` is a DERIVED coarse label. `replication_floor` = the minimum
    # corroboration accepted (consumed by capacity-aware completion in a later phase).
    integrity_policy: IntegrityPolicy = IntegrityPolicy.STANDARD
    replication_target: int = 3
    replication_floor: int = 2
    # §41 containment floor: minimum sandbox isolation a worker must run this
    # experiment's code under (seeded at submit from the tenant tier). 'permissive'
    # | 'strict'. The scheduler matches worker.capabilities['sandbox_policy'].
    required_containment: str = "permissive"
    max_unit_duration_seconds: int | None = None
    max_units: int | None = None
    max_concurrent_assignments: int | None = None
    max_payload_bytes: int | None = None
    # M1 (#30 capability-matching): models/capabilities a worker must locally hold
    # to be eligible for this experiment's units — derived at submit from the
    # manifest's `local_weights_required` models, keyed by worker store model_id
    # (<repo-slug>-<quant>). Empty = no requirement (every worker eligible; pre-M1).
    required_capabilities: dict[str, list[str]] = Field(default_factory=dict)
    # Audit 2026-06-08: a real-execution experiment with NO model requirement
    # (executor runs real code but declares no local weights) must still be kept
    # off synthetic-mode workers (which echo → false consensus). Derived at submit
    # from the manifest's `requires_real_execution`. False = pre-existing behavior.
    requires_real_execution: bool = False
    # M-Results: per-experiment retention controls (0015). NULL TTLs = platform
    # defaults; `retention_hold` makes the age-off sweep skip this experiment;
    # `results_collected_at` is the offload anchor (export-bundle pull).
    raw_payload_ttl_days: int | None = None
    consensus_ttl_days: int | None = None
    retention_hold: bool = False
    retention_hold_reason: str | None = None
    results_collected_at: datetime | None = None
    # §9 #48: admission-assessment provenance (migration 0030). NULL = unassessed.
    # research_class mirrors the manifest's declared class; assessment_decision is
    # 'auto' | 'review' (| 'declined'); assessment_envelope is the per-check result.
    research_class: str | None = None
    assessment_decision: str | None = None
    assessment_tier: int | None = None
    assessment_envelope: list[dict[str, Any]] | None = None
    assessment_rationale: str | None = None
    assessed_at: datetime | None = None
    assessed_by: str | None = None


class IdentityVerificationMethod(StrEnum):
    """Methods for satisfying the §6.2.1 identity gate."""

    MAINTAINER_ATTESTED = "maintainer_attested"
    GITHUB_PROFILE = "github_profile"
    INSTITUTIONAL_EMAIL = "institutional_email"
    ORCID = "orcid"


class ResearchStandingSummary(BaseModel):
    """Recomputed (never stored) research-standing evidence for an account — the
    R2-review eligibility signal derived from the account's ATTESTED experiment
    history. Reward-independent and externally verifiable (the firewall property);
    it earns the human R2 ethics review, it does not promote. See
    AccountRepository.research_standing_summary + vigiles_onramp_phase4_design.md §1.2.
    """

    model_config = ConfigDict(extra="forbid")

    account_id: str
    current: ResearchStanding
    # distinct (by manifest_hash), completed (terminal consensus), evidence-attested
    # (a final attestation exists) experiments the account has run.
    distinct_clean_completed_verified: int
    threshold: int = R2_REVIEW_THRESHOLD
    # current == R1 AND count >= threshold. Eligibility only; the promotion is human.
    eligible_for_r2_review: bool


class Account(BaseModel):
    """A row in the `accounts` table — one human identity bound to one IdP."""

    model_config = ConfigDict(extra="forbid")

    account_id: str
    idp: IdentityProvider
    idp_sub: str
    display_name: str | None = None
    email: str | None = None
    # System B (D): opt-in consent to be NAMED in the public citation of work this
    # account contributes to (default off — auth-consent ≠ attribution-consent).
    # `attribution_name` is how they wish to be credited (falls back to display_name).
    public_attribution: bool = False
    attribution_name: str | None = None
    trust_tier: TrustTier = TrustTier.T1_AUTHENTICATED
    # Research-standing (R0-R3), ORTHOGONAL to trust_tier (compute). A bound account
    # defaults to R1 (OAuth-verified); R2/R3 are reached only by HUMAN promotion
    # (ethics review / maintainer vetting). See research_standing_summary + §1 design.
    research_standing: ResearchStanding = ResearchStanding.R1_VERIFIED
    created_at: datetime
    retired_at: datetime | None = None
    identity_verified_at: datetime | None = None
    identity_verified_by: str | None = None
    identity_verification_method: IdentityVerificationMethod | None = None
    identity_verification_note: str | None = None
    # D8: a linked ORCID iD (e.g. "0000-0002-1825-0097"), set when the researcher
    # links their ORCID (the citation-grade academic identity). Linking also sets
    # identity_verified_at (method=ORCID) — the R2→R3 vetting gate reads that flag,
    # and the iD is surfaced to the reviewer. NULL = no ORCID linked.
    orcid_id: str | None = None
    suspended_at: datetime | None = None
    # Maintainer's reason for the suspension. Set on suspend(), cleared on
    # unsuspend(). Account-scoped: surfaced to the account holder (whoami /
    # account self-view), never to third parties — mirrors worker
    # quarantine_reason.
    suspension_reason: str | None = None
    # Firewall #2 (F4): who set the CURRENT tier — 'system' (auto-promotion) or
    # 'maintainer' (manual). NULL = birth tier. Feeds the footprint promotion path.
    tier_set_by_class: str | None = None


class Vouch(BaseModel):
    """A row in the `vouches` table — a T2+ account vouching for a T1 account."""

    model_config = ConfigDict(extra="forbid")

    vouch_id: str
    voucher_account_id: str
    target_account_id: str
    rationale: str | None = None
    created_at: datetime
    revoked_at: datetime | None = None


class OAuthBinding(BaseModel):
    """A row in the `account_oauth_bindings` table — a short-lived one-shot
    token. M6b's worker-upgrade endpoint exchanges it for an account binding."""

    model_config = ConfigDict(extra="forbid")

    binding_token: str
    account_id: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


class Assignment(BaseModel):
    """A row in a per-job DB's `assignments` table — one worker assigned to
    one unit. (unit_id, worker_id) is unique: a single worker may not get
    the same unit twice. `result_id` is None until the worker submits a
    Result for this assignment. `refused_at` is non-null when the worker
    explicitly refused the assignment via the M3 refuse endpoint
    (manifest-swap defense, sensitive-content gate, tenant deny/allow).
    A row may not have both `result_id` and `refused_at` set. `attempt_count`
    starts at 1 and is bumped each time the unit is re-offered to this worker
    after a retryable refusal (§2.1 #8 dispatch-retry); a re-offer clears the
    refusal fields, so a refused row always reflects its latest attempt."""

    model_config = ConfigDict(extra="forbid")

    assignment_id: str
    unit_id: str
    worker_id: str
    worker_pubkey_hex: str
    assigned_at: datetime
    result_id: str | None = None
    refused_at: datetime | None = None
    refused_kind: str | None = None
    refused_reason: str | None = None
    attempt_count: int = 1


class Result(BaseModel):
    """A row in a per-job DB's `results` table — the SDK Result envelope
    (schemas/result_v0_1.json) plus coordinator-side metadata
    (`received_at`). `payload` is tenant-opaque; `worker_signature` is the
    Ed25519 signature over the canonical encoding of the Result body and
    is stored verbatim for M7 receipt verification."""

    model_config = ConfigDict(extra="forbid")

    result_id: str
    unit_id: str
    worker_id: str
    worker_pubkey_hex: str
    exit_code: int
    payload: dict[str, Any] = Field(default_factory=dict)
    worker_signature: str  # base64
    completed_at: datetime
    received_at: datetime
    # M-Results: retention + delivery metadata. `semantic_hash` is the persisted
    # reduce-time hash; `is_consensus` marks the one durable T-C copy;
    # `delivered_at` is the first tenant fetch; `payload_aged_off_at` (set when
    # `payload` was blanked) is the authoritative aged-off signal.
    semantic_hash: str | None = None
    is_consensus: bool = False
    delivered_at: datetime | None = None
    payload_expires_at: datetime | None = None
    payload_aged_off_at: datetime | None = None
    # EB-1 (§9 #47): coordinator-asserted serving-environment snapshot captured
    # at submission (worker version / ollama_version / served model ids). The
    # reproducibility triple's environment leg; None = pre-EB-1 row.
    environment: dict[str, Any] | None = None
    # §9 #13a: the worker-SIGNED canonical schema version (0/None = legacy
    # 5-field; 1 = the body also signs served_weights) and the worker-ATTESTED
    # served-weights digest ({model_id: gguf_sha256}). Distinct from the
    # coordinator-asserted `environment` snapshot above: this is covered by the
    # worker's Ed25519 signature, so #13b enforces against it (anti-fabrication).
    schema_version: int | None = None
    served_weights: dict[str, str] | None = None
    # A2 #32 (equal-trust flip activation): the worker-SIGNED sandbox policy this
    # result ran under (v2 body). Like served_weights, it's covered by the worker
    # signature — so the flip's STRICT-containment guard is accountable, not
    # heartbeat-self-reported. None = pre-v2 result (resolver falls back to the
    # worker's reported capability).
    ran_under: str | None = None


class WorkUnit(BaseModel):
    """A row in a per-job DB's `work_units` table.

    `payload` is the tenant-defined work content (opaque to v0 — coordinator
    stores and ships it but never interprets it). `replication_target` is
    the number of distinct-worker completions required before the unit is
    considered done; default 3 matches the most-conservative T0-only case
    (§6.1). M6d's scheduler may downgrade this for higher-tier workers.
    """

    model_config = ConfigDict(extra="forbid")

    unit_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    status: WorkUnitStatus = WorkUnitStatus.PENDING
    replication_target: int = 3
    completions_so_far: int = 0
    created_at: datetime
    # M4-tail pin / force-assign: when set, the scheduler offers this unit ONLY
    # to this worker (a maintainer override, audited). NULL = unpinned.
    pinned_worker_id: str | None = None


class Worker(BaseModel):
    """A row in the `workers` table — an Ed25519-keyed worker daemon.

    `capabilities` is the parsed JSON dict (worker-declared; opaque to v0).
    `account_id` is None for T0 anonymous workers, set after a successful
    M6a binding-token upgrade. `last_heartbeat_at` is None until the
    worker's first heartbeat call.
    """

    model_config = ConfigDict(extra="forbid")

    worker_id: str
    pubkey_hex: str  # 64 lowercase hex chars
    account_id: str | None = None
    trust_tier: TrustTier = TrustTier.T0_ANONYMOUS
    capabilities: dict[str, Any] = Field(default_factory=dict)
    registered_at: datetime
    last_heartbeat_at: datetime | None = None
    retired_at: datetime | None = None
    quarantined_at: datetime | None = None
    quarantine_reason: str | None = None
    # M4: operator "pause" — an operational pause (stop assigning), distinct from
    # quarantine (a fault/trust signal). Paused workers are excluded from the
    # active-and-available set. NULL = not paused. §2.1 #11: the pause reason is
    # now surfaced to the worker (via the /assignments 423, like quarantine) —
    # transparent but still no-fault.
    paused_at: datetime | None = None
    pause_reason: str | None = None


class AuditEntry(BaseModel):
    """A row in the `audit_log` table.

    `id` and `occurred_at` are set by the DB / repository on insertion.
    `payload` is stored as JSON text in the column; Pydantic surfaces it as
    a dict for callers.
    """

    model_config = ConfigDict(extra="forbid")

    id: int | None = None  # set by DB
    occurred_at: datetime | None = None  # set by repository on append
    actor_class: CredentialClass
    actor_identifier: str | None = None
    actor_tenant_id: str | None = None
    action: str = Field(min_length=1)
    resource_type: str | None = None
    resource_id: str | None = None
    payload: dict[str, Any] | None = None
