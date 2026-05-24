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


class IdentityProvider(StrEnum):
    """Identity providers the coordinator accepts for account binding.

    Phase 1: GitHub only (auspexai org OAuth App). Adding a new IdP requires
    a migration to relax the accounts.idp CHECK constraint.
    """

    GITHUB = "github"


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


class Tenant(BaseModel):
    """A row in the `tenants` table."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    maintainer_pubkey: str  # 64 lowercase hex chars
    display_name: str | None = None
    contact_email: str | None = None
    contact_public: str | None = None
    description: str | None = None
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
    integrity_policy: IntegrityPolicy = IntegrityPolicy.STANDARD
    max_unit_duration_seconds: int | None = None
    max_units: int | None = None
    max_concurrent_assignments: int | None = None
    max_payload_bytes: int | None = None


class IdentityVerificationMethod(StrEnum):
    """Methods for satisfying the §6.2.1 identity gate."""

    MAINTAINER_ATTESTED = "maintainer_attested"
    GITHUB_PROFILE = "github_profile"
    INSTITUTIONAL_EMAIL = "institutional_email"


class Account(BaseModel):
    """A row in the `accounts` table — one human identity bound to one IdP."""

    model_config = ConfigDict(extra="forbid")

    account_id: str
    idp: IdentityProvider
    idp_sub: str
    display_name: str | None = None
    email: str | None = None
    trust_tier: TrustTier = TrustTier.T1_AUTHENTICATED
    created_at: datetime
    retired_at: datetime | None = None
    identity_verified_at: datetime | None = None
    identity_verified_by: str | None = None
    identity_verification_method: IdentityVerificationMethod | None = None
    identity_verification_note: str | None = None
    suspended_at: datetime | None = None


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
    A row may not have both `result_id` and `refused_at` set."""

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
