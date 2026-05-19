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
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from auspexai_platform.auth.credential import CredentialClass


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
