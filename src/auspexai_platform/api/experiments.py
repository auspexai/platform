"""Experiment routes — /api/v0/experiments.

  POST   /api/v0/experiments                      — researcher submits manifest
  GET    /api/v0/experiments                      — list (filtered)
  GET    /api/v0/experiments/{experiment_id}      — detail
  POST   /api/v0/experiments/{id}/actions/approve — operator only
  POST   /api/v0/experiments/{id}/actions/abort   — operator OR own-tenant researcher
  POST   /api/v0/experiments/{id}/actions/archive — operator only

`pause` + `resume` are deferred to M6 (no scheduler yet means there's nothing
to pause). The lifecycle graph is enforced in `ExperimentRepository.update_status`;
the routes layer adds credential-based authorization on top.

Manifest submission flow:

  1. Researcher signs the HTTP request via RFC 9421 (auth layer resolves
     credential.tenant_id from the keyid).
  2. Body is `{"manifest": {...}, "signature": {...}}` — the manifest body
     plus the SDK's ManifestSignature object as JSON. Both opaque to v0.
  3. We enforce `body.manifest.tenant_id == credential.tenant_id` so a
     researcher can't submit a manifest under another tenant.
  4. `body.manifest.experiment_id` becomes the experiment's
     `tenant_experiment_label`. Coordinator generates its own `experiment_id`.
  5. Insert manifest (raises 409 on hash collision) + experiment (raises 409
     on (tenant, label) collision).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auspexai_platform.assessment import assess_envelope, decide
from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_maintainer
from auspexai_platform.db.models import (
    INTEGRITY_POLICY_REPLICATION,
    ExperimentStatus,
    IntegrityPolicy,
    TrustTier,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AttestationRepository,
    AuditRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
)
from auspexai_platform.db.repositories.experiments import (
    DuplicateExperimentLabelError,
    InvalidStatusTransitionError,
)
from auspexai_platform.db.repositories.manifests import DuplicateManifestError
from auspexai_platform.events import EventBus
from auspexai_platform.exposure import ExposureTag, filter_for_credential
from auspexai_platform.maintenance import projected_raw_age_off
from auspexai_platform.receipts.signing import SigningKey
from auspexai_platform.scheduler import (
    integrity_policy_for_request,
    is_sub_floor_policy,
    policy_floor_for_tier,
    required_containment_for_tier,
)

# ---- response models -------------------------------------------------------


class ExperimentResponse(BaseModel):
    """Wire shape for an experiment. Fields are Optional so the exposure
    filter can mask non-visible ones.

    Tenant-private posture (researcher_dashboard_design.md §3): an experiment's
    operational metadata is visible to its owning tenant and the maintainer
    only — never anonymously. The maintainer sees everything via the
    `is_visible` short-circuit; the owning researcher matches TENANT_SCOPED.
    No field is PUBLIC: experiment rows carry no open-transparency role — that
    is the receipt/verifier surface's job (the DOI-analogue, §6.8.1). The
    earlier PUBLIC tags predated the researcher credential class hitting a
    *list* endpoint, which would have leaked every tenant's experiment
    existence, ids, status and timeline to anonymous callers.
    """

    experiment_id: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    tenant_id: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    status: Annotated[ExperimentStatus | None, ExposureTag.TENANT_SCOPED] = None
    submitted_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    started_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    completed_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    submissions_finalized: Annotated[bool | None, ExposureTag.TENANT_SCOPED] = None
    last_action_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    last_action_by_class: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    tenant_experiment_label: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    manifest_hash: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    revision: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    error_summary: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    integrity_policy: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    max_unit_duration_seconds: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    max_units: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    max_concurrent_assignments: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    max_payload_bytes: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    # M1 (#30): models a worker must locally hold to be eligible (empty = none).
    required_capabilities: Annotated[dict[str, list[str]] | None, ExposureTag.TENANT_SCOPED] = None
    # M-Results retention state.
    retention_hold: Annotated[bool | None, ExposureTag.TENANT_SCOPED] = None
    retention_hold_reason: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    results_collected_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    # Retention policy + projected age-off (O-M8): operators set/own the policy;
    # researchers see only its effects (hold + collected_at + aged-off badges).
    raw_payload_ttl_days: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    consensus_ttl_days: Annotated[int | None, ExposureTag.OPERATOR_ONLY] = None
    raw_payload_age_off_at: Annotated[datetime | None, ExposureTag.OPERATOR_ONLY] = None
    # §9 #48 admission-assessment provenance — the lifecycle-timeline (R-D) +
    # review/auto-queue (console) inputs. TENANT_SCOPED: the owning tenant sees
    # its OWN verdicts (ratified transparency = outcome + envelope always,
    # rationale own-only) and the maintainer sees all. `assessed_by` (which
    # maintainer/agent decided) is operator audit detail, not the tenant's.
    research_class: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_decision: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_tier: Annotated[int | None, ExposureTag.TENANT_SCOPED] = None
    assessment_rationale: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    assessment_envelope: Annotated[list[dict[str, Any]] | None, ExposureTag.TENANT_SCOPED] = None
    assessed_at: Annotated[datetime | None, ExposureTag.TENANT_SCOPED] = None
    assessed_by: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None


class ExperimentListResponse(BaseModel):
    experiments: Annotated[list[ExperimentResponse] | None, ExposureTag.PUBLIC] = None


class ExperimentSubmissionRequest(BaseModel):
    """POST /api/v0/experiments body. Manifest + ManifestSignature."""

    manifest: dict[str, Any] = Field(description="Manifest body (opaque to v0)")
    signature: dict[str, Any] = Field(description="SDK ManifestSignature object")


class SetIntegrityPolicyRequest(BaseModel):
    """M4 scheduler override: change an experiment's integrity policy (the
    replication target). `reason` is mandatory + audited. `force` is required to
    set a policy BELOW the tenant's tier floor (A' approve-time clamp)."""

    integrity_policy: str = Field(description="standard | high | trusted")
    reason: str = Field(min_length=1, max_length=2000)
    force: bool = Field(
        default=False,
        description="override the tenant tier floor (set a sub-floor / repl-1 policy "
        "the account hasn't earned); requires reason; loudly audited",
    )


# ---- helpers ---------------------------------------------------------------


def _assessment_payload(experiment) -> dict[str, Any]:
    """The §9 #48 assessment view: the decision + its provenance (class, tier,
    envelope, rationale) and the resulting status (`approved` after an auto)."""
    return {
        "experiment_id": experiment.experiment_id,
        "status": experiment.status.value,
        "research_class": experiment.research_class,
        "decision": experiment.assessment_decision,
        "tier": experiment.assessment_tier,
        "rationale": experiment.assessment_rationale,
        "envelope": experiment.assessment_envelope,
        "assessed_at": experiment.assessed_at.isoformat() if experiment.assessed_at else None,
        "assessed_by": experiment.assessed_by,
    }


def _to_response(experiment) -> ExperimentResponse:
    return ExperimentResponse(
        experiment_id=experiment.experiment_id,
        tenant_id=experiment.tenant_id,
        tenant_experiment_label=experiment.tenant_experiment_label,
        manifest_hash=experiment.manifest_hash,
        status=experiment.status,
        submitted_at=experiment.submitted_at,
        started_at=experiment.started_at,
        completed_at=experiment.completed_at,
        revision=experiment.revision,
        error_summary=experiment.error_summary,
        submissions_finalized=experiment.submissions_finalized,
        last_action_at=experiment.last_action_at,
        last_action_by_class=(
            experiment.last_action_by_class.value
            if experiment.last_action_by_class is not None
            else None
        ),
        integrity_policy=experiment.integrity_policy.value
        if hasattr(experiment, "integrity_policy") and experiment.integrity_policy
        else "standard",
        max_unit_duration_seconds=experiment.max_unit_duration_seconds,
        max_units=experiment.max_units,
        max_concurrent_assignments=experiment.max_concurrent_assignments,
        max_payload_bytes=experiment.max_payload_bytes,
        required_capabilities=getattr(experiment, "required_capabilities", None) or None,
        retention_hold=getattr(experiment, "retention_hold", False) or None,
        retention_hold_reason=getattr(experiment, "retention_hold_reason", None),
        results_collected_at=getattr(experiment, "results_collected_at", None),
        raw_payload_ttl_days=getattr(experiment, "raw_payload_ttl_days", None),
        consensus_ttl_days=getattr(experiment, "consensus_ttl_days", None),
        raw_payload_age_off_at=projected_raw_age_off(experiment),
        research_class=getattr(experiment, "research_class", None),
        assessment_decision=getattr(experiment, "assessment_decision", None),
        assessment_tier=getattr(experiment, "assessment_tier", None),
        assessment_rationale=getattr(experiment, "assessment_rationale", None),
        assessment_envelope=getattr(experiment, "assessment_envelope", None),
        assessed_at=getattr(experiment, "assessed_at", None),
        assessed_by=getattr(experiment, "assessed_by", None),
    )


def _extract_manifest_identity(manifest: dict[str, Any]) -> tuple[str, str]:
    """Return `(tenant_id, experiment_id)` from a manifest dict. Raises
    ValueError if either is missing or malformed."""
    tenant_id = manifest.get("tenant_id")
    experiment_id = manifest.get("experiment_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("manifest must include `tenant_id` (non-empty string)")
    if not isinstance(experiment_id, str) or not experiment_id:
        raise ValueError("manifest must include `experiment_id` (non-empty string)")
    return tenant_id, experiment_id


def _derive_required_capabilities(manifest: dict[str, Any]) -> dict[str, list[str]]:
    """M1 (#30): a worker must locally hold every model the manifest marks
    `local_weights_required` (BYOM, §5.8). Keyed by the worker store model_id
    (`<repo-slug>-<quant>`, exact match for hash-agreement consensus). Empty ⇒ no
    requirement (every worker eligible). Phase-1 emits only the "models" key; the
    manifest stays opaque otherwise."""
    models = manifest.get("models")
    if not isinstance(models, list):
        return {}
    required = [
        m["id"]
        for m in models
        if isinstance(m, dict) and m.get("local_weights_required") and m.get("id")
    ]
    return {"models": required} if required else {}


def _check_action_authz(credential: Credential, experiment, *, allow_researcher: bool) -> None:
    """403 if credential can't act on the experiment. Maintainer can always
    act; researcher can act only on their own tenant's experiments and only
    when the route allows it."""
    if credential.is_maintainer():
        return
    if (
        allow_researcher
        and credential.is_researcher()
        and credential.tenant_id == experiment.tenant_id
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": {
                "code": "experiment_action_forbidden",
                "message": "this credential is not authorized to perform this action",
                "details": {"experiment_id": experiment.experiment_id},
            }
        },
    )


def _can_view(credential: Credential, experiment) -> bool:
    """True if this credential may view the experiment: maintainer (all) or the
    owning-tenant researcher. Tenant-private — no anonymous/cross-tenant view."""
    if credential.is_maintainer():
        return True
    return credential.is_researcher() and credential.tenant_id == experiment.tenant_id


def _experiment_not_found(experiment_id: str) -> HTTPException:
    """The 404 used for both genuinely-absent and not-visible-to-you
    experiments, so a non-owner cannot distinguish existence (§3)."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": {
                "code": "experiment_not_found",
                "message": f"no experiment with id {experiment_id!r}",
                "details": {"experiment_id": experiment_id},
            }
        },
    )


def _enforce_policy_floor(
    *,
    experiment,
    policy: IntegrityPolicy,
    tenant_tier: Callable[[str], int] | None,
    force: bool,
    reason: str | None,
) -> dict[str, Any]:
    """A' approve-time clamp (§9 trust-economics). The submit path already seeds
    an experiment's integrity policy floored by the tenant's tier; this guards
    the two MANUAL maintainer overrides (approve `?integrity_policy=` and
    set-integrity-policy) so they can't silently re-open the hole.

    A maintainer may RAISE integrity above the floor freely. Lowering it BELOW
    the floor (fewer replicas / less consensus than the account has earned) is a
    deliberate, audited exception, not a silent default:

      - no override          → 409 sub_floor_integrity_policy
      - force=true, no reason → 422 force_requires_reason
      - force=true + reason   → allowed; returns the audit-extra dict
        (forced_below_floor / floor_policy / tenant_tier / force_reason) for the
        caller to fold into the action's audit payload.

    No-op (returns {}) when `tenant_tier` is unwired (tests) or the requested
    policy already sits at/above the floor — the common case."""
    if tenant_tier is None:
        return {}
    tier = tenant_tier(experiment.tenant_id)
    if tier is None or not is_sub_floor_policy(policy, tier):
        return {}
    floor = policy_floor_for_tier(tier)
    if not force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "sub_floor_integrity_policy",
                    "message": (
                        f"{policy.value} (repl-{INTEGRITY_POLICY_REPLICATION[policy]}) is below "
                        f"the tier floor {floor.value!r} "
                        f"(repl-{INTEGRITY_POLICY_REPLICATION[floor]}) for tenant tier "
                        f"T{int(tier)}; pass force=true with a reason to override for this "
                        f"experiment, or promote the account to lower replication"
                    ),
                    "details": {
                        "requested_policy": policy.value,
                        "floor_policy": floor.value,
                        "tenant_tier": int(tier),
                    },
                }
            },
        )
    if not (reason and reason.strip()):
        raise HTTPException(
            status_code=422,
            detail={
                "error": {
                    "code": "force_requires_reason",
                    "message": "force=true requires a non-empty reason for a sub-floor "
                    "integrity-policy override",
                }
            },
        )
    return {
        "forced_below_floor": True,
        "floor_policy": floor.value,
        "tenant_tier": int(tier),
        "force_reason": reason,
    }


# ---- router ----------------------------------------------------------------


def build_router(
    credential_dep,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    *,
    event_bus: EventBus | None = None,
    per_job_factory: PerJobDatabaseFactory | None = None,
    receipt_index_repository: ReceiptIndexRepository | None = None,
    signing_key: SigningKey | None = None,
    attestation_repository: AttestationRepository | None = None,
    # §9 #48: injected lookups (wired in main.py from the account/application
    # repos, à la the scheduler's account_suspended_for_tenant). All optional so
    # the router builds in tests without them — defaults make every experiment
    # route to human review (tier T1, no scope, no catalog).
    tenant_tier: Callable[[str], int] | None = None,
    approved_classes: Callable[[str], list[str] | None] | None = None,
    served_model_ids: Callable[[], set[str] | None] | None = None,
    # §9 #48 inc-4: the runtime auto-approval gate, read server-authoritatively
    # at decision time. Returns (enabled, min_tier). Unwired (tests that don't
    # exercise the gate) ⇒ the endpoint falls back to DISABLED — the safe default.
    auto_approval_gate: Callable[[], tuple[bool, int]] | None = None,
    # §41 containment floor: tenants below this tier require strict sandboxing.
    # 0 = disabled (Phase-1 default). Wired from config.containment_strict_below_tier.
    containment_strict_below_tier: int = 0,
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/experiments",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_experiment(
        body: ExperimentSubmissionRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        if not credential.is_researcher():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "researcher_required",
                        "message": "experiment submission requires a researcher credential",
                        "details": {"credential_class": credential.kind.value},
                    }
                },
            )

        try:
            manifest_tenant, manifest_label = _extract_manifest_identity(body.manifest)
        except ValueError as e:
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT — Starlette renamed in 1.0
                detail={
                    "error": {
                        "code": "manifest_malformed",
                        "message": str(e),
                        "details": {},
                    }
                },
            ) from e

        if manifest_tenant != credential.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "manifest_tenant_mismatch",
                        "message": (
                            f"manifest tenant_id {manifest_tenant!r} does not match "
                            f"the signing credential's tenant {credential.tenant_id!r}"
                        ),
                        "details": {
                            "manifest_tenant": manifest_tenant,
                            "credential_tenant": credential.tenant_id,
                        },
                    }
                },
            )

        # Custom reducers are advertised in the SDK manifest contract but the
        # coordinator only runs builtin_hash_agreement (issuance.py defers custom
        # reducers). Reject `kind:"custom"` at ingest so a tenant can't submit a
        # reducer that would silently never run (its consensus would fall back to
        # hash-agreement without the tenant knowing). Drop this guard when custom
        # reducer subprocess dispatch lands.
        reducer = body.manifest.get("reducer")
        if isinstance(reducer, dict) and reducer.get("kind") == "custom":
            raise HTTPException(
                status_code=422,  # UNPROCESSABLE_CONTENT (starlette 1.x deprecates the _ENTITY alias)
                detail={
                    "error": {
                        "code": "custom_reducer_unsupported",
                        "message": (
                            "custom reducers are not yet supported; the coordinator "
                            "runs builtin_hash_agreement only. Use "
                            'reducer.kind="builtin_hash_agreement".'
                        ),
                    }
                },
            )

        # Insert manifest. Duplicate (same canonical hash) means re-submission;
        # treat as 409 — researchers shouldn't blindly re-upload identical
        # manifests; the receipt audit chain wants distinct submission events.
        try:
            manifest = manifest_repository.insert(
                tenant_id=manifest_tenant,
                manifest_json=body.manifest,
                signature_json=body.signature,
            )
        except DuplicateManifestError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_manifest",
                        "message": "an identical manifest is already stored",
                        "details": {"db_error": str(e)},
                    }
                },
            ) from e

        try:
            experiment = experiment_repository.create(
                tenant_id=manifest_tenant,
                tenant_experiment_label=manifest_label,
                manifest_hash=manifest.manifest_hash,
                required_capabilities=_derive_required_capabilities(body.manifest),
                requires_real_execution=bool(body.manifest.get("requires_real_execution")),
            )
        except DuplicateExperimentLabelError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "duplicate_experiment_label",
                        "message": (
                            f"tenant {manifest_tenant!r} already has an experiment "
                            f"with label {manifest_label!r}"
                        ),
                        "details": {
                            "tenant_id": manifest_tenant,
                            "tenant_experiment_label": manifest_label,
                        },
                    }
                },
            ) from e

        # A' (§9): seed the integrity policy from the researcher's requested
        # replication (manifest.replication_factor), FLOORED by the tenant's trust
        # tier — reciprocity: a tenant earns lower replication (less consensus
        # cross-check) only as its account earns trust. The maintainer can still
        # RAISE it at approve; the floor caps how LOW it can go, and auto-approval
        # (§9 #48) inherits this floored seed so it can never clear a sub-tier
        # experiment at trusted/repl-1.
        if tenant_tier is not None:
            tier = tenant_tier(manifest_tenant)
            experiment_repository.set_integrity_policy(
                experiment.experiment_id,
                integrity_policy_for_request(
                    replication_factor=int(body.manifest.get("replication_factor", 1) or 1),
                    tenant_tier=tier,
                ),
            )
            # §41 containment floor: seed the minimum sandbox isolation from the
            # tenant tier (the host-isolation analogue of the A' replication floor).
            # The scheduler then routes units only to workers that meet it.
            experiment_repository.set_required_containment(
                experiment.experiment_id,
                required_containment_for_tier(tier, containment_strict_below_tier),
            )
            experiment = experiment_repository.get_by_id(experiment.experiment_id)

        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.submit",
            resource_type="experiment",
            resource_id=experiment.experiment_id,
            payload={
                "tenant_experiment_label": experiment.tenant_experiment_label,
                "manifest_hash": experiment.manifest_hash,
                "integrity_policy": experiment.integrity_policy.value
                if experiment.integrity_policy
                else None,
            },
        )

        # M6: a newly-submitted experiment enters the approval queue. The bus
        # otherwise emits `experiment.status` only on *transitions* — never on
        # creation — so without this the operator console can't surface a pending
        # approval live (it had to be refreshed). Full payload: the maintainer
        # firehose renders it as-is; a tenant-scoped stream applies the §6.1
        # per-subscriber exposure filter (the event is not pre-redacted by audience).
        if event_bus is not None:
            event_bus.publish(
                "experiment.submitted",
                experiment_id=experiment.experiment_id,
                data={
                    "status": experiment.status.value,
                    "tenant_id": experiment.tenant_id,
                    "tenant_experiment_label": experiment.tenant_experiment_label,
                    "manifest_hash": experiment.manifest_hash,
                    "submitted_at": (
                        experiment.submitted_at.isoformat()
                        if experiment.submitted_at is not None
                        else None
                    ),
                    "required_capabilities": getattr(experiment, "required_capabilities", None)
                    or None,
                },
            )

        return filter_for_credential(
            _to_response(experiment),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    @router.get(
        "/experiments",
        response_model=ExperimentListResponse,
        response_model_exclude_none=True,
    )
    async def list_experiments(
        assessment: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentListResponse:
        # Tenant-private row scoping (§3): maintainer sees the whole fleet; a
        # researcher sees only their own tenant's rows; anyone else (anonymous,
        # worker) sees none. Field-level filtering still applies on top, but the
        # row scope is what stops cross-tenant existence/count leaking through a
        # list endpoint.
        # §9 #48: `?assessment=review|auto` is the maintainer's review / auto
        # queue (maintainer-only — a researcher's list stays their full set).
        if credential.is_maintainer():
            experiments = experiment_repository.list_all(assessment_decision=assessment)
        elif credential.is_researcher() and credential.tenant_id is not None:
            experiments = experiment_repository.list_all(tenant_id=credential.tenant_id)
        else:
            experiments = []
        filtered = [
            filter_for_credential(
                _to_response(e),
                credential,
                resource_tenant_id=e.tenant_id,
            )
            for e in experiments
        ]
        return ExperimentListResponse(experiments=filtered)

    @router.get(
        "/experiments/{experiment_id}",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def get_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        # Tenant-private (§3): a non-owning researcher / anonymous caller gets
        # the same 404 as a genuinely-absent experiment, so detail never
        # confirms an experiment id exists.
        if experiment is None or not _can_view(credential, experiment):
            raise _experiment_not_found(experiment_id)
        return filter_for_credential(
            _to_response(experiment),
            credential,
            resource_tenant_id=experiment.tenant_id,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/approve",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def approve_experiment(
        experiment_id: str,
        integrity_policy: str | None = None,
        max_unit_duration_seconds: int | None = None,
        max_units: int | None = None,
        max_concurrent_assignments: int | None = None,
        max_payload_bytes: int | None = None,
        force: bool = False,
        reason: str | None = None,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        require_maintainer(credential)
        override_audit: dict[str, Any] = {}
        if integrity_policy is not None:
            try:
                policy = IntegrityPolicy(integrity_policy)
            except ValueError:
                raise HTTPException(
                    status_code=422,
                    detail=f"invalid integrity_policy: {integrity_policy!r}; "
                    f"must be one of: standard, high, trusted",
                ) from None
            experiment = experiment_repository.get_by_id(experiment_id)
            if experiment is None:
                raise _experiment_not_found(experiment_id)
            # A' approve-time clamp: a sub-floor policy needs force=true + reason.
            override_audit = _enforce_policy_floor(
                experiment=experiment,
                policy=policy,
                tenant_tier=tenant_tier,
                force=force,
                reason=reason,
            )
            experiment_repository.set_integrity_policy(experiment_id, policy)
        if any(
            v is not None
            for v in [
                max_unit_duration_seconds,
                max_units,
                max_concurrent_assignments,
                max_payload_bytes,
            ]
        ):
            experiment_repository.set_resource_bounds(
                experiment_id,
                max_unit_duration_seconds=max_unit_duration_seconds,
                max_units=max_units,
                max_concurrent_assignments=max_concurrent_assignments,
                max_payload_bytes=max_payload_bytes,
            )
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.APPROVED,
            credential=credential,
            allow_researcher=False,
            action="experiment.approve",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
            extra_payload=override_audit or None,
        )

    @router.post("/experiments/{experiment_id}/assessment")
    async def assess_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> JSONResponse:
        """§9 #48 — assess a submitted experiment (class-by-tier auto-approval).

        Maintainer-credentialed (the future agent uses a scoped maintainer
        token). The decision is computed SERVER-AUTHORITATIVELY here — the
        caller cannot propose one — so a compromised agent cannot widen the
        gate. `auto` reuses the maintainer approve transition; `review` records
        the assessment and leaves the experiment in `submitted` for the human
        queue. Idempotent: re-calling an already-assessed experiment returns the
        prior assessment unchanged.
        """
        require_maintainer(credential)
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "experiment_not_found",
                        "message": f"no experiment with id {experiment_id!r}",
                    }
                },
            )
        if experiment.assessment_decision is not None:
            return JSONResponse(_assessment_payload(experiment))  # idempotent
        if experiment.status != ExperimentStatus.SUBMITTED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "not_assessable",
                        "message": (
                            "only a submitted experiment can be assessed "
                            f"(status: {experiment.status.value})"
                        ),
                    }
                },
            )

        manifest = manifest_repository.get(experiment.manifest_hash)
        manifest_json = manifest.manifest_json if manifest else {}
        research_class = manifest_json.get("research_class")
        tier = (
            tenant_tier(experiment.tenant_id)
            if tenant_tier is not None
            else int(TrustTier.T1_AUTHENTICATED)
        )
        approved = approved_classes(experiment.tenant_id) if approved_classes is not None else None
        served = served_model_ids() if served_model_ids is not None else None

        envelope = assess_envelope(
            manifest_json=manifest_json,
            research_class=research_class,
            tenant_approved_classes=approved,
            served_model_ids=served,
        )
        if auto_approval_gate is not None:
            gate_enabled, gate_min_tier = auto_approval_gate()
        else:
            # Unwired (a test that doesn't exercise the gate): DISABLED is the
            # safe default — production always wires the reader in main.py.
            gate_enabled, gate_min_tier = False, int(TrustTier.T2_TRUSTED)
        verdict = decide(
            research_class=research_class,
            tenant_tier=tier,
            envelope=envelope,
            auto_tier=gate_min_tier,
            auto_approval_enabled=gate_enabled,
        )
        assessed_by = credential.maintainer_login or "maintainer"
        experiment = experiment_repository.set_assessment(
            experiment_id,
            research_class=research_class,
            decision=verdict.decision,
            tier=tier,
            envelope=envelope.as_json(),
            rationale=verdict.rationale,
            assessed_by=assessed_by,
        )
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            actor_identifier=assessed_by,
            actor_tenant_id=None,
            action="experiment.assess",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "research_class": research_class,
                "decision": verdict.decision,
                "track": verdict.track,
                "tier": tier,
                "envelope_failures": envelope.failures,
                "rationale": verdict.rationale,
            },
        )
        if verdict.decision == "auto":
            # Reuse the maintainer approve transition; the assessment row records
            # WHY. The distinct action keeps an auto-approval auditable as such.
            _transition(
                experiment_id=experiment_id,
                new_status=ExperimentStatus.APPROVED,
                credential=credential,
                allow_researcher=False,
                action="experiment.assess.auto",
                experiment_repository=experiment_repository,
                audit_repository=audit_repository,
                event_bus=event_bus,
            )
            experiment = experiment_repository.get_by_id(experiment_id)
        return JSONResponse(_assessment_payload(experiment))

    @router.post(
        "/experiments/{experiment_id}/actions/abort",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def abort_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.ABORTED,
            credential=credential,
            allow_researcher=True,
            action="experiment.abort",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/archive",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def archive_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        require_maintainer(credential)
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.ARCHIVED,
            credential=credential,
            allow_researcher=False,
            action="experiment.archive",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/pause",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def pause_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.PAUSED,
            credential=credential,
            allow_researcher=True,
            action="experiment.pause",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/resume",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def resume_experiment(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        return _transition(
            experiment_id=experiment_id,
            new_status=ExperimentStatus.APPROVED,
            credential=credential,
            allow_researcher=True,
            action="experiment.resume",
            experiment_repository=experiment_repository,
            audit_repository=audit_repository,
            event_bus=event_bus,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/finalize-submissions",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def finalize_submissions(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": {
                        "code": "experiment_not_found",
                        "message": f"no experiment with id {experiment_id!r}",
                        "details": {"experiment_id": experiment_id},
                    }
                },
            )
        _check_action_authz(credential, experiment, allow_researcher=True)
        # Only sensible when there's something to receive — block on terminal
        # states. The transition graph already encodes which statuses are
        # terminal; finalize is meaningful only for approved/paused.
        if experiment.status not in {ExperimentStatus.APPROVED, ExperimentStatus.PAUSED}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": {
                        "code": "finalize_not_applicable",
                        "message": (
                            f"submissions can only be finalized while the experiment "
                            f"is approved or paused (current status: "
                            f"{experiment.status.value})"
                        ),
                        "details": {"current_status": experiment.status.value},
                    }
                },
            )
        updated = experiment_repository.finalize_submissions(
            experiment_id, actor_class=credential.kind
        )
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.finalize_submissions",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={
                "was_already_finalized": experiment.submissions_finalized,
            },
        )
        # If every unit already completed *before* this finalize (the autonomic
        # loop's finalize-on-convergence case — it finalizes once the last round's
        # units are all done), the unit-completion auto-complete trigger
        # (assignments._maybe_auto_complete, fired on result submit) never re-fires.
        # So run the same check here; otherwise the experiment is stuck APPROVED +
        # finalized and never reaches COMPLETED (no result-set attestation).
        if per_job_factory is not None:
            per_job_db = per_job_factory.get(experiment_id)
            if per_job_db is not None:
                from auspexai_platform.api.assignments import (
                    _maybe_auto_complete,
                    _maybe_emit_completion_attestation,
                )

                _maybe_auto_complete(
                    experiment_id=experiment_id,
                    per_job_db=per_job_db,
                    experiment_repository=experiment_repository,
                    audit_repository=audit_repository,
                    event_bus=event_bus,
                )
                # A1: the finalize-on-convergence completion path (M8 autonomic
                # driver finalizes after the last round's units are all done)
                # reaches COMPLETED here, NOT via a result submit — so persist the
                # canonical attestation on this path too. Idempotent + best-effort;
                # the on-demand GET canonicalizes lazily if these deps are absent.
                if receipt_index_repository is not None and signing_key is not None:
                    _maybe_emit_completion_attestation(
                        experiment_id=experiment_id,
                        per_job_db=per_job_db,
                        experiment_repository=experiment_repository,
                        receipt_index_repository=receipt_index_repository,
                        signing_key=signing_key,
                        audit_repository=audit_repository,
                        attestation_repository=attestation_repository,
                        event_bus=event_bus,
                    )
                updated = experiment_repository.get_by_id(experiment_id) or updated
        return filter_for_credential(
            _to_response(updated),
            credential,
            resource_tenant_id=updated.tenant_id,
        )

    @router.post(
        "/experiments/{experiment_id}/actions/retention-hold",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def place_retention_hold(
        experiment_id: str,
        reason: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only: place an audit/legal retention hold so the age-off
        sweep keeps this experiment's data regardless of collection. Mandatory
        reason (mirrors the account-suspension pattern)."""
        require_maintainer(credential)
        if not reason.strip():
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "reason_required",
                        "message": "a reason is required to place a retention hold",
                    }
                },
            )
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        updated = experiment_repository.set_retention_hold(experiment_id, held=True, reason=reason)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.retention_hold",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"reason": reason},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    @router.post(
        "/experiments/{experiment_id}/actions/set-integrity-policy",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def set_integrity_policy(
        experiment_id: str,
        body: SetIntegrityPolicyRequest,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only M4 scheduler override: change the experiment's
        integrity policy (replication target). NOTE: units bake `replication_target`
        at submit, so this changes FUTURE units' target, not units already
        submitted. Mandatory reason; audited."""
        require_maintainer(credential)

        try:
            policy = IntegrityPolicy(body.integrity_policy)
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": {
                        "code": "invalid_integrity_policy",
                        "message": f"invalid integrity_policy: {body.integrity_policy!r}; "
                        "expected standard | high | trusted",
                    }
                },
            ) from e
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        # A' approve-time clamp: a sub-floor policy needs force=true + reason.
        override_audit = _enforce_policy_floor(
            experiment=experiment,
            policy=policy,
            tenant_tier=tenant_tier,
            force=body.force,
            reason=body.reason,
        )
        experiment_repository.set_integrity_policy(experiment_id, policy)
        updated = experiment_repository.get_by_id(experiment_id)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.set_integrity_policy",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"integrity_policy": policy.value, "reason": body.reason, **override_audit},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    @router.post(
        "/experiments/{experiment_id}/actions/release-hold",
        response_model=ExperimentResponse,
        response_model_exclude_none=True,
    )
    async def release_retention_hold(
        experiment_id: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> ExperimentResponse:
        """Maintainer-only: release a retention hold (the experiment's data
        resumes normal age-off)."""
        require_maintainer(credential)
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None:
            raise _experiment_not_found(experiment_id)
        updated = experiment_repository.set_retention_hold(experiment_id, held=False, reason=None)
        audit_repository.append(
            actor_class=credential.kind,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="experiment.retention_hold_released",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={},
        )
        return filter_for_credential(
            _to_response(updated), credential, resource_tenant_id=updated.tenant_id
        )

    return router


def _transition(
    *,
    experiment_id: str,
    new_status: ExperimentStatus,
    credential: Credential,
    allow_researcher: bool,
    action: str,
    experiment_repository: ExperimentRepository,
    audit_repository: AuditRepository,
    event_bus: EventBus | None = None,
    extra_payload: dict[str, Any] | None = None,
) -> ExperimentResponse:
    """Common path for the action endpoints. Authorization + transition +
    audit + response filter. `extra_payload` merges into the audit payload —
    used by approve to record an A' sub-floor integrity-policy override."""
    experiment = experiment_repository.get_by_id(experiment_id)
    if experiment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "code": "experiment_not_found",
                    "message": f"no experiment with id {experiment_id!r}",
                    "details": {"experiment_id": experiment_id},
                }
            },
        )
    _check_action_authz(credential, experiment, allow_researcher=allow_researcher)
    try:
        updated = experiment_repository.update_status(
            experiment_id, new_status, actor_class=credential.kind
        )
    except InvalidStatusTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": {
                    "code": "invalid_status_transition",
                    "message": str(e),
                    "details": {
                        "current_status": experiment.status.value,
                        "requested_status": new_status.value,
                    },
                }
            },
        ) from e

    audit_repository.append(
        actor_class=credential.kind,
        actor_identifier=credential.pubkey_hex,
        actor_tenant_id=credential.tenant_id,
        action=action,
        resource_type="experiment",
        resource_id=experiment_id,
        payload={
            "from_status": experiment.status.value,
            "to_status": new_status.value,
            **(extra_payload or {}),
        },
    )
    if event_bus is not None:
        event_bus.publish(
            "experiment.status",
            experiment_id=experiment_id,
            data={
                "status": new_status.value,
                "from_status": experiment.status.value,
                "revision": updated.revision,
                "actor_class": credential.kind.value,
            },
        )
    return filter_for_credential(
        _to_response(updated),
        credential,
        resource_tenant_id=updated.tenant_id,
    )
