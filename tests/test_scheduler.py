"""Scheduler unit tests — pure-Python picking logic over fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from auspexai_platform.db.models import (
    Assignment,
    ExperimentStatus,
    IntegrityPolicy,
    TrustTier,
    Worker,
)
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import (
    AssignmentRepository,
    ExperimentRepository,
    ManifestRepository,
    WorkUnitRepository,
)
from auspexai_platform.scheduler import (
    ASSIGNMENT_REDELIVERY_LEASE_SECONDS,
    MAX_ASSIGNMENT_ATTEMPTS,
    Scheduler,
    assignment_presumed_lost,
    integrity_policy_for_request,
    is_retryable_refusal,
    is_sub_floor_policy,
    policy_floor_for_tier,
    reoffer_eligible,
    worker_is_degraded,
    worker_is_self_paused,
    worker_satisfies,
)


def test_integrity_policy_for_request_floors_by_tenant_tier():
    f = integrity_policy_for_request
    tier = TrustTier
    # T0/T1 can't reach trusted even asking for repl-1 -> floored to standard.
    assert f(replication_factor=1, tenant_tier=tier.T0_ANONYMOUS) == IntegrityPolicy.STANDARD
    assert f(replication_factor=1, tenant_tier=tier.T1_AUTHENTICATED) == IntegrityPolicy.STANDARD
    # T2/T3 earn trusted/repl-1 when they request it.
    assert f(replication_factor=1, tenant_tier=tier.T2_TRUSTED) == IntegrityPolicy.TRUSTED
    assert f(replication_factor=1, tenant_tier=tier.T3_VETTED) == IntegrityPolicy.TRUSTED
    # A higher requested replication is always honored, regardless of tier.
    assert f(replication_factor=3, tenant_tier=tier.T2_TRUSTED) == IntegrityPolicy.STANDARD
    assert f(replication_factor=5, tenant_tier=tier.T2_TRUSTED) == IntegrityPolicy.HIGH
    # int tier accepted; unknown defaults to the safe (standard) floor.
    assert f(replication_factor=1, tenant_tier=2) == IntegrityPolicy.TRUSTED


def test_policy_floor_for_tier_matches_submit_seed():
    # The manual-override floor must agree with the submit-time seed (both reuse
    # integrity_policy_for_request) so the two paths can't drift apart.
    tier = TrustTier
    assert policy_floor_for_tier(tier.T0_ANONYMOUS) == IntegrityPolicy.STANDARD
    assert policy_floor_for_tier(tier.T1_AUTHENTICATED) == IntegrityPolicy.STANDARD
    assert policy_floor_for_tier(tier.T2_TRUSTED) == IntegrityPolicy.TRUSTED
    assert policy_floor_for_tier(tier.T3_VETTED) == IntegrityPolicy.TRUSTED


def test_is_sub_floor_policy_gates_only_lowering_below_floor():
    p, tier = IntegrityPolicy, TrustTier
    # trusted (repl-1) is below the T0/T1 floor (standard/repl-3) -> sub-floor.
    assert is_sub_floor_policy(p.TRUSTED, tier.T1_AUTHENTICATED) is True
    assert is_sub_floor_policy(p.TRUSTED, tier.T0_ANONYMOUS) is True
    # T2+ have EARNED trusted/repl-1 -> not sub-floor.
    assert is_sub_floor_policy(p.TRUSTED, tier.T2_TRUSTED) is False
    assert is_sub_floor_policy(p.TRUSTED, tier.T3_VETTED) is False
    # At or above the floor is always fine (raising consensus is never gated).
    assert is_sub_floor_policy(p.STANDARD, tier.T1_AUTHENTICATED) is False
    assert is_sub_floor_policy(p.HIGH, tier.T1_AUTHENTICATED) is False
    assert is_sub_floor_policy(p.HIGH, tier.T2_TRUSTED) is False
    # int tier accepted.
    assert is_sub_floor_policy(p.TRUSTED, int(tier.T1_AUTHENTICATED)) is True


def _make_experiment(
    *,
    manifest_repository: ManifestRepository,
    experiment_repository: ExperimentRepository,
    tenant_id: str,
    label: str,
    approved: bool = True,
    required_capabilities: dict[str, list[str]] | None = None,
):
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": label},
        signature_json={},
    )
    experiment = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label=label,
        manifest_hash=manifest.manifest_hash,
        required_capabilities=required_capabilities,
    )
    if approved:
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.APPROVED)
        experiment = experiment_repository.get_by_id(experiment.experiment_id)
    return experiment


def _worker(
    *,
    worker_id: str,
    models: list[str] | None,
    tier: TrustTier = TrustTier.T2_TRUSTED,
    execute_tenant_code: str | None = "provisioned",
    sandbox_policy: str | None = None,
):
    # M9 leg 4: a model-holding worker that's meant to RUN real units declares
    # provisioned mode (the default here); pass execute_tenant_code="synthetic"/None
    # to exercise the consensus-safe exclusion.
    caps: dict = {"os": "linux"}
    if models is not None:
        caps["models"] = models
    if execute_tenant_code is not None:
        caps["execute_tenant_code"] = execute_tenant_code
    if sandbox_policy is not None:
        caps["sandbox_policy"] = sandbox_policy
    return Worker(
        worker_id=worker_id,
        pubkey_hex="a" * 64,
        trust_tier=tier,
        capabilities=caps,
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


# ---- §41 containment floor ------------------------------------------------


def test_required_containment_for_tier():
    from auspexai_platform.scheduler import required_containment_for_tier

    # strict_below_tier=0 disables the floor (Phase-1): everyone permissive.
    assert required_containment_for_tier(TrustTier.T0_ANONYMOUS, 0) == "permissive"
    # strict_below_tier=2: T0/T1 tenant code must run strict; T2+ may run permissive.
    assert required_containment_for_tier(TrustTier.T0_ANONYMOUS, 2) == "strict"
    assert required_containment_for_tier(TrustTier.T1_AUTHENTICATED, 2) == "strict"
    assert required_containment_for_tier(TrustTier.T2_TRUSTED, 2) == "permissive"


def test_worker_satisfies_containment_floor():
    # permissive-required (the Phase-1 norm): every worker eligible.
    assert worker_satisfies(_worker(worker_id="w", models=[]), {}) is True
    # strict-required: a permissive (or unreporting) worker is INELIGIBLE...
    perm = _worker(worker_id="w", models=[], sandbox_policy="permissive")
    unreported = _worker(worker_id="w", models=[])  # old worker, no policy
    assert worker_satisfies(perm, {}, required_containment="strict") is False
    assert worker_satisfies(unreported, {}, required_containment="strict") is False
    # ...but a strict worker IS eligible for strict-required work...
    strict = _worker(worker_id="w", models=[], sandbox_policy="strict")
    assert worker_satisfies(strict, {}, required_containment="strict") is True
    # ...and a strict worker is also eligible for permissive work (always tighter-OK).
    assert worker_satisfies(strict, {}, required_containment="permissive") is True


# ---- #30 (M1) capability matching -----------------------------------------


def test_worker_satisfies_empty_requirement_is_always_true():
    assert worker_satisfies(_worker(worker_id="w", models=[]), {}) is True
    assert worker_satisfies(_worker(worker_id="w", models=None), {"models": []}) is True


def test_worker_satisfies_requires_all_models():
    assert worker_satisfies(_worker(worker_id="w", models=["m-a", "m-b"]), {"models": ["m-a"]})
    assert not worker_satisfies(_worker(worker_id="w", models=["m-a"]), {"models": ["m-a", "m-b"]})
    assert not worker_satisfies(_worker(worker_id="w", models=None), {"models": ["m-a"]})


def test_worker_satisfies_auto_acquire_matches_any_model():
    """M3 lazy auto-acquire: an auto_acquire worker satisfies a model
    requirement it doesn't yet hold (it'll pull on assignment); a worker without
    the model and without auto_acquire does not."""
    aa = Worker(
        worker_id="wkr-aa",
        pubkey_hex="a" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        # auto_acquire is only meaningful under provisioned (the daemon only
        # declares it then) — so an auto_acquire worker is provisioned.
        capabilities={"os": "linux", "auto_acquire": True, "execute_tenant_code": "provisioned"},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert worker_satisfies(aa, {"models": ["m-x"]}) is True
    # auto_acquire must be exactly True, not just any truthy junk in the dict.
    assert worker_satisfies(_worker(worker_id="w", models=["m-y"]), {"models": ["m-x"]}) is False


def test_worker_satisfies_excludes_synthetic_mode_worker():
    """M9 leg 4 (consensus-safe routing): a synthetic/off-mode worker is NOT
    eligible for a model-gated (real-execution) experiment even if it holds the
    exact model — its echo would pollute consensus. A no-requirement experiment
    is still open to it (the doubler/test-tenant path)."""
    synth = _worker(worker_id="w-synth", models=["m-x"], execute_tenant_code="synthetic")
    off = _worker(worker_id="w-off", models=["m-x"], execute_tenant_code="off")
    undeclared = _worker(worker_id="w-bare", models=["m-x"], execute_tenant_code=None)
    for w in (synth, off, undeclared):
        assert worker_satisfies(w, {"models": ["m-x"]}) is False  # excluded from real work
        assert worker_satisfies(w, {}) is True  # but still eligible for unrequired work


def test_scheduler_routes_only_to_capable_workers(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="cap-1",
        required_capabilities={"models": ["m-x"]},
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    # Worker that holds m-x is offered the unit; one that doesn't is skipped
    # (the requirement is experiment-level — pick_for_worker is read-only, so the
    # two calls are independent).
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-has", models=["m-x"])) is not None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-not", models=["m-y"])) is None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-bare", models=None)) is None


def test_scheduler_no_requirement_is_open_to_all(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # Backward-compat: an experiment with no required_capabilities behaves exactly
    # as pre-M1 — every worker (with no models declared) is eligible.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="open-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-any", models=None)) is not None


def test_scheduler_skips_paused_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # M4: a paused worker (operational pause) is offered no work.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="pause-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    paused = Worker(
        worker_id="wkr-paused",
        pubkey_hex="p" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux"},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        paused_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert scheduler.pick_for_worker(paused) is None
    # sanity: an identical but un-paused worker is offered the unit
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-live", models=None)) is not None


def test_worker_is_degraded_reads_thermal_state():
    """M5: a worker is degraded iff its heartbeat thermal snapshot is critical."""
    base = dict(
        pubkey_hex="a" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    crit = Worker(worker_id="w", capabilities={"thermal": {"state": "critical"}}, **base)
    warm = Worker(worker_id="w", capabilities={"thermal": {"state": "warm"}}, **base)
    none = Worker(worker_id="w", capabilities={"os": "linux"}, **base)
    assert worker_is_degraded(crit) is True
    assert worker_is_degraded(warm) is False  # warm still works
    assert worker_is_degraded(none) is False  # no sensor → not excluded


def test_scheduler_skips_thermal_critical_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # M5 (W-H increment 2): the coordinator routes around a degraded worker.
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="therm-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    hot = Worker(
        worker_id="wkr-hot",
        pubkey_hex="h" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux", "thermal": {"state": "critical", "current_temp_c": 95.0}},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert scheduler.pick_for_worker(hot) is None
    # a cool worker (no thermal-critical) is offered the unit
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-cool", models=None)) is not None


def test_scheduler_skips_self_paused_worker(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    # §2.1 #11: a volunteer-self-paused worker is routed around (owner hold).
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="sp-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    sp = Worker(
        worker_id="wkr-sp",
        pubkey_hex="s" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities={"os": "linux", "self_paused": True},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert worker_is_self_paused(sp) is True
    assert scheduler.pick_for_worker(sp) is None
    assert scheduler.pick_for_worker(_worker(worker_id="wkr-live", models=None)) is not None


def test_picks_pending_unit_for_eligible_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {"input": 5}}])

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"
    assert pick.experiment_id == experiment.experiment_id
    assert pick.tenant_id == experiment.tenant_id


def test_skips_units_worker_already_assigned(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    AssignmentRepository(db).create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_t0_worker_assigned_low_replication_unit(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    """D9 Phase 4 (worker-participation accrual): a freshly-onboarded T0
    worker is NOT stranded — it is assigned a low-replication (repl-1) unit it
    can satisfy. The worker trust-tier no longer gates eligibility; corroboration
    rides the experiment's (target, floor), not the worker's tier. The
    SELF-CORROBORATION guard still holds for the same T0 worker, and a security
    skip (paused) still refuses it.
    """
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="t0-repl1",
        required_capabilities={"models": ["m-x"]},
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    # repl-2 so the same-worker guard (not the replication cap) is the unambiguous
    # cause of the self-corroboration refusal below.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=2)
    scheduler = Scheduler(experiment_repository, per_job_factory)

    # T0 worker holding m-x is offered the low-replication unit (previously:
    # stranded by the T0 tier floor of 3 > 2).
    t0 = _worker(worker_id="wkr-t0", models=["m-x"], tier=TrustTier.T0_ANONYMOUS)
    pick = scheduler.pick_for_worker(t0)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"

    # SELF-CORROBORATION guard intact: once this T0 worker holds an assignment for
    # u1, it is NOT offered a second replica of the same unit (the unit still
    # needs a 2nd replica, so only the same-worker guard can refuse it here).
    AssignmentRepository(db).create(
        assignment_id="asg-t0",
        unit_id="u1",
        worker_id=t0.worker_id,
        worker_pubkey_hex=t0.pubkey_hex,
    )
    assert scheduler.pick_for_worker(t0) is None

    # SECURITY/availability gate intact: a paused T0 worker is still refused.
    paused_t0 = Worker(
        worker_id="wkr-t0-paused",
        pubkey_hex="b" * 64,
        trust_tier=TrustTier.T0_ANONYMOUS,
        capabilities={"os": "linux", "models": ["m-x"], "execute_tenant_code": "provisioned"},
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        paused_at=datetime(2026, 6, 2, tzinfo=UTC),
    )
    assert scheduler.pick_for_worker(paused_t0) is None


def test_skips_units_at_replication_target(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """Default replication_target = 3. If 3 other workers are already
    assigned, this worker should get nothing for that unit."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    for i, other in enumerate(["wkr-other-1", "wkr-other-2", "wkr-other-3"]):
        assignments.create(
            assignment_id=f"asg-{i}",
            unit_id="u1",
            worker_id=other,
            worker_pubkey_hex=f"{chr(ord('a') + i) * 64}",
        )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_returns_none_when_no_approved_experiments(
    enrolled_worker,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    _, worker = enrolled_worker
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_skips_unapproved_experiments(
    enrolled_worker,
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    """Submitted-but-not-approved experiment doesn't get scheduled."""
    _, worker = enrolled_worker
    _, tenant_binding = registered_tenant
    experiment = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=tenant_binding.tenant_id,
        label="submitted-label",
        approved=False,
    )
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_picks_in_progress_unit_that_still_needs_replicas(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """In-progress units (already assigned to ≥1 worker, but not yet at
    target) should still be picked for additional workers."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    WorkUnitRepository(db).mark_in_progress("u1")
    # Only ONE other worker assigned; target is 3 → 2 slots left.
    AssignmentRepository(db).create(
        assignment_id="asg-other",
        unit_id="u1",
        worker_id="wkr-other",
        worker_pubkey_hex="a" * 64,
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"


# ---- §2.1 #8 dispatch-retry: refusal classification + re-offer ------------


def _refused_assignment(
    *, kind: str | None, attempt_count: int = 1, result_id=None, reason: str | None = None
) -> Assignment:
    return Assignment(
        assignment_id="asg-x",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="a" * 64,
        assigned_at=datetime(2026, 6, 1, tzinfo=UTC),
        result_id=result_id,
        refused_at=(None if kind is None and result_id else datetime(2026, 6, 1, tzinfo=UTC)),
        refused_kind=kind,
        refused_reason=reason,
        attempt_count=attempt_count,
    )


def test_is_retryable_refusal_classification():
    # Environmental / transient → retryable (the M0 failure classes).
    for kind in (
        "runner_failed",
        "sandbox_unavailable",
        "thermal_critical",
        "submit_failed_transient",
    ):
        assert is_retryable_refusal(kind) is True, kind
    # Policy / capability / integrity → terminal.
    for kind in (
        "refused_tenant_deny",
        "refused_tenant_allow_list_miss",
        "refused_sensitive",
        "refused_manifest_swap",
        "executor_refused",
        "submit_failed_terminal",
        "manual",
    ):
        assert is_retryable_refusal(kind) is False, kind
    # Unknown / None default to terminal (no surprise retry loops).
    assert is_retryable_refusal("something_new") is False
    assert is_retryable_refusal(None) is False


def test_is_retryable_refusal_by_reason_marker():
    # `executor_refused` is terminal by KIND, but the worker tags transient
    # availability failures in the REASON so the coordinator re-offers them (#40a).
    assert (
        is_retryable_refusal("executor_refused", "fetch failed: 404 (package_unavailable)") is True
    )
    assert (
        is_retryable_refusal("executor_refused", "inference serving unavailable for gemma: timeout")
        is True
    )
    # v0_2 M1: a version-skewed worker refuses a serving_version_pin'd unit; the
    # unit re-offers to a version-matching peer.
    assert (
        is_retryable_refusal(
            "executor_refused", "serving_version_mismatch: serving 'ollama/0.18.2'"
        )
        is True
    )
    # A real policy/integrity refusal on the SAME kind stays terminal.
    assert (
        is_retryable_refusal("executor_refused", "worker policy execute_tenant_code=off") is False
    )
    assert is_retryable_refusal("executor_refused", "manifest_swap: staged hash mismatch") is False
    # No reason → kind-only (executor_refused is terminal).
    assert is_retryable_refusal("executor_refused", None) is False


def test_reoffer_eligible_by_availability_reason():
    # executor_refused + a package_unavailable reason → re-offerable under the cap.
    a = _refused_assignment(
        kind="executor_refused", reason="fetch failed (package_unavailable)", attempt_count=1
    )
    assert reoffer_eligible(a) is True
    # executor_refused + a policy reason → terminal (no re-offer).
    b = _refused_assignment(kind="executor_refused", reason="tenant_deny", attempt_count=1)
    assert reoffer_eligible(b) is False


def test_reoffer_eligible_logic():
    # Retryable + under cap → re-offerable.
    assert reoffer_eligible(_refused_assignment(kind="runner_failed", attempt_count=1)) is True
    assert (
        reoffer_eligible(
            _refused_assignment(kind="runner_failed", attempt_count=MAX_ASSIGNMENT_ATTEMPTS - 1)
        )
        is True
    )
    # At the cap → not re-offerable.
    assert (
        reoffer_eligible(
            _refused_assignment(kind="runner_failed", attempt_count=MAX_ASSIGNMENT_ATTEMPTS)
        )
        is False
    )
    # Terminal kind → never re-offerable, regardless of attempts.
    assert (
        reoffer_eligible(_refused_assignment(kind="refused_tenant_deny", attempt_count=1)) is False
    )
    # A result-bearing (completed) assignment is never re-offerable.
    assert reoffer_eligible(_refused_assignment(kind=None, result_id="res-1")) is False


def test_retryable_refusal_reoffers_same_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """The M0 scenario: a worker refuses for an environmental reason
    (runner crash). On a small fleet it must remain eligible for re-offer
    rather than being permanently barred from the unit."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="sandbox boom")

    scheduler = Scheduler(experiment_repository, per_job_factory)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"


def test_terminal_refusal_excludes_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """A policy refusal (tenant deny) keeps the worker excluded — re-offering
    would just refuse again."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    assignments.mark_refused(
        assignment_id="asg-1", kind="refused_tenant_deny", reason="tenant denied"
    )

    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_retryable_refusal_excluded_once_attempts_exhausted(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """A retryable refusal that keeps recurring is bounded: after
    MAX_ASSIGNMENT_ATTEMPTS the worker is excluded like a terminal refusal."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    # Default replication_target (3) matches the enrolled_worker's T0 tier floor.
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}])
    assignments = AssignmentRepository(db)
    assignments.create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    scheduler = Scheduler(experiment_repository, per_job_factory)
    # Drive attempts up to the cap: refuse → (scheduler re-offers) → reactivate.
    for _attempt in range(1, MAX_ASSIGNMENT_ATTEMPTS):
        assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="boom")
        assert scheduler.pick_for_worker(worker) is not None  # still eligible
        assignments.reactivate("asg-1")
    # Final refusal brings attempt_count to the cap → no more re-offers.
    assignments.mark_refused(assignment_id="asg-1", kind="runner_failed", reason="boom")
    assert assignments.get_by_id("asg-1").attempt_count == MAX_ASSIGNMENT_ATTEMPTS
    assert scheduler.pick_for_worker(worker) is None


def test_pinned_unit_offered_only_to_pinned_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """M4-tail pin / force-assign: a pinned unit is offered only to its pinned
    worker; others skip it."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    wu = WorkUnitRepository(db)
    wu.submit_batch([{"unit_id": "u1", "payload": {}}])
    scheduler = Scheduler(experiment_repository, per_job_factory)

    wu.pin("u1", "wkr-someone-else")
    assert scheduler.pick_for_worker(worker) is None  # not the pinned worker

    wu.pin("u1", worker.worker_id)  # pin to this worker
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None and pick.work_unit.unit_id == "u1"


def test_skips_experiment_with_no_per_job_db(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """An approved experiment with no work-unit submissions has no per-job
    DB — scheduler must skip it without erroring."""
    _, worker = enrolled_worker
    # Don't create a per-job DB.
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(worker) is None


def test_worker_satisfies_requires_real_execution_gates_synthetic():
    """Audit 2026-06-08: a real-execution experiment with NO model requirement
    must still exclude synthetic-mode workers (an all-synthetic fleet would echo
    identically → a FALSE consensus). The experiment-level requires_real_execution
    flag gates such units to provisioned-mode workers only."""
    syn = _worker(worker_id="s", models=[], execute_tenant_code="synthetic")
    prov = _worker(worker_id="p", models=[], execute_tenant_code="provisioned")
    # No model requirement + requires_real_execution → only provisioned eligible.
    assert worker_satisfies(syn, {}, requires_real_execution=True) is False
    assert worker_satisfies(prov, {}, requires_real_execution=True) is True
    # Flag off → both eligible (pre-existing behavior, unchanged).
    assert worker_satisfies(syn, {}, requires_real_execution=False) is True
    assert worker_satisfies(prov, {}, requires_real_execution=False) is True


def test_scheduler_halts_suspended_account_experiments(
    registered_tenant,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
) -> None:
    """F5 (accountability cascade): a suspended account's already-APPROVED
    experiment stops dispatching, and unsuspension resumes it. No experiment
    state change — the scheduler routes around it while suspended."""
    _, binding = registered_tenant
    exp = _make_experiment(
        manifest_repository=manifest_repository,
        experiment_repository=experiment_repository,
        tenant_id=binding.tenant_id,
        label="susp-1",
    )
    db = per_job_factory.get_or_create(exp.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)

    suspended = {"value": False}
    scheduler = Scheduler(
        experiment_repository,
        per_job_factory,
        account_suspended_for_tenant=lambda tid: suspended["value"] and tid == binding.tenant_id,
    )
    w = _worker(worker_id="wkr-1", models=None)

    # Not suspended → the unit is dispatched.
    assert scheduler.pick_for_worker(w) is not None
    # Suspended → routed around, experiment unchanged (still APPROVED).
    suspended["value"] = True
    assert scheduler.pick_for_worker(w) is None
    assert experiment_repository.get_by_id(exp.experiment_id).status == ExperimentStatus.APPROVED
    # Unsuspend → dispatch resumes.
    suspended["value"] = False
    assert scheduler.pick_for_worker(w) is not None


# ---- C16: at-least-once offer delivery (stale-active re-delivery) ----------
# Incident 2026-07-01 (exp-9WLGijaO): an assignment row committed server-side
# but the offer RESPONSE was lost in flight (poll read-timeout under settle-sweep
# DB contention) — the worker never learned of it, the active row blocked every
# re-offer, and the unit wedged forever. The soft lease makes delivery
# at-least-once: a stale active row is re-delivered to its own worker.


def _active_assignment(*, age_seconds: float, attempt_count: int = 1, now: datetime) -> Assignment:
    return Assignment(
        assignment_id="asg-x",
        unit_id="u1",
        worker_id="wkr-a",
        worker_pubkey_hex="a" * 64,
        assigned_at=now - timedelta(seconds=age_seconds),
        attempt_count=attempt_count,
    )


def _backdate_assignment(db, assignment_id: str, seconds: float) -> None:
    """Simulate a lost offer response: the row exists, the worker never heard,
    and time passes (the worker keeps polling and getting no-work)."""
    past = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()
    with db.transaction() as cur:
        cur.execute(
            "UPDATE assignments SET assigned_at = ? WHERE assignment_id = ?",
            (past, assignment_id),
        )


def test_assignment_presumed_lost_predicate():
    now = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    lease = ASSIGNMENT_REDELIVERY_LEASE_SECONDS
    # Fresh active → presumed delivered (the worker may be executing right now).
    assert assignment_presumed_lost(_active_assignment(age_seconds=30, now=now), now=now) is False
    # Just inside the lease → still presumed delivered.
    assert (
        assignment_presumed_lost(_active_assignment(age_seconds=lease - 1, now=now), now=now)
        is False
    )
    # Past the lease → presumed lost.
    assert (
        assignment_presumed_lost(_active_assignment(age_seconds=lease + 1, now=now), now=now)
        is True
    )
    # Refused / result-bearing rows are never "lost offers".
    assert assignment_presumed_lost(_refused_assignment(kind="runner_failed"), now=now) is False
    assert (
        assignment_presumed_lost(_refused_assignment(kind=None, result_id="res-1"), now=now)
        is False
    )


def test_reoffer_eligible_stale_active_redelivery():
    now = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    lease = ASSIGNMENT_REDELIVERY_LEASE_SECONDS
    # Fresh active row → NOT re-offerable (no double-dispatch under a live offer).
    assert reoffer_eligible(_active_assignment(age_seconds=30, now=now), now=now) is False
    # Past the lease → the presumed-lost offer is re-deliverable to its worker.
    assert reoffer_eligible(_active_assignment(age_seconds=lease + 1, now=now), now=now) is True
    # The attempt cap bounds re-delivery exactly like refusal retries — no
    # infinite re-delivery to a pairing that never lands.
    assert (
        reoffer_eligible(
            _active_assignment(
                age_seconds=lease + 1, attempt_count=MAX_ASSIGNMENT_ATTEMPTS, now=now
            ),
            now=now,
        )
        is False
    )
    # A naive assigned_at is treated as UTC (SQLite round-trips drop tzinfo).
    naive = _active_assignment(age_seconds=lease + 1, now=now)
    naive = naive.model_copy(update={"assigned_at": naive.assigned_at.replace(tzinfo=None)})
    assert reoffer_eligible(naive, now=now) is True


def test_stale_active_offer_redelivers_to_same_worker(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """The C16 lost-delivery scenario end-to-end at the scheduler: the offer row
    exists (created during the lost poll), the unit is at full replication (its
    own row occupies the slot), and after the lease the SAME unit is picked for
    the SAME worker again — the capacity check must not block re-delivery."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    wu_repo = WorkUnitRepository(db)
    wu_repo.submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    AssignmentRepository(db).create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    wu_repo.mark_in_progress("u1")

    scheduler = Scheduler(experiment_repository, per_job_factory)
    # Fresh active row: presumed delivered — nothing offered (worker may be
    # executing; the unit is at capacity for everyone else too).
    assert scheduler.pick_for_worker(worker) is None
    # The response was lost; the row ages past the re-delivery lease.
    _backdate_assignment(db, "asg-1", ASSIGNMENT_REDELIVERY_LEASE_SECONDS + 60)
    pick = scheduler.pick_for_worker(worker)
    assert pick is not None
    assert pick.work_unit.unit_id == "u1"


def test_stale_active_slot_not_offered_to_other_workers(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
    worker_repository,
) -> None:
    """Re-delivery targets ONLY the owning worker: the stale row still occupies
    its replication slot, so a different worker is capacity-blocked as before
    (no over-assignment beyond the target while the offer might yet land)."""
    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    AssignmentRepository(db).create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    _backdate_assignment(db, "asg-1", ASSIGNMENT_REDELIVERY_LEASE_SECONDS + 60)

    other = worker_repository.enroll(
        worker_id="wkr-test02",
        pubkey_hex="b" * 64,
        capabilities={"os": "linux"},
    )
    scheduler = Scheduler(experiment_repository, per_job_factory)
    assert scheduler.pick_for_worker(other) is None


def test_stalled_unit_experiments_detector(
    enrolled_worker,
    approved_experiment,
    per_job_factory: PerJobDatabaseFactory,
    experiment_repository: ExperimentRepository,
) -> None:
    """C16 detection backstop: a unit wedged on a stale ACTIVE assignment
    surfaces on the E14 attention feed (the mid-run stall the zero-units
    detector can't see — it returned count:0 live during the incident); a
    fresh active assignment does not."""
    from auspexai_platform.api.experiments import (
        STALLED_UNIT_MINUTES,
        _stalled_unit_experiments,
    )

    _, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    wu_repo = WorkUnitRepository(db)
    wu_repo.submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    wu_repo.mark_in_progress("u1")
    AssignmentRepository(db).create(
        assignment_id="asg-1",
        unit_id="u1",
        worker_id=worker.worker_id,
        worker_pubkey_hex=worker.pubkey_hex,
    )
    now = datetime.now(UTC)
    # Fresh assignment → nothing to report.
    assert _stalled_unit_experiments(experiment_repository, per_job_factory, now) == []
    # Stale past the threshold → surfaced, with the unit count and age.
    _backdate_assignment(db, "asg-1", STALLED_UNIT_MINUTES * 60 + 120)
    out = _stalled_unit_experiments(experiment_repository, per_job_factory, now)
    assert len(out) == 1
    exp, n_units, oldest_minutes = out[0]
    assert exp.experiment_id == experiment.experiment_id
    assert n_units == 1
    assert oldest_minutes >= STALLED_UNIT_MINUTES


def test_stall_threshold_exceeds_redelivery_lease():
    """Load-bearing ordering: soft-lease re-delivery (the self-heal) must get
    first shot before the attention surface pages a human — a re-armed row gets
    a fresh assigned_at and drops back below the stall threshold."""
    from auspexai_platform.api.experiments import STALLED_UNIT_MINUTES

    assert STALLED_UNIT_MINUTES * 60 > ASSIGNMENT_REDELIVERY_LEASE_SECONDS


# ---- v0.2 M1: the features dimension (generation_policy routing) ------------


def test_worker_satisfies_features_dimension():
    def worker_with_features(features):
        w = _worker(worker_id="w", models=["m-a"])
        if features is not None:
            w.capabilities["worker_features"] = features
        return w

    req = {"models": ["m-a"], "features": ["generation_policy"]}
    # A declaring worker is eligible; a silent (pre-M1) worker is NOT — its
    # broker would burn sampling units with params_rejected at request time.
    assert worker_satisfies(worker_with_features(["generation_policy"]), req) is True
    assert worker_satisfies(worker_with_features(None), req) is False
    assert worker_satisfies(worker_with_features([]), req) is False
    assert worker_satisfies(worker_with_features(["other_feature"]), req) is False
    # No features requirement ⇒ the dimension is inert (back-compat).
    assert worker_satisfies(worker_with_features(None), {"models": ["m-a"]}) is True


# ---- top-down fleet-fit: RAM-gated routing ----------------------------------


def _worker_ram(worker_id: str, models, ram_gb, *, auto_acquire: bool = False) -> Worker:
    caps: dict = {"os": "linux", "execute_tenant_code": "provisioned"}
    if models is not None:
        caps["models"] = models
    if ram_gb is not None:
        caps["ram_total_gb"] = ram_gb
    if auto_acquire:
        caps["auto_acquire"] = True
    return Worker(
        worker_id=worker_id,
        pubkey_hex="a" * 64,
        trust_tier=TrustTier.T2_TRUSTED,
        capabilities=caps,
        registered_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def test_worker_satisfies_ram_gate_excludes_too_small_worker():
    # The coordinator sized the model at submit (model_ram_gb). A worker that HOLDS
    # the model but whose RAM can't serve it is NOT eligible — a too-big model is
    # never routed to it.
    req = {"models": ["big-model"], "model_ram_gb": {"big-model": 20.0}}
    assert worker_satisfies(_worker_ram("w-small", ["big-model"], 7.44), req) is False
    assert worker_satisfies(_worker_ram("w-big", ["big-model"], 24.0), req) is True


def test_worker_satisfies_ram_gate_excludes_too_small_auto_acquire():
    # An auto-acquire worker too small for the model must NOT be eligible either —
    # it would pull it (now blocked by the worker guard) and fail at load.
    req = {"models": ["big-model"], "model_ram_gb": {"big-model": 20.0}}
    assert worker_satisfies(_worker_ram("w-aa", None, 7.44, auto_acquire=True), req) is False
    assert worker_satisfies(_worker_ram("w-aa2", None, 24.0, auto_acquire=True), req) is True


def test_worker_satisfies_ram_gate_backstop_when_unsized_or_ram_unknown():
    # Backstop: an UNSIZED model (no model_ram_gb) or a worker that doesn't report
    # RAM can't be gated here → passes (the worker's own acquire guard catches it).
    assert worker_satisfies(_worker_ram("w1", ["m"], 7.44), {"models": ["m"]}) is True
    sized = {"models": ["m"], "model_ram_gb": {"m": 20.0}}
    assert worker_satisfies(_worker_ram("w2", ["m"], None), sized) is True


def test_derive_required_capabilities_sizes_models():
    from auspexai_platform.api.experiments import _derive_required_capabilities

    class _FakeSizer:
        def footprint_gb(self, repo, filename):
            return 20.34 if repo and filename else None

    manifest = {
        "models": [
            {
                "id": "big-q4",
                "local_weights_required": True,
                "hf_repo": "org/big-GGUF",
                "hf_filename": "big-Q4.gguf",
            }
        ]
    }
    req = _derive_required_capabilities(manifest, sizer=_FakeSizer())
    assert req["models"] == ["big-q4"]
    assert req["model_ram_gb"] == {"big-q4": 20.34}
    # No sizer → no model_ram_gb (backward-compatible).
    assert "model_ram_gb" not in _derive_required_capabilities(manifest)


def test_worker_satisfies_ram_gate_uses_usable_budget_not_raw_ram():
    # The routing gate compares against usable_memory_gb (the serve budget), not raw
    # ram_total — a Jetson with 7.44 raw but 5.44 usable is NOT eligible for an 8B
    # model (footprint 5.91), so it's never routed a model it would refuse at load.
    req = {"models": ["m8b"], "model_ram_gb": {"m8b": 5.91}}

    def _w(wid, ram_total, usable):
        return Worker(
            worker_id=wid,
            pubkey_hex="a" * 64,
            trust_tier=TrustTier.T2_TRUSTED,
            capabilities={
                "os": "linux",
                "execute_tenant_code": "provisioned",
                "models": ["m8b"],
                "ram_total_gb": ram_total,
                "usable_memory_gb": usable,
            },
            registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        )

    assert worker_satisfies(_w("jetson", 7.44, 5.44), req) is False  # 5.91 > usable 5.44
    assert worker_satisfies(_w("mac", 24.0, 22.0), req) is True  # fits the usable budget


def test_order_by_constraint_offers_scarcest_fit_first():
    """Constraint-aware ordering: an experiment whose model fits FEWER workers is
    offered before a fits-everywhere one — so the Mac takes llama (Mac-only) over
    mistral (fits all), and mistral falls to the Jetsons. No idle reservation."""
    from auspexai_platform.scheduler import Scheduler

    def _w(wid, usable):
        return Worker(
            worker_id=wid,
            pubkey_hex="a" * 64,
            trust_tier=TrustTier.T2_TRUSTED,
            capabilities={
                "os": "linux",
                "execute_tenant_code": "provisioned",
                "usable_memory_gb": usable,
                "auto_acquire": True,
            },
            registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        )

    fleet = [_w("mac", 22.0), _w("jet1", 5.44), _w("jet2", 5.44)]
    sched = Scheduler(None, None, active_workers=lambda: fleet)

    class _Exp:
        def __init__(self, eid, model, ram):
            self.experiment_id = eid
            self.required_capabilities = {"models": [model], "model_ram_gb": {model: ram}}
            self.requires_real_execution = True
            self.required_containment = "permissive"

    small = _Exp("exp-small", "smol", 1.5)  # 1.5 * 1.2 = 1.8 <= 5.44 → fits all 3
    llama = _Exp("exp-llama", "llama", 5.91)  # fits only the Mac (5.91 * 1.2 > 5.44)
    qwen3 = _Exp("exp-qwen3", "qwen3", 10.8)  # fits only the Mac
    # NB: mistral-7b-q4 (5.25) is NOT a fits-all model — 5.25 * _LOAD_OVERHEAD = 6.3
    # exceeds the 5.44 Jetson budget, so it too is Mac-only (see the overhead test).

    # Registration order small→llama→qwen3 reorders to scarcest-first: the two
    # Mac-only models (fit 1) before the small fits-all one (fit 3). Ties keep
    # registration order.
    ordered = [e.experiment_id for e in sched._order_by_constraint([small, llama, qwen3])]
    assert ordered == ["exp-llama", "exp-qwen3", "exp-small"]

    # No fleet ⇒ registration-order fallback (unchanged behavior).
    plain = Scheduler(None, None)
    assert [e.experiment_id for e in plain._order_by_constraint([small, llama])] == [
        "exp-small",
        "exp-llama",
    ]


def test_worker_satisfies_ram_gate_applies_load_overhead():
    # A model whose RAW footprint fits the usable budget but whose SERVE footprint
    # (footprint * _LOAD_OVERHEAD, covering KV cache + compute/CUDA buffers) does not
    # must be excluded: mistral-7b-q4 (5.25 GB) must NOT route to a 5.44 GB-usable
    # Jetson that then 500s at load ("unable to allocate CUDA0 buffer").
    req = {"models": ["mistral"], "model_ram_gb": {"mistral": 5.25}}

    def _w(wid, usable):
        return Worker(
            worker_id=wid,
            pubkey_hex="a" * 64,
            trust_tier=TrustTier.T2_TRUSTED,
            capabilities={
                "os": "linux",
                "execute_tenant_code": "provisioned",
                "models": ["mistral"],
                "usable_memory_gb": usable,
            },
            registered_at=datetime(2026, 6, 1, tzinfo=UTC),
        )

    # 5.25 <= 5.44 (raw would have passed) but 5.25 * 1.2 = 6.3 > 5.44 → excluded.
    assert worker_satisfies(_w("jetson", 5.44), req) is False
    # The Mac's 22 GB usable clears the overhead-adjusted footprint.
    assert worker_satisfies(_w("mac", 22.0), req) is True
