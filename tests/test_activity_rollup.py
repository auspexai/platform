"""Tests for the R-D3 experiment-activity rollup endpoint.

GET /api/v0/experiments/{id}/activity — anonymized liveness aggregate:
active-contributor count, work-unit status breakdown, last-activity timestamp,
and replication fill. Never leaks worker identity. Access:
  - owning-tenant researcher / maintainer → 200
  - cross-tenant researcher → 403 (auth-layer tenant scoping, like every
    other /experiments/{id}/... researcher route)
  - anonymous / unknown experiment → 404 (tenant-private; existence not
    confirmed)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository

AUTHORITY = "testserver"


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _seed(per_job_factory: PerJobDatabaseFactory, experiment_id: str) -> None:
    """Seed a per-job DB with 3 work units (2 completed, 1 pending) and results
    from 2 distinct workers. Both completed units reach AGREEMENT (a promoted
    consensus row), so this is a clean run with zero divergence."""
    db = per_job_factory.get_or_create(experiment_id)
    work_units = WorkUnitRepository(db)
    results = ResultRepository(db)
    work_units.submit_batch(
        [{"unit_id": f"u{i}", "payload": {}} for i in range(3)],
        replication_target=3,
    )
    # Drive u0 & u1 to fully replicated/completed (3 of 3); u2 stays pending.
    for unit_id in ("u0", "u1"):
        for _ in range(3):
            work_units.increment_completions(unit_id)
    # Results from 2 distinct workers: w-alpha ran u0 & u1, w-beta ran u0.
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)
    for n, (worker_id, unit_id) in enumerate(
        [("w-alpha", "u0"), ("w-alpha", "u1"), ("w-beta", "u0")]
    ):
        results.insert(
            result_id=f"r{n}",
            unit_id=unit_id,
            worker_id=worker_id,
            worker_pubkey_hex=f"{n:064x}",
            exit_code=0,
            payload={"ok": True},
            worker_signature="sig",
            completed_at=base + timedelta(minutes=n),
        )
    # The replicas AGREED → the reducer promotes one result per completed unit to
    # consensus. Without this, `collect_diverged_units` would (correctly) read
    # every completed-with-results-but-no-consensus unit as diverged — so a clean
    # run MUST carry a promoted consensus row, which is exactly what agreement does.
    results.promote_consensus("u0", "r0")
    results.promote_consensus("u1", "r1")


def _seed_diverged(per_job_factory: PerJobDatabaseFactory, experiment_id: str) -> None:
    """Seed a per-job DB with one DIVERGED unit: a completed work unit whose
    independent replicas produced different output and so reached NO agreement —
    results exist, but no result was promoted to consensus (`promote_consensus`
    never fired). This is precisely the state `collect_diverged_units` reads:
    work_units.status='completed' AND has results AND no is_consensus=1 row.

    `collect_diverged_units` only inspects per-job state (work_units + results); it
    does not require an issued receipt, so seeding the two repos is sufficient."""
    db = per_job_factory.get_or_create(experiment_id)
    work_units = WorkUnitRepository(db)
    results = ResultRepository(db)
    work_units.submit_batch([{"unit_id": "d0", "payload": {}}], replication_target=2)
    # Two replicas land → unit completes at target 2, but they DISAGREED, so the
    # reducer never promotes a consensus row (left deliberately unpromoted here).
    for _ in range(2):
        work_units.increment_completions("d0")
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)
    for n, (worker_id, payload) in enumerate(
        [("w-alpha", {"answer": 1}), ("w-beta", {"answer": 2})]  # different output
    ):
        results.insert(
            result_id=f"d-r{n}",
            unit_id="d0",
            worker_id=worker_id,
            worker_pubkey_hex=f"{n:064x}",
            exit_code=0,
            payload=payload,
            worker_signature="sig",
            completed_at=base + timedelta(minutes=n),
        )


def _seed_queued(per_job_factory: PerJobDatabaseFactory, experiment_id: str) -> None:
    """Seed a per-job DB with PENDING work units only — no completions, no
    results, no assignments. This is the D12 'approved but never started, queued
    behind capacity' state (run_phase == 'queued')."""
    db = per_job_factory.get_or_create(experiment_id)
    WorkUnitRepository(db).submit_batch(
        [{"unit_id": f"q{i}", "payload": {}} for i in range(2)],
        replication_target=2,
    )


class TestExperimentActivity:
    def test_owner_gets_anonymized_rollup(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        privkey, binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["experiment_id"] == experiment.experiment_id
        assert body["active_contributor_count"] == 2  # w-alpha, w-beta
        assert body["total_work_units"] == 3
        assert body["work_unit_counts"] == {"completed": 2, "pending": 1}
        assert body["completions_total"] == 6  # 3 + 3
        assert body["replication_target_total"] == 9  # 3 * 3
        assert body["last_activity_at"]  # present (received_at set on insert)
        # Richer D8: both completed units AGREED (consensus promoted) → clean.
        assert body["diverged_unit_count"] == 0
        # Anonymized: no worker identity may appear anywhere in the rollup.
        flat = repr(body)
        assert "w-alpha" not in flat
        assert "w-beta" not in flat
        assert "worker_id" not in body
        assert "worker_pubkey" not in body

    def test_maintainer_sees_rollup(
        self, client, approved_experiment, per_job_factory, maintainer_token
    ) -> None:
        _privkey, _binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        resp = client.get(
            f"/api/v0/experiments/{experiment.experiment_id}/activity",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["active_contributor_count"] == 2

    def test_empty_experiment_rollup(self, client, approved_experiment) -> None:
        privkey, binding, experiment, _hash = approved_experiment
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["active_contributor_count"] == 0
        assert body["total_work_units"] == 0
        assert body["completions_total"] == 0
        assert body["replication_target_total"] == 0
        # No activity yet → last_activity_at omitted (response_model_exclude_none).
        assert "last_activity_at" not in body

    def test_cross_tenant_researcher_gets_404(
        self, client, approved_experiment, per_job_factory, tenant_registry
    ) -> None:
        _privkey, _binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        # A different tenant's key → tenant-private 404 (not 403): the handler's
        # _can_view denies non-owners with the same 404 as a missing experiment,
        # mirroring the work-units route, so existence is never confirmed.
        other_priv = Ed25519PrivateKey.generate()
        other_pub = other_priv.public_key().public_bytes_raw().hex()
        tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
        resp = _signed_get(
            client,
            privkey=other_priv,
            pubkey_hex=other_pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 404, resp.text

    def test_anonymous_gets_404(self, client, approved_experiment) -> None:
        # Unsigned/anonymous → tenant-private 404 (existence not confirmed).
        _privkey, _binding, experiment, _hash = approved_experiment
        resp = client.get(f"/api/v0/experiments/{experiment.experiment_id}/activity")
        assert resp.status_code == 404, resp.text

    def test_unknown_experiment_404(self, client, registered_tenant) -> None:
        privkey, binding = registered_tenant
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path="/api/v0/experiments/exp-does-not-exist/activity",
        )
        assert resp.status_code == 404, resp.text

    def test_system_pause_yields_regime3_liveness_note(
        self, client, approved_experiment, per_job_factory, experiment_repository
    ) -> None:
        """D8: a C14 regime-3 pause (last_action_by_class == system) self-explains
        as a self-healing 'waiting for an eligible worker, auto-resumes' hold."""
        from auspexai_platform.auth.credential import CredentialClass
        from auspexai_platform.db.models import ExperimentStatus

        privkey, binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        # The coordinator pauses the run when the eligible fleet can't meet the
        # corroboration floor → recorded as a system-actor transition.
        experiment_repository.update_status(
            experiment.experiment_id,
            ExperimentStatus.PAUSED,
            actor_class=CredentialClass.SYSTEM,
        )

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        note = resp.json()["liveness_note"]
        assert "auto-resumes" in note
        assert "corroborating workers" in note

    def test_normal_run_has_no_liveness_note(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        """A healthy (approved, no thin-corroboration) run has nothing to explain →
        the field is omitted (response_model_exclude_none)."""
        privkey, binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        assert "liveness_note" not in resp.json()

    def test_queued_experiment_reports_phase_position_and_note(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        """D12: an approved experiment that has never started (pending units, no
        completions, nothing in flight) reports run_phase='queued', its 1-based
        FIFO position among approved experiments, and a plain-language wait note."""
        privkey, binding, experiment, _hash = approved_experiment
        _seed_queued(per_job_factory, experiment.experiment_id)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["run_phase"] == "queued"
        assert body["queue_position"] == 1
        assert body["queue_depth"] >= 1
        assert "queued" in body["liveness_note"].lower()

    def test_running_experiment_reports_running_phase_no_queue(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        """D12: an approved experiment with completions reads as 'running' (an idle
        gap between rounds is 'between beats', not 'queued') and carries no queue
        position (the field is omitted when not queued)."""
        privkey, binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["run_phase"] == "running"
        assert "queue_position" not in body

    def test_queue_position_excludes_abandoned_experiments(
        self, client, approved_experiment, per_job_factory, experiment_repository
    ) -> None:
        """D15: an approved experiment with no work units (an abandoned orphan)
        does NOT inflate the queue — queue_depth counts only approved experiments
        with pending work, in registration order."""
        from auspexai_platform.db.models import ExperimentStatus

        privkey, binding, experiment, _hash = approved_experiment
        _seed_queued(per_job_factory, experiment.experiment_id)
        # A second approved experiment that never submitted units (orphan).
        other = experiment_repository.create(
            tenant_id=binding.tenant_id,
            tenant_experiment_label="abandoned",
            manifest_hash=_hash,
        )
        experiment_repository.update_status(other.experiment_id, ExperimentStatus.APPROVED)

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["run_phase"] == "queued"
        assert body["queue_position"] == 1
        assert body["queue_depth"] == 1  # the abandoned 0-unit experiment is excluded

    def test_clean_run_reports_zero_divergence(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        """Richer D8: a run whose completed units all reached agreement reports
        `diverged_unit_count == 0` — the field is present (reassurance is the
        point) and the cross-check is clean."""
        privkey, binding, experiment, _hash = approved_experiment
        _seed(per_job_factory, experiment.experiment_id)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "diverged_unit_count" in body
        assert body["diverged_unit_count"] == 0

    def test_diverged_unit_surfaces_in_rollup(
        self, client, approved_experiment, per_job_factory
    ) -> None:
        """Richer D8: a completed unit whose replicas disagreed (no consensus
        promoted) surfaces live as a divergence count, not only retrospectively in
        the evidence footprint."""
        privkey, binding, experiment, _hash = approved_experiment
        _seed_diverged(per_job_factory, experiment.experiment_id)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["diverged_unit_count"] >= 1

    def test_empty_experiment_omits_divergence(self, client, approved_experiment) -> None:
        """The empty rollup (no per-job DB yet) leaves `diverged_unit_count` None,
        so it's omitted under response_model_exclude_none — nothing to corroborate."""
        privkey, binding, experiment, _hash = approved_experiment
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        assert "diverged_unit_count" not in resp.json()
