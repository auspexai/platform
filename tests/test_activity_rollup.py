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
    from 2 distinct workers."""
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
