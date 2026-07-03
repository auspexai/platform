"""D19 — non-consensus payload export (ratified 2026-07-03).

The bundle gains a basis-labeled `additional_results` section under the
ANCHOR-OR-OMIT rule: observation rows anchor to their own receipts, diverged
rows to the predicate's diverged_units hashes, outlier rows to the tolerance
block's outlier_result_hashes (forward-fix). Agreement duplicates never export.
Observe-only replicas take the T-C retention horizon (the tier follows what
the run declared as its science)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from auspexai_platform.db.repositories import ResultRepository
from auspexai_platform.db.repositories.unit_consensus import UnitConsensusRepository
from auspexai_platform.maintenance import _horizon_for

from .test_results_mresults import _seed_unit, _signed_get


def _export(client, privkey, binding, experiment_id):
    resp = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        path=f"/api/v0/experiments/{experiment_id}/results/export",
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestAdditionalResultsExport:
    def test_agreement_duplicates_never_export_and_schema_stays_v1(
        self, client, approved_experiment, per_job_factory
    ):
        privkey, binding, experiment, _mh = approved_experiment
        _seed_unit(
            per_job_factory, experiment.experiment_id, unit_id="u1", payloads=[{"v": 7}, {"v": 7}]
        )
        bundle = _export(client, privkey, binding, experiment.experiment_id)
        assert "additional_results" not in bundle
        assert bundle["schema"] == "auspexai-evidence-bundle/v1"

    def test_diverged_rows_export_with_basis(self, client, approved_experiment, per_job_factory):
        privkey, binding, experiment, _mh = approved_experiment
        # u1 agrees (promoted); u2 diverges (no promotion).
        _seed_unit(
            per_job_factory, experiment.experiment_id, unit_id="u1", payloads=[{"v": 7}, {"v": 7}]
        )
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u2",
            payloads=[{"v": 1}, {"v": 2}],
            promote=False,
        )
        bundle = _export(client, privkey, binding, experiment.experiment_id)
        assert bundle["schema"] == "auspexai-evidence-bundle/v2"
        rows = bundle["additional_results"]
        assert {r["unit_id"] for r in rows} == {"u2"}
        assert all(r["integrity_basis"] == "diverged" for r in rows)
        assert len(rows) == 2  # both diverged replicas, payloads included
        assert all(r["payload"] is not None for r in rows)
        # Anonymity convention holds: pseudonymous pubkey + signature, no worker_id.
        assert all("worker_id" not in r and r["worker_pubkey_hex"] for r in rows)

    def test_observation_rows_export_with_their_receipts(
        self, client, approved_experiment, per_job_factory
    ):
        privkey, binding, experiment, _mh = approved_experiment
        db = per_job_factory.get_or_create(experiment.experiment_id)
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"v": 1}, {"v": 2}, {"v": 3}],
        )
        UnitConsensusRepository(db).record(
            unit_id="u1",
            method="builtin_process_only",
            representative=None,
            representative_hash="a" * 64,
            spread=None,
            envelope=None,
            agreeing_workers=1,
            outlier_count=0,
        )
        bundle = _export(client, privkey, binding, experiment.experiment_id)
        rows = bundle.get("additional_results") or []
        # ANCHOR-OR-OMIT: without per-replica receipts in the per-job DB the
        # observation rows must NOT ship (no receipt = no anchor).
        assert rows == []

    def test_outlier_rows_gated_on_forward_fix_hashes(
        self, client, approved_experiment, per_job_factory
    ):
        privkey, binding, experiment, _mh = approved_experiment
        db = per_job_factory.get_or_create(experiment.experiment_id)
        _repo, results = _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"v": 1.0}, {"v": 1.01}, {"v": 9.9}],
        )
        # Pre-fix record: outlier_count only → the outlier row must NOT ship.
        UnitConsensusRepository(db).record(
            unit_id="u1",
            method="builtin_tolerance_v0",
            representative={"v": 1.0},
            representative_hash="b" * 64,
            spread={"v": 0.01},
            envelope={"v": {"rule": "numeric", "rel": 0.02}},
            agreeing_workers=2,
            outlier_count=1,
        )
        bundle = _export(client, privkey, binding, experiment.experiment_id)
        assert "additional_results" not in bundle
        # Post-fix record: the outlier's hash is anchored → it ships.
        outlier_hash = results[2].semantic_hash
        UnitConsensusRepository(db).record(
            unit_id="u1",
            method="builtin_tolerance_v0",
            representative={"v": 1.0},
            representative_hash="b" * 64,
            spread={"v": 0.01},
            envelope={"v": {"rule": "numeric", "rel": 0.02}},
            agreeing_workers=2,
            outlier_count=1,
            outlier_result_hashes=[outlier_hash],
        )
        bundle = _export(client, privkey, binding, experiment.experiment_id)
        rows = bundle["additional_results"]
        assert len(rows) == 1
        assert rows[0]["integrity_basis"] == "outlier"
        assert rows[0]["semantic_hash"] == outlier_hash
        # The within-envelope non-promoted member (v=1.01) stays unexported.


class TestObservationRetentionTier:
    def test_process_only_rows_take_the_consensus_horizon(
        self, client, approved_experiment, per_job_factory, experiment_repository
    ):
        _privkey, _binding, experiment, _mh = approved_experiment
        db = per_job_factory.get_or_create(experiment.experiment_id)
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"v": 1}, {"v": 2}],
            completed_at=datetime.now(UTC) - timedelta(days=90),
        )
        exp = experiment_repository.get_by_id(experiment.experiment_id)
        non_promoted = next(
            r for r in ResultRepository(db).list_active_payloads() if not r.is_consensus
        )
        # T-X clock (byproduct): 90 days old, never collected → grace expired.
        assert _horizon_for(non_promoted, exp, raw_ttl_days=30, grace_days=14) < datetime.now(UTC)
        # Declared-science clock: same row under an observe-only unit is KEPT
        # (experiment-lifetime — no consensus_ttl_days override set).
        assert (
            _horizon_for(
                non_promoted,
                exp,
                raw_ttl_days=30,
                grace_days=14,
                observation_units=frozenset({"u1"}),
            )
            is None
        )
