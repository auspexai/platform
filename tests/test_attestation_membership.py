"""Signature-scope regression suite (2026-06-12 finding, D1's sibling).

The result-set attestation used to decide leaf membership from the control-DB
`receipt_index` — a best-effort display cache whose write failures are
swallowed at issuance. One failed index write produced a canonical,
validly-signed, internally-consistent attestation covering N-1 of N consensus
units, undetectable by the standalone verify path. These tests pin the fix:

1. membership now derives from the AUTHORITATIVE per-job receipts ⨝ results
   join (`receipt_map_from_per_job`) — a missing index row changes nothing;
2. an independent persist-time recount (`assert_entries_cover_consensus`)
   refuses to sign a set that diverges from the consensus table;
3. the evidence bundle's receipts are likewise index-independent;
4. `receipts rebuild-index` reconciles the display cache from per-job truth.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.receipts.attestation import (
    IncompleteAttestationSetError,
    assert_entries_cover_consensus,
    collect_result_set_entries,
    receipt_map_from_per_job,
)
from tests.test_attestation import _seed_consensus_unit, _signed_get


def _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker):
    for i in range(3):
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id=f"u{i}",
            payload={"v": i},
            worker_id=worker.worker_id,
        )


class TestAuthoritativeMembership:
    def test_attestation_unaffected_by_missing_index_row(
        self,
        client: TestClient,
        approved_experiment,
        per_job_factory,
        receipt_index_repository,
        experiment_repository,
        enrolled_worker,
        db,
    ):
        """THE regression: drop one receipt_index row (the swallowed-write
        failure mode) — the attestation must still cover all 3 units with a
        root byte-identical to the fully-indexed build."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        path = f"/api/v0/experiments/{experiment.experiment_id}/attestation"

        # Reference build while the index is intact.
        healthy = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path)
        assert healthy.status_code == 200
        healthy_body = healthy.json()
        assert healthy_body["unit_count"] == 3

        # Simulate the swallowed index write: remove one row, wipe the
        # persisted attestation so the route must rebuild from scratch.
        db.execute("DELETE FROM receipt_index WHERE receipt_id = 'rcpt-u1'")
        db.execute("DELETE FROM attestations WHERE experiment_id = ?", (experiment.experiment_id,))

        rebuilt = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path)
        assert rebuilt.status_code == 200
        body = rebuilt.json()
        assert body["unit_count"] == 3  # pre-fix this silently dropped to 2
        assert body["merkle_root"] == healthy_body["merkle_root"]
        assert {u["unit_id"] for u in body["units"]} == {"u0", "u1", "u2"}

    def test_export_bundle_receipts_unaffected_by_missing_index_row(
        self,
        client: TestClient,
        approved_experiment,
        per_job_factory,
        receipt_index_repository,
        experiment_repository,
        enrolled_worker,
        db,
    ):
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        db.execute("DELETE FROM receipt_index WHERE receipt_id = 'rcpt-u1'")

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert resp.status_code == 200, resp.text
        bundle = resp.json()
        assert {r["receipt_id"] for r in bundle["receipts"]} == {"rcpt-u0", "rcpt-u1", "rcpt-u2"}
        by_unit = {r["unit_id"]: r for r in bundle["consensus_results"]}
        assert by_unit["u1"]["receipt_id"] == "rcpt-u1"

    def test_map_builder_joins_receipts_to_results(
        self, per_job_factory, receipt_index_repository, approved_experiment, enrolled_worker
    ):
        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        per_job_db = per_job_factory.get(experiment.experiment_id)
        assert receipt_map_from_per_job(per_job_db) == {
            "res-u0": "rcpt-u0",
            "res-u1": "rcpt-u1",
            "res-u2": "rcpt-u2",
        }


class TestRecountGuard:
    def test_guard_refuses_divergent_set(
        self,
        client: TestClient,
        approved_experiment,
        per_job_factory,
        receipt_index_repository,
        experiment_repository,
        enrolled_worker,
    ):
        """Corrupt one receipt body: the join can no longer claim the unit's
        leaf, but the unit-level recount still sees the receipt row — the
        route must 409 rather than sign the narrower set."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        per_job_db = per_job_factory.get(experiment.experiment_id)
        per_job_db.execute(
            "UPDATE receipts SET receipt_body_cbor = ? WHERE receipt_id = 'rcpt-u1'",
            (b"not-cbor",),
        )

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/attestation",
        )
        assert resp.status_code == 409
        err = resp.json()["detail"]["error"]
        assert err["code"] == "attestation_incomplete_set"
        assert err["details"]["missing_units"] == ["u1"]

    def test_guard_passes_when_unit_genuinely_has_no_receipt(
        self, per_job_factory, receipt_index_repository, approved_experiment, enrolled_worker
    ):
        """A consensus row with NO receipt row at all stays excluded by design
        (disagreement/issuance-failure semantics) — the guard's predicate is
        receipt-holding units, so this is consistent, not divergent."""
        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        per_job_db = per_job_factory.get(experiment.experiment_id)
        per_job_db.execute("DELETE FROM receipts WHERE receipt_id = 'rcpt-u1'")
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=receipt_map_from_per_job(per_job_db)
        )
        assert {e.unit_id for e in entries} == {"u0", "u2"}
        assert_entries_cover_consensus(per_job_db, entries)  # no raise

    def test_guard_raises_on_short_entries(
        self, per_job_factory, receipt_index_repository, approved_experiment, enrolled_worker
    ):
        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        per_job_db = per_job_factory.get(experiment.experiment_id)
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=receipt_map_from_per_job(per_job_db)
        )
        short = [e for e in entries if e.unit_id != "u2"]
        try:
            assert_entries_cover_consensus(per_job_db, short)
        except IncompleteAttestationSetError as e:
            assert e.missing_units == ["u2"]
        else:
            raise AssertionError("guard accepted a short set")


class TestRebuildIndexCli:
    def test_rebuild_restores_missing_rows(
        self,
        per_job_factory,
        receipt_index_repository,
        approved_experiment,
        enrolled_worker,
        db,
    ):
        """The promised sweep, now real: drop index rows, rebuild from the
        per-job join, confirm restoration incl. the result_id backreference."""
        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_three_units(per_job_factory, receipt_index_repository, experiment, worker)
        db.execute("DELETE FROM receipt_index WHERE receipt_id IN ('rcpt-u0', 'rcpt-u2')")
        assert len(receipt_index_repository.list_for_experiment(experiment.experiment_id)) == 1

        # Mirror the CLI body (the command itself needs a state dir; the
        # reconcile logic is what matters here).
        per_job_db = per_job_factory.get(experiment.experiment_id)
        indexed = {
            e.result_id
            for e in receipt_index_repository.list_for_experiment(experiment.experiment_id)
            if e.result_id is not None
        }
        authoritative = receipt_map_from_per_job(per_job_db)
        worker_by_result = {
            row["result_id"]: (row["worker_id"], row["worker_pubkey_hex"])
            for row in per_job_db.execute(
                "SELECT result_id, worker_id, worker_pubkey_hex FROM results"
            )
        }
        for result_id in sorted(set(authoritative) - indexed):
            worker_id, worker_pubkey = worker_by_result[result_id]
            receipt_index_repository.record(
                receipt_id=authoritative[result_id],
                experiment_id=experiment.experiment_id,
                worker_id=worker_id,
                worker_pubkey=worker_pubkey,
                result_id=result_id,
            )

        entries = receipt_index_repository.list_for_experiment(experiment.experiment_id)
        assert {e.receipt_id for e in entries} == {"rcpt-u0", "rcpt-u1", "rcpt-u2"}
        assert {e.result_id for e in entries} == {"res-u0", "res-u1", "res-u2"}
