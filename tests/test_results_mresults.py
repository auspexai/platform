"""M-Results — researcher results delivery + three-tier retention.

Covers the `GET /experiments/{id}/results` family, the offload export bundle
(consensus payloads + receipts + manifest + a signed proof-of-transfer), the
age-off sweep (dry-run vs apply, collection-anchored, hold-aware), and the
maintainer retention-hold action. Mirrors test_receipts_rd1b.py's harness.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.db.repositories import ResultRepository
from auspexai_platform.maintenance import age_off_sweep

AUTHORITY = "testserver"


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    # RFC 9421 covers @path (no query); sign the path-without-query, request the full.
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path.split("?", 1)[0],
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _seed_unit(
    per_job_factory: PerJobDatabaseFactory,
    experiment_id: str,
    *,
    unit_id: str,
    payloads: list[dict],
    completed_at: datetime | None = None,
    promote: bool = True,
) -> tuple[ResultRepository, list]:
    """Create a completed work unit + its results in the experiment's per-job DB.
    If `promote`, mark the first result the consensus (T-C) copy (the rest T-X)."""
    db = per_job_factory.get_or_create(experiment_id)
    completed = (completed_at or datetime.now(UTC)).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO work_units "
        "(unit_id, payload_json, status, replication_target, completions_so_far, created_at) "
        "VALUES (?, '{}', 'completed', ?, ?, ?)",
        (unit_id, len(payloads), len(payloads), completed),
    )
    repo = ResultRepository(db)
    results = []
    for i, payload in enumerate(payloads):
        results.append(
            repo.insert(
                result_id=f"res-{unit_id}-{i}",
                unit_id=unit_id,
                worker_id=f"wkr-{unit_id}-{i}",
                worker_pubkey_hex=f"{i + 1:02x}" * 32,
                exit_code=0,
                payload=payload,
                worker_signature="c2ln",
                completed_at=completed_at or datetime.now(UTC),
            )
        )
    if promote:
        repo.promote_consensus(unit_id, results[0].result_id)
    return repo, results


# ---- delivery route --------------------------------------------------------


class TestResultsRoute:
    def test_researcher_gets_consensus_with_payload_no_worker_identity(
        self, client, approved_experiment, per_job_factory
    ):
        privkey, binding, experiment, _h = approved_experiment
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"answer": 42}, {"answer": 42}, {"answer": 42}],
        )
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results",
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["results"]
        assert len(items) == 1  # consensus default → one per unit
        item = items[0]
        assert item["payload"] == {"answer": 42}
        assert item["semantic_hash"]
        assert item["is_consensus"] is True
        # worker identity is ACCOUNT_SCOPED → stripped for the researcher.
        assert "worker_id" not in item
        assert "worker_pubkey_hex" not in item

    def test_include_raw_returns_all_replicas(self, client, approved_experiment, per_job_factory):
        privkey, binding, experiment, _h = approved_experiment
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"a": 1}, {"a": 1}, {"a": 1}],
        )
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results?include=raw",
        )
        assert resp.status_code == 200
        assert len(resp.json()["results"]) == 3

    def test_maintainer_sees_worker_identity(
        self, client, maintainer_token, approved_experiment, per_job_factory
    ):
        _p, _b, experiment, _h = approved_experiment
        _seed_unit(per_job_factory, experiment.experiment_id, unit_id="u1", payloads=[{"a": 1}])
        resp = client.get(
            f"/api/v0/experiments/{experiment.experiment_id}/results",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert resp.status_code == 200
        item = resp.json()["results"][0]
        assert item["worker_id"] == "wkr-u1-0"
        assert item["worker_pubkey_hex"]

    def test_fetch_marks_delivered(self, client, approved_experiment, per_job_factory):
        privkey, binding, experiment, _h = approved_experiment
        repo, _ = _seed_unit(
            per_job_factory, experiment.experiment_id, unit_id="u1", payloads=[{"a": 1}]
        )
        assert repo.get_by_id("res-u1-0").delivered_at is None
        _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results",
        )
        assert repo.get_by_id("res-u1-0").delivered_at is not None

    def test_other_tenant_forbidden(self, client, approved_experiment, tenant_registry):
        _p, _b, experiment, _h = approved_experiment
        other = Ed25519PrivateKey.generate()
        other_pub = other.public_key().public_bytes_raw().hex()
        tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
        resp = _signed_get(
            client,
            privkey=other,
            pubkey_hex=other_pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results",
        )
        assert resp.status_code == 403

    def test_missing_experiment_404(self, client, registered_tenant):
        privkey, binding = registered_tenant
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path="/api/v0/experiments/exp-nope/results",
        )
        assert resp.status_code == 404

    def test_anonymous_forbidden(self, client, approved_experiment):
        _p, _b, experiment, _h = approved_experiment
        resp = client.get(f"/api/v0/experiments/{experiment.experiment_id}/results")
        assert resp.status_code in (401, 403)


# ---- offload export bundle -------------------------------------------------


class TestExportBundle:
    def test_export_has_manifest_consensus_and_signed_transfer(
        self, client, approved_experiment, per_job_factory, experiment_repository
    ):
        privkey, binding, experiment, _manifest_hash = approved_experiment
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"v": 7}, {"v": 7}],
        )
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert resp.status_code == 200, resp.text
        bundle = resp.json()
        assert bundle["manifest"]["experiment_id"] == "exp-label"
        assert len(bundle["consensus_results"]) == 1
        t = bundle["transfer"]
        # The custody record is signed by the coordinator key — verify it.
        record = (
            f"{t['result_set_root']}|{t['collected_by_pubkey']}|"
            f"{t['collected_at']}|{t['manifest_hash']}"
        ).encode()
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(t["coordinator_pubkey_hex"]))
        pub.verify(bytes.fromhex(t["coordinator_signature"]), record)  # raises if bad
        assert t["collected_by_pubkey"] == binding.pubkey_hex
        # EB-1: a pre-completion export has no canonical attestation — the
        # custody root stays the flat construction, and the bundle says so.
        assert t["root_kind"] == "flat-v0"
        assert bundle["attestation"] is None
        assert bundle["schema"] == "auspexai-evidence-bundle/v1"
        # The INPUT leg is always present (seeded work-unit payloads are {}).
        assert {u["unit_id"] for u in bundle["work_units"]} == {"u1"}
        # Collection stamped → arms collection-anchored age-off.
        assert experiment_repository.get_by_id(experiment.experiment_id).results_collected_at

    def _seed_receipted_unit(
        self, per_job_factory, receipt_index_repository, experiment_id, *,
        unit_id, payload, worker_id,
    ):
        _repo, results = _seed_unit(
            per_job_factory, experiment_id, unit_id=unit_id, payloads=[payload]
        )
        receipt_index_repository.record(
            receipt_id=f"rcpt-{unit_id}",
            experiment_id=experiment_id,
            worker_id=worker_id,
            worker_pubkey="ab" * 32,
            result_id=results[0].result_id,
        )

    def test_export_completed_unifies_root_with_attestation(
        self,
        client,
        approved_experiment,
        per_job_factory,
        receipt_index_repository,
        experiment_repository,
        enrolled_worker,
    ):
        """EB-1 (§9 #47): for a COMPLETED experiment the proof-of-transfer
        signs the canonical attestation's merkle root — one root binds data ↔
        custody ↔ Rekor — and the bundle carries the attestation artifact."""
        privkey, binding, experiment, _h = approved_experiment
        _, worker = enrolled_worker
        for i in range(2):
            self._seed_receipted_unit(
                per_job_factory,
                receipt_index_repository,
                experiment.experiment_id,
                unit_id=f"u{i}",
                payload={"v": i},
                worker_id=worker.worker_id,
            )
        experiment_repository.update_status(
            experiment.experiment_id, ExperimentStatus.COMPLETED
        )
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert resp.status_code == 200, resp.text
        bundle = resp.json()
        att = bundle["attestation"]
        assert att is not None
        assert att["algorithm"] == "sha256-merkle-v1"
        assert att["cose_b64"]
        t = bundle["transfer"]
        assert t["root_kind"] == "sha256-merkle-v1"
        assert t["result_set_root"] == att["merkle_root"]
        assert t["attestation_id"] == att["attestation_id"]
        # The custody signature verifies over the UNIFIED root.
        record = (
            f"{t['result_set_root']}|{t['collected_by_pubkey']}|"
            f"{t['collected_at']}|{t['manifest_hash']}"
        ).encode()
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(t["coordinator_pubkey_hex"]))
        pub.verify(bytes.fromhex(t["coordinator_signature"]), record)
        assert {u["unit_id"] for u in bundle["work_units"]} == {"u0", "u1"}

    def test_export_refuses_when_results_no_longer_match_attestation(
        self,
        client,
        approved_experiment,
        per_job_factory,
        receipt_index_repository,
        experiment_repository,
        enrolled_worker,
    ):
        """Verify-on-export (the at-rest tamper alarm): if the stored result
        set no longer reproduces the canonical attestation's root, the export
        REFUSES to sign custody — 409, audited."""
        privkey, binding, experiment, _h = approved_experiment
        _, worker = enrolled_worker
        self._seed_receipted_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        experiment_repository.update_status(
            experiment.experiment_id, ExperimentStatus.COMPLETED
        )
        # First export persists the canonical attestation.
        ok = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert ok.status_code == 200, ok.text
        # Tamper the at-rest consensus hash, then export again.
        db = per_job_factory.get(experiment.experiment_id)
        db.execute("UPDATE results SET semantic_hash = ?", ("ff" * 32,))
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"]["error"]["code"] == "attestation_root_mismatch"

    def test_export_drains_past_page_cap_and_signs_full_root(
        self, client, approved_experiment, per_job_factory, monkeypatch
    ):
        """D1 regression (researcher_data_custody_and_analysis_design.md §2):
        export must page consensus rows to exhaustion — a custody root signed
        over one capped page is a valid-looking proof of an incomplete
        dataset. Cap forced to 2 so 5 units require three pages."""
        import hashlib
        import json

        from auspexai_platform.api import results as results_api

        privkey, binding, experiment, _h = approved_experiment
        for i in range(5):
            _seed_unit(
                per_job_factory,
                experiment.experiment_id,
                unit_id=f"u{i}",
                payloads=[{"v": i}, {"v": i}],
            )
        monkeypatch.setattr(results_api, "MAX_PAGE_SIZE", 2)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results/export",
        )
        assert resp.status_code == 200, resp.text
        bundle = resp.json()
        assert {r["unit_id"] for r in bundle["consensus_results"]} == {
            f"u{i}" for i in range(5)
        }
        # The signed custody root must cover the FULL set, not the first page.
        items = sorted(
            (r["unit_id"], r.get("semantic_hash") or "") for r in bundle["consensus_results"]
        )
        expected_root = hashlib.sha256(
            json.dumps(items, separators=(",", ":")).encode()
        ).hexdigest()
        assert bundle["transfer"]["result_set_root"] == expected_root


# ---- age-off sweep ---------------------------------------------------------


class TestAgeOffSweep:
    def _old(self) -> datetime:
        return datetime.now(UTC) - timedelta(days=60)

    def test_dry_run_reports_but_does_not_mutate(
        self, approved_experiment, per_job_factory, config, db
    ):
        _p, _b, experiment, _h = approved_experiment
        repo, _ = _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"a": 1}, {"a": 1}],
            completed_at=self._old(),
        )
        report = age_off_sweep(config.jobs_dir, db, apply=False, now=datetime.now(UTC))
        assert report.total_aged >= 1
        # T-X replica (res-u1-1) is past grace; payload still intact (dry-run).
        assert repo.get_by_id("res-u1-1").payload == {"a": 1}
        assert repo.get_by_id("res-u1-1").payload_aged_off_at is None

    def test_apply_blanks_tx_keeps_consensus(
        self, approved_experiment, per_job_factory, config, db
    ):
        _p, _b, experiment, _h = approved_experiment
        repo, _ = _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"a": 1}, {"a": 1}],
            completed_at=self._old(),
        )
        age_off_sweep(config.jobs_dir, db, apply=True, now=datetime.now(UTC))
        # T-X replica aged off (payload blanked, flag set); consensus kept.
        tx = repo.get_by_id("res-u1-1")
        assert tx.payload_aged_off_at is not None
        assert tx.payload == {}
        assert tx.semantic_hash  # provenance preserved
        consensus = repo.get_by_id("res-u1-0")
        assert consensus.is_consensus is True
        assert consensus.payload == {"a": 1}
        assert consensus.payload_aged_off_at is None

    def test_hold_skips_experiment(
        self, approved_experiment, per_job_factory, config, db, experiment_repository
    ):
        _p, _b, experiment, _h = approved_experiment
        repo, _ = _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"a": 1}, {"a": 1}],
            completed_at=self._old(),
        )
        experiment_repository.set_retention_hold(
            experiment.experiment_id, held=True, reason="litigation hold"
        )
        report = age_off_sweep(config.jobs_dir, db, apply=True, now=datetime.now(UTC))
        assert report.total_aged == 0
        assert report.held_count == 1
        assert repo.get_by_id("res-u1-1").payload == {"a": 1}

    def test_aged_off_result_api_shape(
        self, client, approved_experiment, per_job_factory, config, db
    ):
        privkey, binding, experiment, _h = approved_experiment
        _seed_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u1",
            payloads=[{"a": 1}, {"a": 1}],
            completed_at=self._old(),
        )
        age_off_sweep(config.jobs_dir, db, apply=True, now=datetime.now(UTC))
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/results?include=raw",
        )
        assert resp.status_code == 200
        aged = [r for r in resp.json()["results"] if r.get("aged_off")]
        assert aged
        for r in aged:
            assert "payload" not in r  # excluded; the receipt/hash still prove it ran
            assert r["semantic_hash"]


# ---- retention-hold action -------------------------------------------------


class TestRetentionHoldAction:
    def test_maintainer_can_hold_and_release(
        self, client, maintainer_token, approved_experiment, experiment_repository
    ):
        _p, _b, experiment, _h = approved_experiment
        eid = experiment.experiment_id
        h = {"Authorization": f"Bearer {maintainer_token}"}
        resp = client.post(
            f"/api/v0/experiments/{eid}/actions/retention-hold?reason=audit", headers=h
        )
        assert resp.status_code == 200, resp.text
        assert experiment_repository.get_by_id(eid).retention_hold is True
        resp = client.post(f"/api/v0/experiments/{eid}/actions/release-hold", headers=h)
        assert resp.status_code == 200
        assert experiment_repository.get_by_id(eid).retention_hold is False

    def test_hold_requires_reason(self, client, maintainer_token, approved_experiment):
        _p, _b, experiment, _h = approved_experiment
        resp = client.post(
            f"/api/v0/experiments/{experiment.experiment_id}/actions/retention-hold?reason=",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert resp.status_code == 422

    def test_researcher_cannot_hold(self, client, approved_experiment):
        privkey, binding, experiment, _h = approved_experiment
        base = f"/api/v0/experiments/{experiment.experiment_id}/actions/retention-hold"
        headers = sign_request(
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            method="POST",
            path=base,  # @path excludes the query
            authority=AUTHORITY,
            body=b"",
        )
        resp = client.post(base + "?reason=x", headers=headers)
        assert resp.status_code == 403


# ---- O-M8: retention policy exposure + age-off projection ------------------


def test_projected_raw_age_off_math():
    """Unit: collection-anchored, no extra grace; default TTL when unset."""
    from types import SimpleNamespace

    from auspexai_platform.maintenance import (
        DEFAULT_RAW_TTL_DAYS,
        projected_raw_age_off,
    )

    now = datetime(2026, 1, 1, tzinfo=UTC)
    # Not collected yet → no experiment-level projection.
    assert (
        projected_raw_age_off(SimpleNamespace(results_collected_at=None, raw_payload_ttl_days=7))
        is None
    )
    # Collected + override TTL → collected + ttl (no grace).
    assert projected_raw_age_off(
        SimpleNamespace(results_collected_at=now, raw_payload_ttl_days=7)
    ) == now + timedelta(days=7)
    # Collected + no override → default raw TTL.
    assert projected_raw_age_off(
        SimpleNamespace(results_collected_at=now, raw_payload_ttl_days=None)
    ) == now + timedelta(days=DEFAULT_RAW_TTL_DAYS)


class TestRetentionExposure:
    def _maintainer_get(self, client, maintainer_token, eid):
        return client.get(
            f"/api/v0/experiments/{eid}",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )

    def test_operator_sees_ttls_and_projection(
        self, client, maintainer_token, approved_experiment, experiment_repository
    ):
        _p, _b, experiment, _h = approved_experiment
        eid = experiment.experiment_id
        experiment_repository.set_ttl_overrides(eid, raw_payload_ttl_days=7, consensus_ttl_days=90)
        experiment_repository.mark_results_collected(eid)
        resp = self._maintainer_get(client, maintainer_token, eid)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["raw_payload_ttl_days"] == 7
        assert body["consensus_ttl_days"] == 90
        collected = experiment_repository.get_by_id(eid).results_collected_at
        assert datetime.fromisoformat(body["raw_payload_age_off_at"]) == collected + timedelta(
            days=7
        )

    def test_tenant_does_not_see_policy_fields(
        self, client, approved_experiment, experiment_repository
    ):
        privkey, binding, experiment, _h = approved_experiment
        eid = experiment.experiment_id
        experiment_repository.set_ttl_overrides(eid, raw_payload_ttl_days=7, consensus_ttl_days=90)
        experiment_repository.mark_results_collected(eid)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{eid}",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # OPERATOR_ONLY policy fields are stripped for the tenant...
        assert "raw_payload_ttl_days" not in body
        assert "consensus_ttl_days" not in body
        assert "raw_payload_age_off_at" not in body
        # ...but the tenant-scoped *effect* (collection anchor) stays visible.
        assert "results_collected_at" in body

    def test_projection_absent_until_collected(
        self, client, maintainer_token, approved_experiment, experiment_repository
    ):
        _p, _b, experiment, _h = approved_experiment
        eid = experiment.experiment_id
        experiment_repository.set_ttl_overrides(
            eid, raw_payload_ttl_days=7, consensus_ttl_days=None
        )
        resp = self._maintainer_get(client, maintainer_token, eid)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["raw_payload_ttl_days"] == 7
        # None → excluded by response_model_exclude_none.
        assert "raw_payload_age_off_at" not in body


# ---- repository units ------------------------------------------------------


def test_promote_consensus_is_exclusive(per_job_factory):
    repo, results = _seed_unit(
        per_job_factory, "exp-x", unit_id="u1", payloads=[{"a": 1}, {"a": 1}], promote=False
    )
    repo.promote_consensus("u1", results[1].result_id)
    assert repo.get_by_id(results[1].result_id).is_consensus is True
    assert repo.get_by_id(results[0].result_id).is_consensus is False
    # re-promoting another flips exclusively
    repo.promote_consensus("u1", results[0].result_id)
    assert repo.get_by_id(results[0].result_id).is_consensus is True
    assert repo.get_by_id(results[1].result_id).is_consensus is False
