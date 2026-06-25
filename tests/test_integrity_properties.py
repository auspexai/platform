"""Property-based integrity pass — result acceptance + export state machine.

§9 #47 follow-up (external-review recommendation, evidence-backed: three
integrity-class bugs surfaced in this subsystem within 48 hours, each found by
a *different* method — the 7-agent audit, the D6 live run, and a design-session
code reading). This suite replaces incidental discovery with systematic
adversarial coverage: a Hypothesis state machine drives arbitrary interleavings
of the real HTTP routes (multiple experiments with COLLIDING tenant-chosen
unit_ids, multiple workers, aborts mid-flight, late/duplicate results, exports)
and checks the integrity invariants after every step:

  I1  per-unit accounting: completions_so_far == result rows; status is
      'completed' iff completions >= replication_target.
  I2  consensus uniqueness: at most one is_consensus row per unit, only on
      completed units.
  I3  no misattribution: each experiment's result-row count equals the number
      of submissions the model saw ACCEPTED for that experiment (the D6
      bare-unit_id collision bug class).
  I4  terminal guard: a result is never accepted into an aborted experiment
      (acceptance into one would break I3's per-experiment ledger).
  I5  post-completion stability: once an experiment COMPLETES, its consensus
      set {(unit_id, semantic_hash)} never changes — late results are durable
      replicas, never promotions (M9 leg 3).
  I6  export never false-alarms: for any legitimately-reached state the
      evidence-bundle export returns 200 (the verify-on-export 409 fires ONLY
      on real at-rest tamper), and a COMPLETED export's custody root equals
      the canonical attestation's merkle root.

Each Hypothesis example builds a fully fresh world (own tmpdir, control DB,
app, client) — no pytest fixtures, so examples can't leak state into each
other (HealthCheck.function_scoped_fixture).
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
)

from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.signature import sign_request
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.config import Config
from auspexai_platform.db import Database, MigrationRunner
from auspexai_platform.db.repositories import TenantRepository
from auspexai_platform.main import create_app
from auspexai_platform.rate_limit import reset_for_tests as _reset_rate_limit
from tests._result_helpers import sign_result_body

pytestmark = __import__("pytest").mark.timeout(600)

AUTHORITY = "testserver"
# Tiny unit-id alphabet → cross-experiment collisions are the COMMON case,
# exactly the namespace the D6 misattribution bug lived in.
UNIT_IDS = ["u0", "u1", "u2"]


def _ed25519() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


class World:
    """A fresh coordinator: tmpdir-isolated config/DB/app/client + the signed
    request helpers. Built once per Hypothesis example."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="auspexai-prop-")
        state_dir = Path(self._tmp.name) / "state"
        state_dir.mkdir()
        self.config = Config(state_dir=state_dir)
        token_store = TokenStore(self.config.maintainer_token_path)
        token_store.initialize()
        self.maintainer_headers = {"Authorization": f"Bearer {token_store.active_tokens()[0]}"}
        self.db = Database(self.config.control_db_path)
        MigrationRunner(self.db).apply_all()
        tenant_registry = TenantRegistry(TenantRepository(self.db))
        _reset_rate_limit()
        app = create_app(
            config=self.config,
            token_store=token_store,
            tenant_registry=tenant_registry,
            db=self.db,
            identity_verifier=None,
        )
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()
        # one researcher tenant drives every experiment (collisions are
        # per-tenant by construction: unit_ids are tenant-chosen)
        self.researcher_priv, self.researcher_pub = _ed25519()
        r = self.client.post(
            "/api/v0/tenants",
            headers=self.maintainer_headers,
            json={"tenant_id": "prop-tenant", "maintainer_pubkey": self.researcher_pub},
        )
        assert r.status_code == 201, r.text

    def close(self) -> None:
        try:
            self._client_cm.__exit__(None, None, None)
            self.db.close()
        finally:
            self._tmp.cleanup()

    # ---- signed request helpers ----

    def signed(self, method: str, path: str, *, privkey, pubkey_hex, json_body=None):
        body = json.dumps(json_body).encode() if json_body is not None else b""
        headers = sign_request(
            privkey=privkey,
            pubkey_hex=pubkey_hex,
            method=method,
            path=path,
            authority=AUTHORITY,
            body=body,
        )
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        return self.client.request(method, path, headers=headers, content=body or None)

    def researcher(self, method: str, path: str, json_body=None):
        return self.signed(
            method,
            path,
            privkey=self.researcher_priv,
            pubkey_hex=self.researcher_pub,
            json_body=json_body,
        )

    # ---- domain helpers ----

    def create_approved_experiment(
        self, label: str, *, replication_factor: int | None = None
    ) -> tuple[str, str]:
        manifest = {
            "tenant_id": "prop-tenant",
            "experiment_id": label,
            "executor": "python -m prop.executor",
        }
        if replication_factor is not None:  # C14: opt into explicit repl (else the tier default)
            manifest["replication_factor"] = replication_factor
        r = self.researcher(
            "POST",
            "/api/v0/experiments",
            json_body={
                "manifest": manifest,
                "signature": {"alg": "ed25519", "sig": "opaque-to-v0"},
            },
        )
        assert r.status_code == 201, r.text
        exp_id = r.json()["experiment_id"]
        manifest_hash = r.json()["manifest_hash"]
        r = self.client.post(
            f"/api/v0/experiments/{exp_id}/actions/approve",
            headers=self.maintainer_headers,
        )
        assert r.status_code == 200, r.text
        return exp_id, manifest_hash

    def enroll_worker(self) -> dict:
        priv, pub = _ed25519()
        r = self.client.post(
            "/api/v0/workers/enroll",
            json={"pubkey_hex": pub, "capabilities": {"os": "linux"}},
        )
        assert r.status_code == 201, r.text
        return {"priv": priv, "pub": pub, "id": r.json()["worker_id"]}

    def soak(self) -> None:
        """Pre-populate accumulated coordinator mess (nightly profile): six
        experiments left in varied states — aborted with dangling assignments,
        completed-and-finalized, paused with pending units — plus two busy
        workers, so every Hypothesis example runs against a soaked DB instead
        of a clean slate. Fully deterministic (no randomness): a failure under
        soak reproduces. Every soak experiment ends in a state the scheduler
        will NOT offer from (aborted/completed/paused), so the machine's own
        workers never receive soak units."""
        workers = [self.enroll_worker() for _ in range(2)]

        def drain(exp_id: str) -> None:
            # fetch+submit until the scheduler stops offering (trusted, N=1)
            for _ in range(6):
                offered = False
                for w in workers:
                    r = self.signed(
                        "GET",
                        f"/api/v0/workers/{w['id']}/assignments",
                        privkey=w["priv"],
                        pubkey_hex=w["pub"],
                    )
                    body = r.json()
                    if not body.get("work_unit"):
                        continue
                    offered = True
                    u = body["work_unit"]["unit_id"]
                    rr = self.signed(
                        "POST",
                        f"/api/v0/workers/{w['id']}/assignments/{u}/result",
                        privkey=w["priv"],
                        pubkey_hex=w["pub"],
                        json_body={
                            "unit_id": u,
                            "worker_pubkey": w["pub"],
                            "completed_at": "2026-06-11T12:00:00+00:00",
                            "exit_code": 0,
                            "payload": {"answer": u},
                            # #13a verifies worker_signature at submit — the soak's
                            # drained results must carry a REAL signature (a fake one
                            # bounces, leaving units IN_PROGRESS in an APPROVED
                            # experiment, which the scheduler then offers → the soak's
                            # "never offers soak units" invariant breaks).
                            "worker_signature": sign_result_body(
                                w["priv"],
                                w["pub"],
                                unit_id=u,
                                completed_at="2026-06-11T12:00:00+00:00",
                                exit_code=0,
                                payload={"answer": u},
                            ),
                            "assignment_id": body["assignment_id"],
                        },
                    )
                    # Fail loudly if a future submit-contract change rejects these
                    # again, instead of silently leaving an offerable unit behind.
                    assert rr.status_code == 201, rr.text
                if not offered:
                    return

        for i in range(6):
            label = f"soak-exp-{i}"
            exp_id, manifest_hash = self.create_approved_experiment(label)
            r = self.client.post(
                f"/api/v0/experiments/{exp_id}/actions/set-integrity-policy",
                headers=self.maintainer_headers,
                json={"integrity_policy": "trusted", "reason": "soak fixture", "force": True},
            )
            assert r.status_code == 200, r.text
            units = [f"soak-u{i}-{j}" for j in range(2)]
            r = self.researcher(
                "POST",
                f"/api/v0/experiments/{exp_id}/work-units",
                json_body={
                    "work_units": [
                        {
                            "schema_version": "0.1",
                            "unit_id": u,
                            "tenant_id": "prop-tenant",
                            "experiment_id": label,
                            "manifest_sha256": manifest_hash,
                            "created_at": "2026-06-11T00:00:00Z",
                            "payload": {"q": u},
                            "replication_target": 1,
                        }
                        for u in units
                    ]
                },
            )
            assert r.status_code == 201, r.text
            if i % 3 == 0:
                # dangling assignments into an abort (stale-state mess)
                for w in workers:
                    self.signed(
                        "GET",
                        f"/api/v0/workers/{w['id']}/assignments",
                        privkey=w["priv"],
                        pubkey_hex=w["pub"],
                    )
                r = self.researcher("POST", f"/api/v0/experiments/{exp_id}/actions/abort")
                assert r.status_code == 200, r.text
            elif i % 3 == 1:
                # fully run: results + receipts + attestation-eligible history
                drain(exp_id)
                r = self.researcher(
                    "POST", f"/api/v0/experiments/{exp_id}/actions/finalize-submissions"
                )
                assert r.status_code == 200, r.text
            else:
                # pending units parked behind a pause (no new assignments)
                r = self.researcher("POST", f"/api/v0/experiments/{exp_id}/actions/pause")
                assert r.status_code == 200, r.text

    def per_job_rows(self, exp_id: str, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        path = self.config.jobs_dir / f"{exp_id}.db"
        if not path.exists():
            return []
        con = sqlite3.connect(path)
        con.row_factory = sqlite3.Row
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()


class ResultAcceptanceMachine(RuleBasedStateMachine):
    """Arbitrary interleavings of the real acceptance/lifecycle/export routes,
    with a parallel ledger the DB must always agree with."""

    def __init__(self) -> None:
        super().__init__()
        self.w = World()
        if os.environ.get("AUSPEXAI_PROPERTY_SOAK") == "1":
            self.w.soak()
        self.exp_count = 0
        # exp_id -> {"label", "manifest_hash", "status", "units": {unit_id: target},
        #            "accepted": int, "consensus_snapshot": set | None}
        self.exps: dict[str, dict] = {}
        self.workers: list[dict] = []
        # open (unsubmitted) assignments: list of dicts
        self.assignments: list[dict] = []

    def teardown(self) -> None:
        self.w.close()

    # ---- rules ----------------------------------------------------------

    @rule()
    def create_experiment(self) -> None:
        if len(self.exps) >= 3:
            return
        self.exp_count += 1
        label = f"prop-exp-{self.exp_count}"
        exp_id, manifest_hash = self.w.create_approved_experiment(label)
        # Alternate integrity policy so completion is reachable with <=3
        # workers on half the experiments (replication is MAINTAINER-set;
        # researcher-submitted replication_target is ignored by design).
        if self.exp_count % 2 == 1:
            r = self.w.client.post(
                f"/api/v0/experiments/{exp_id}/actions/set-integrity-policy",
                headers=self.w.maintainer_headers,
                json={"integrity_policy": "trusted", "reason": "property pass: N=1", "force": True},
            )
            assert r.status_code == 200, r.text
        self.exps[exp_id] = {
            "label": label,
            "manifest_hash": manifest_hash,
            "status": "approved",
            "units": {},
            "accepted": 0,
            "finalized": False,
            "consensus_snapshot": None,
        }

    @precondition(lambda self: len(self.workers) < 3)
    @rule()
    def enroll_worker(self) -> None:
        self.workers.append(self.w.enroll_worker())

    @precondition(lambda self: any(e["status"] == "approved" for e in self.exps.values()))
    @rule(data=st.data(), unit_id=st.sampled_from(UNIT_IDS), replication=st.integers(1, 2))
    def submit_unit(self, data, unit_id: str, replication: int) -> None:
        exp_id = data.draw(
            st.sampled_from([k for k, e in self.exps.items() if e["status"] == "approved"])
        )
        e = self.exps[exp_id]
        r = self.w.researcher(
            "POST",
            f"/api/v0/experiments/{exp_id}/work-units",
            json_body={
                "work_units": [
                    {
                        "schema_version": "0.1",
                        "unit_id": unit_id,
                        "tenant_id": "prop-tenant",
                        "experiment_id": e["label"],
                        "manifest_sha256": e["manifest_hash"],
                        "created_at": "2026-06-11T00:00:00Z",
                        "payload": {"q": unit_id},
                        "replication_target": replication,
                    }
                ]
            },
        )
        if e["finalized"]:
            # the finalize gate: no NEW batches after finalize-submissions
            assert r.status_code == 409, r.text
            assert "finalized" in r.text
        elif unit_id in e["units"]:
            assert r.status_code in (400, 409, 422), r.text  # duplicate rejected
        else:
            assert r.status_code == 201, r.text
            actual = self.w.per_job_rows(
                exp_id,
                "SELECT replication_target FROM work_units WHERE unit_id = ?",
                (unit_id,),
            )[0]["replication_target"]
            e["units"][unit_id] = actual

    @precondition(lambda self: self.workers and self.exps)
    @rule(data=st.data())
    def fetch_assignment(self, data) -> None:
        worker = data.draw(st.sampled_from(self.workers))
        r = self.w.signed(
            "GET",
            f"/api/v0/workers/{worker['id']}/assignments",
            privkey=worker["priv"],
            pubkey_hex=worker["pub"],
        )
        assert r.status_code == 200, r.text
        body = r.json()
        if not body.get("work_unit"):
            return
        label = body["work_unit"]["experiment_id"]
        exp_id = next(k for k, e in self.exps.items() if e["label"] == label)
        self.assignments.append(
            {
                "exp_id": exp_id,
                "unit_id": body["work_unit"]["unit_id"],
                "worker": worker,
                "assignment_id": body["assignment_id"],
                "submitted": False,
            }
        )

    def _submit(self, a: dict, *, send_assignment_id: bool) -> None:
        exp = self.exps[a["exp_id"]]
        body = {
            "unit_id": a["unit_id"],
            "worker_pubkey": a["worker"]["pub"],
            "completed_at": "2026-06-11T12:00:00+00:00",
            "exit_code": 0,
            # byte-identical replicas per unit → hash-agreement consensus fires
            "payload": {"answer": a["unit_id"]},
            "worker_signature": sign_result_body(
                a["worker"]["priv"],
                a["worker"]["pub"],
                unit_id=a["unit_id"],
                completed_at="2026-06-11T12:00:00+00:00",
                exit_code=0,
                payload={"answer": a["unit_id"]},
            ),
        }
        if send_assignment_id:
            body["assignment_id"] = a["assignment_id"]
        r = self.w.signed(
            "POST",
            f"/api/v0/workers/{a['worker']['id']}/assignments/{a['unit_id']}/result",
            privkey=a["worker"]["priv"],
            pubkey_hex=a["worker"]["pub"],
            json_body=body,
        )
        if exp["status"] in ("aborted", "archived"):
            # I4: the terminal guard must refuse — never accept, never 5xx.
            assert r.status_code == 404, (
                f"result accepted into terminal experiment: {r.status_code} {r.text}"
            )
            return
        if a["submitted"]:
            assert r.status_code == 409, r.text  # duplicate → idempotent refusal
            return
        assert r.status_code == 201, r.text
        a["submitted"] = True
        exp["accepted"] += 1

    @precondition(lambda self: any(not a["submitted"] for a in self.assignments))
    @rule(data=st.data())
    def submit_result(self, data) -> None:
        a = data.draw(st.sampled_from([a for a in self.assignments if not a["submitted"]]))
        self._submit(a, send_assignment_id=True)

    @precondition(lambda self: any(not a["submitted"] for a in self.assignments))
    @rule(data=st.data())
    def submit_result_legacy_wire(self, data) -> None:
        """Pre-v0.2.2 worker: no assignment_id on the wire. Only exercised when
        the (unit, worker) pair is unambiguous among NON-TERMINAL experiments —
        the ambiguous case is pinned by its own targeted test below."""
        open_unambiguous = [
            a
            for a in self.assignments
            if not a["submitted"]
            and sum(
                1
                for b in self.assignments
                if b["unit_id"] == a["unit_id"]
                and b["worker"]["id"] == a["worker"]["id"]
                and self.exps[b["exp_id"]]["status"] not in ("aborted", "archived")
            )
            <= 1
        ]
        if not open_unambiguous:
            return
        a = data.draw(st.sampled_from(open_unambiguous))
        self._submit(a, send_assignment_id=False)

    @precondition(lambda self: any(a["submitted"] for a in self.assignments))
    @rule(data=st.data())
    def duplicate_submit(self, data) -> None:
        a = data.draw(st.sampled_from([a for a in self.assignments if a["submitted"]]))
        self._submit(a, send_assignment_id=True)

    @precondition(lambda self: any(e["status"] == "approved" for e in self.exps.values()))
    @rule(data=st.data())
    def abort_experiment(self, data) -> None:
        exp_id = data.draw(
            st.sampled_from([k for k, e in self.exps.items() if e["status"] == "approved"])
        )
        r = self.w.client.post(
            f"/api/v0/experiments/{exp_id}/actions/abort",
            headers=self.w.maintainer_headers,
        )
        assert r.status_code in (200, 400, 422), r.text
        if r.status_code == 200:
            self.exps[exp_id]["status"] = "aborted"

    @precondition(
        lambda self: any(e["status"] == "approved" and e["units"] for e in self.exps.values())
    )
    @rule(data=st.data())
    def finalize_submissions(self, data) -> None:
        exp_id = data.draw(
            st.sampled_from(
                [k for k, e in self.exps.items() if e["status"] == "approved" and e["units"]]
            )
        )
        r = self.w.researcher("POST", f"/api/v0/experiments/{exp_id}/actions/finalize-submissions")
        assert r.status_code in (200, 409), r.text
        if r.status_code == 200:
            self.exps[exp_id]["finalized"] = True

    @precondition(lambda self: self.exps)
    @rule(data=st.data())
    def export_bundle(self, data) -> None:
        """I6: export must NEVER 409 on a legitimately-reached state — the
        verify-on-export alarm exists for at-rest tamper only. For a COMPLETED
        experiment the custody root must equal the attestation's root."""
        exp_id = data.draw(st.sampled_from(list(self.exps.keys())))
        r = self.w.researcher("GET", f"/api/v0/experiments/{exp_id}/results/export")
        assert r.status_code == 200, (
            f"export false-alarmed on untampered state: {r.status_code} {r.text}"
        )
        bundle = r.json()
        status = self._db_status(exp_id)
        if status == "completed":
            att = bundle.get("attestation")
            assert att is not None, "completed export missing attestation"
            t = bundle["transfer"]
            assert t["result_set_root"] == att["merkle_root"]
            assert t["root_kind"] == att["algorithm"]

    # ---- invariants -------------------------------------------------------

    def _db_status(self, exp_id: str) -> str:
        r = self.w.client.get(f"/api/v0/experiments/{exp_id}", headers=self.w.maintainer_headers)
        return r.json()["status"]

    @invariant()
    def ledger_agrees_with_db(self) -> None:
        for exp_id, e in self.exps.items():
            rows = self.w.per_job_rows(
                exp_id,
                "SELECT unit_id, COUNT(*) AS n, SUM(is_consensus) AS c FROM results "
                "GROUP BY unit_id",
            )
            # I3 — per-experiment result count == accepted ledger (misattribution
            # in EITHER direction shifts a count somewhere).
            total = sum(r["n"] for r in rows)
            assert total == e["accepted"], (
                f"{exp_id}: {total} result rows vs {e['accepted']} accepted "
                f"(cross-experiment misattribution?)"
            )
            units = {
                r["unit_id"]: r
                for r in self.w.per_job_rows(
                    exp_id,
                    "SELECT unit_id, status, replication_target, completions_so_far "
                    "FROM work_units",
                )
            }
            results_by_unit = {r["unit_id"]: r for r in rows}
            for unit_id, u in units.items():
                n = results_by_unit[unit_id]["n"] if unit_id in results_by_unit else 0
                # I1 — accounting
                assert u["completions_so_far"] == n, (
                    f"{exp_id}/{unit_id}: completions {u['completions_so_far']} != rows {n}"
                )
                expect_completed = u["completions_so_far"] >= u["replication_target"]
                assert (u["status"] == "completed") == expect_completed, (
                    f"{exp_id}/{unit_id}: status {u['status']} vs "
                    f"{u['completions_so_far']}/{u['replication_target']}"
                )
                # I2 — consensus uniqueness, only on completed units
                c = results_by_unit[unit_id]["c"] or 0 if unit_id in results_by_unit else 0
                assert c <= 1, f"{exp_id}/{unit_id}: {c} consensus rows"
                if c == 1:
                    assert u["status"] == "completed"

    @invariant()
    def attestation_covers_consensus(self) -> None:
        # I7 (2026-06-12, from the signature-scope fix) — the served result-set
        # attestation must cover EXACTLY the consensus-with-receipt set
        # recomputed from the per-job DB. A narrower signed set was the 4th
        # integrity bug (receipt_index-sourced membership); this keeps the
        # recount continuously exercised rather than fixed-once.
        for exp_id in self.exps:
            if self._db_status(exp_id) != "completed":
                continue
            r = self.w.client.get(
                f"/api/v0/experiments/{exp_id}/attestation",
                headers=self.w.maintainer_headers,
            )
            assert r.status_code != 409, (
                f"{exp_id}: attestation refused as incomplete_set: {r.text}"
            )
            if r.status_code != 200:
                continue
            expected = self.w.per_job_rows(
                exp_id,
                "SELECT COUNT(*) AS n FROM results r "
                "WHERE r.is_consensus = 1 AND r.semantic_hash IS NOT NULL "
                "  AND EXISTS (SELECT 1 FROM receipts rc "
                "              WHERE rc.work_unit_ids_json LIKE '%\"' || r.unit_id || '\"%')",
            )[0]["n"]
            assert r.json()["unit_count"] == expected, (
                f"{exp_id}: attestation unit_count {r.json()['unit_count']} != "
                f"consensus-with-receipt count {expected}"
            )

    @invariant()
    def completed_consensus_is_frozen(self) -> None:
        # I5 — once completed, the consensus set never changes.
        for exp_id, e in self.exps.items():
            if self._db_status(exp_id) != "completed":
                continue
            current = {
                (r["unit_id"], r["semantic_hash"])
                for r in self.w.per_job_rows(
                    exp_id,
                    "SELECT unit_id, semantic_hash FROM results WHERE is_consensus = 1",
                )
            }
            if e["consensus_snapshot"] is None:
                e["consensus_snapshot"] = current
                e["status"] = "completed"
            else:
                assert current == e["consensus_snapshot"], (
                    f"{exp_id}: consensus set changed after completion"
                )


# Depth profiles: "ci" (default) fits inside the normal suite; "nightly" is
# the deep exploration (16x the state space) the systemd timer runs with
# AUSPEXAI_PROPERTY_PROFILE=nightly + AUSPEXAI_PROPERTY_SOAK=1 (+ pytest
# -o timeout=0 — the global 60s per-test cap would kill it). Hypothesis
# persists shrunk failing examples in .hypothesis/ across runs.
settings.register_profile(
    "ci",
    max_examples=50,
    stateful_step_count=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile(
    "nightly",
    max_examples=200,
    stateful_step_count=200,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
ResultAcceptanceMachine.TestCase.settings = settings.get_profile(
    os.environ.get("AUSPEXAI_PROPERTY_PROFILE", "ci")
)
TestResultAcceptanceProperties = ResultAcceptanceMachine.TestCase


# ---- targeted: the legacy-ambiguous case the machine deliberately avoids ----


def test_legacy_submit_with_ambiguous_unit_lands_in_exactly_one_active_experiment():
    """Pre-v0.2.2 worker, same (unit_id, worker) open in TWO active experiments:
    the coordinator may pick either, but the result must land in EXACTLY ONE
    active experiment — never both, never an aborted one. (The D6 bug was the
    aborted-experiment variant; v0.1.24 added the terminal skip.)"""
    w = World()
    try:
        exp_a, hash_a = w.create_approved_experiment("amb-a", replication_factor=3)
        exp_b, hash_b = w.create_approved_experiment("amb-b", replication_factor=3)
        worker = w.enroll_worker()
        for exp_id, label, h in ((exp_a, "amb-a", hash_a), (exp_b, "amb-b", hash_b)):
            r = w.researcher(
                "POST",
                f"/api/v0/experiments/{exp_id}/work-units",
                json_body={
                    "work_units": [
                        {
                            "schema_version": "0.1",
                            "unit_id": "u-shared",
                            "tenant_id": "prop-tenant",
                            "experiment_id": label,
                            "manifest_sha256": h,
                            "created_at": "2026-06-11T00:00:00Z",
                            "payload": {"q": 1},
                            "replication_target": 1,
                        }
                    ]
                },
            )
            assert r.status_code == 201, r.text
        # the worker acquires BOTH assignments (scheduler offers each once)
        picks = []
        for _ in range(4):
            r = w.signed(
                "GET",
                f"/api/v0/workers/{worker['id']}/assignments",
                privkey=worker["priv"],
                pubkey_hex=worker["pub"],
            )
            body = r.json()
            if body.get("work_unit"):
                picks.append(body)
            if len(picks) == 2:
                break
        assert len(picks) == 2, f"expected both assignments offered, got {len(picks)}"
        # legacy submit: NO assignment_id on the wire
        r = w.signed(
            "POST",
            f"/api/v0/workers/{worker['id']}/assignments/u-shared/result",
            privkey=worker["priv"],
            pubkey_hex=worker["pub"],
            json_body={
                "unit_id": "u-shared",
                "worker_pubkey": worker["pub"],
                "completed_at": "2026-06-11T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"answer": 1},
                "worker_signature": sign_result_body(
                    worker["priv"],
                    worker["pub"],
                    unit_id="u-shared",
                    completed_at="2026-06-11T12:00:00+00:00",
                    exit_code=0,
                    payload={"answer": 1},
                ),
            },
        )
        assert r.status_code == 201, r.text
        rows_a = w.per_job_rows(exp_a, "SELECT COUNT(*) AS n FROM results")[0]["n"]
        rows_b = w.per_job_rows(exp_b, "SELECT COUNT(*) AS n FROM results")[0]["n"]
        assert rows_a + rows_b == 1, (
            f"legacy ambiguous submit landed in {rows_a + rows_b} experiments"
        )
    finally:
        w.close()
