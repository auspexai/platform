"""End-to-end integration tests — full coordinator flow exercised via routes only.

Unlike the per-milestone route tests (test_experiments_route.py,
test_workers_route.py, test_work_units_route.py, test_assignments_route.py,
test_experiment_lifecycle_m6e.py) which each exercise one resource, these
tests walk the entire researcher → maintainer → worker loop through the
HTTP API and verify:
  - Status transitions land correctly at every step
  - The audit_log accumulates a coherent trace
  - Auto-complete fires at the right moment

M6f is the "do all the pieces compose?" verification step. If a future
refactor breaks the loop, these tests fail loudly.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request

AUTHORITY = "testserver"


# ---- request helpers ------------------------------------------------------


def _signed_request(
    client: TestClient,
    *,
    method: str,
    path: str,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    json_body: dict[str, Any] | None = None,
):
    body = json.dumps(json_body).encode() if json_body is not None else b""
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method=method,
        path=path,
        authority=AUTHORITY,
        body=body,
    )
    if body:
        headers["Content-Type"] = "application/json"
    if method == "GET":
        return client.get(path, headers=headers)
    return client.request(method, path, headers=headers, content=body)


def _ed25519() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    return priv, pub


# ---- helper: a fresh worker that's enrolled & resolves via credential ----


def _enroll_worker(client: TestClient, capabilities: dict[str, Any] | None = None):
    """Returns (priv, pubkey_hex, worker_id) for a freshly enrolled worker."""
    priv, pub = _ed25519()
    response = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": pub, "capabilities": capabilities or {"os": "linux"}},
    )
    assert response.status_code == 201, response.text
    return priv, pub, response.json()["worker_id"]


# ---- the canonical happy-path -------------------------------------------


def test_full_flow_researcher_to_auto_complete(
    client: TestClient,
    maintainer_token: str,
    audit_repository,
) -> None:
    """Drives the entire coordinator loop through HTTP routes and asserts
    the audit log captures each step with the right actor class.

    Sequence:
      1. Maintainer registers a tenant (with researcher pubkey).
      2. Researcher submits an experiment (signed request, opaque manifest).
      3. Maintainer approves the experiment.
      4. Researcher submits one work unit.
      5. Researcher finalizes submissions.
      6. Three workers each enroll, fetch the unit, and submit a result.
      7. Third result completes the unit → all units done + finalized →
         auto-complete fires → experiment status = completed,
         last_action_by_class = system.

    Assertions verify both the route responses AND the audit_log trail.
    """
    maintainer_headers = {"Authorization": f"Bearer {maintainer_token}"}

    # ---- step 1: register tenant ----
    researcher_priv, researcher_pub = _ed25519()
    response = client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={
            "tenant_id": "synth-doubler",
            "maintainer_pubkey": researcher_pub,
            "display_name": "Synthetic Doubler",
        },
    )
    assert response.status_code == 201, response.text

    # ---- step 2: submit experiment ----
    response = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "manifest": {
                "tenant_id": "synth-doubler",
                "experiment_id": "doubler-001",
                "executor": "python -m examples.doubler",
            },
            "signature": {"alg": "ed25519", "sig": "fake-sig-opaque-to-v0"},
        },
    )
    assert response.status_code == 201, response.text
    experiment_body = response.json()
    coordinator_exp_id = experiment_body["experiment_id"]
    assert experiment_body["status"] == "submitted"
    manifest_hash = experiment_body["manifest_hash"]

    # ---- step 3: maintainer approves ----
    response = client.post(
        f"/api/v0/experiments/{coordinator_exp_id}/actions/approve",
        headers=maintainer_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert response.json()["last_action_by_class"] == "maintainer"

    # ---- step 4: submit one work unit ----
    response = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{coordinator_exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-double-5",
                    "tenant_id": "synth-doubler",
                    "experiment_id": "doubler-001",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 5},
                }
            ]
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["count"] == 1

    # ---- step 5: finalize submissions ----
    response = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{coordinator_exp_id}/actions/finalize-submissions",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    assert response.status_code == 200, response.text
    assert response.json()["submissions_finalized"] is True

    # ---- step 6: three workers complete the unit ----
    completed_results: list[dict[str, Any]] = []
    for _ in range(3):
        wp, wpub, wid = _enroll_worker(client)
        # Worker fetches assignment.
        pick = _signed_request(
            client,
            method="GET",
            path=f"/api/v0/workers/{wid}/assignments",
            privkey=wp,
            pubkey_hex=wpub,
        ).json()
        assert pick["work_unit"]["unit_id"] == "u-double-5"
        assert pick["work_unit"]["payload"]["input"] == 5
        # Worker submits result.
        response = _signed_request(
            client,
            method="POST",
            path=f"/api/v0/workers/{wid}/assignments/u-double-5/result",
            privkey=wp,
            pubkey_hex=wpub,
            json_body={
                "unit_id": "u-double-5",
                "worker_pubkey": wpub,
                "completed_at": "2026-05-19T12:00:00+00:00",
                "exit_code": 0,
                "payload": {"output": 10},
                "worker_signature": "ZmFrZS1zaWc=",
            },
        )
        assert response.status_code == 201, response.text
        completed_results.append(response.json())

    # Last result should have completed the unit AND triggered auto-complete.
    assert completed_results[-1]["unit_status_after"] == "completed"
    assert completed_results[-1]["completions_so_far"] == 3
    assert completed_results[-1]["replication_target"] == 3

    # ---- step 7: experiment is auto-completed ----
    response = client.get(
        f"/api/v0/experiments/{coordinator_exp_id}",
        headers=maintainer_headers,
    )
    assert response.status_code == 200
    final = response.json()
    assert final["status"] == "completed"
    assert final["last_action_by_class"] == "system"

    # ---- audit-log trace verification ----
    entries = audit_repository.latest(limit=100)
    # The latest() returns DESC by id; reverse for forward reading.
    actions_in_order = [e.action for e in reversed(entries)]
    expected_subsequence = [
        "tenant.register",
        "experiment.submit",
        "experiment.approve",
        "work_units.submit_batch",
        "experiment.finalize_submissions",
        # The three (enroll, assign, result) triples interleave per worker:
        "worker.enroll",
        "assignment.create",
        "result.submit",
        "worker.enroll",
        "assignment.create",
        "result.submit",
        "worker.enroll",
        "assignment.create",
        "result.submit",
        # M7c: on the third result, the unit transitions to completed and
        # the hash_agreement reducer issues receipts.
        "receipts.issue.agreed",
        "experiment.auto_complete",
    ]
    assert actions_in_order == expected_subsequence, (
        f"audit trace mismatch:\n  expected: {expected_subsequence}\n  got:      {actions_in_order}"
    )

    # ---- M7c: verify receipts were issued ----
    from auspexai_platform.receipts import (
        HASH_AGREEMENT_METHOD,
        ReceiptRepository,
        cose_sign1_decode,
        decode_cbor,
    )

    per_job_db = client.app.state.per_job_factory.get(coordinator_exp_id)
    assert per_job_db is not None
    receipts = ReceiptRepository(per_job_db).list_all()
    assert len(receipts) == 3, f"expected 3 receipts (one per agreeing worker), got {len(receipts)}"
    signing_key = client.app.state.receipt_signing_key
    seen_pubkeys = set()
    for record in receipts:
        assert record.signing_key_pubkey_hex == signing_key.pubkey_hex
        payload, kid = cose_sign1_decode(
            record.cose_signed_blob, expected_pubkey=signing_key.public_key
        )
        assert kid == signing_key.pubkey_hex
        receipt = decode_cbor(payload)
        assert receipt.quorum_agreement.method == HASH_AGREEMENT_METHOD
        assert receipt.quorum_agreement.agreeing_workers == 3
        assert receipt.quorum_agreement.replication_factor == 3
        seen_pubkeys.add(receipt.worker_pubkey.hex())
    # Three distinct workers contributed — three distinct pubkeys in receipts.
    assert len(seen_pubkeys) == 3

    # Verify actor_class attribution on key entries.
    by_action = {e.action: e for e in entries}
    assert by_action["tenant.register"].actor_class.value == "maintainer"
    assert by_action["experiment.submit"].actor_class.value == "researcher"
    assert by_action["experiment.submit"].actor_tenant_id == "synth-doubler"
    assert by_action["experiment.approve"].actor_class.value == "maintainer"
    assert by_action["experiment.finalize_submissions"].actor_class.value == "researcher"
    assert by_action["experiment.auto_complete"].actor_class.value == "system"
    assert by_action["experiment.auto_complete"].actor_identifier is None


# ---- pause/resume mid-flow ---------------------------------------------


def test_pause_mid_flow_stops_new_assignments_but_accepts_in_flight(
    client: TestClient,
    maintainer_token: str,
) -> None:
    """Two units submitted; one worker grabs assignment 1; researcher pauses;
    a second worker grabbing an assignment gets nothing; the first worker can
    still submit a result; resume restores scheduling."""
    maintainer_headers = {"Authorization": f"Bearer {maintainer_token}"}

    # Setup: tenant + experiment + 2 work units + approval.
    researcher_priv, researcher_pub = _ed25519()
    client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={"tenant_id": "synth", "maintainer_pubkey": researcher_pub},
    )
    submit = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "manifest": {"tenant_id": "synth", "experiment_id": "exp-1"},
            "signature": {},
        },
    ).json()
    exp_id = submit["experiment_id"]
    manifest_hash = submit["manifest_hash"]
    client.post(
        f"/api/v0/experiments/{exp_id}/actions/approve",
        headers=maintainer_headers,
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u1",
                    "tenant_id": "synth",
                    "experiment_id": "exp-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 1},
                },
                {
                    "schema_version": "0.1",
                    "unit_id": "u2",
                    "tenant_id": "synth",
                    "experiment_id": "exp-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {"input": 2},
                },
            ]
        },
    )

    # Worker A grabs an assignment.
    wa_priv, wa_pub, wa_id = _enroll_worker(client)
    a_pick = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wa_id}/assignments",
        privkey=wa_priv,
        pubkey_hex=wa_pub,
    ).json()
    a_unit_id = a_pick["work_unit"]["unit_id"]
    assert a_unit_id in {"u1", "u2"}

    # Researcher pauses (own-tenant action).
    pause_response = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/pause",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    assert pause_response.status_code == 200
    assert pause_response.json()["status"] == "paused"
    assert pause_response.json()["last_action_by_class"] == "researcher"

    # Worker B enrolls and asks for work → nothing (paused).
    wb_priv, wb_pub, wb_id = _enroll_worker(client)
    b_pick = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wb_id}/assignments",
        privkey=wb_priv,
        pubkey_hex=wb_pub,
    ).json()
    assert b_pick["work_unit"] is None

    # Worker A submits their in-flight result — still accepted.
    submit_response = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/workers/{wa_id}/assignments/{a_unit_id}/result",
        privkey=wa_priv,
        pubkey_hex=wa_pub,
        json_body={
            "unit_id": a_unit_id,
            "worker_pubkey": wa_pub,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {"out": 1},
            "worker_signature": "Zm9v",
        },
    )
    assert submit_response.status_code == 201, submit_response.text

    # Maintainer resumes.
    resume_response = client.post(
        f"/api/v0/experiments/{exp_id}/actions/resume",
        headers=maintainer_headers,
    )
    assert resume_response.status_code == 200
    assert resume_response.json()["status"] == "approved"
    assert resume_response.json()["last_action_by_class"] == "maintainer"

    # Worker B asks again → now gets something.
    b_pick_again = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wb_id}/assignments",
        privkey=wb_priv,
        pubkey_hex=wb_pub,
    ).json()
    assert b_pick_again["work_unit"] is not None


# ---- abort mid-flow ----------------------------------------------------


def test_abort_mid_flow_records_attribution(
    client: TestClient,
    maintainer_token: str,
    audit_repository,
) -> None:
    """Researcher aborts their own experiment after work has been assigned.
    Verify the abort is recorded with actor_class=researcher and the
    experiment lands in 'aborted' status."""
    maintainer_headers = {"Authorization": f"Bearer {maintainer_token}"}

    researcher_priv, researcher_pub = _ed25519()
    client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={"tenant_id": "synth", "maintainer_pubkey": researcher_pub},
    )
    submit = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "manifest": {"tenant_id": "synth", "experiment_id": "doomed"},
            "signature": {},
        },
    ).json()
    exp_id = submit["experiment_id"]
    client.post(
        f"/api/v0/experiments/{exp_id}/actions/approve",
        headers=maintainer_headers,
    )

    # Researcher aborts.
    abort_response = _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/abort",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    assert abort_response.status_code == 200, abort_response.text
    body = abort_response.json()
    assert body["status"] == "aborted"
    assert body["last_action_by_class"] == "researcher"

    # Audit log shows researcher-attributed abort.
    entries = audit_repository.latest(limit=20)
    abort_entries = [e for e in entries if e.action == "experiment.abort"]
    assert len(abort_entries) == 1
    assert abort_entries[0].actor_class.value == "researcher"
    assert abort_entries[0].actor_tenant_id == "synth"


# ---- audit-coverage sanity check ---------------------------------------


def test_every_state_changing_action_in_full_flow_writes_audit(
    client: TestClient,
    maintainer_token: str,
    audit_repository,
) -> None:
    """Sanity check: after running through the canonical happy path, every
    audit `action` we expect to see is present. Guards against accidental
    deletion of audit_repository.append() calls in future refactors."""
    maintainer_headers = {"Authorization": f"Bearer {maintainer_token}"}

    # Minimal flow to exercise each action type.
    researcher_priv, researcher_pub = _ed25519()
    client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={"tenant_id": "tcoverage", "maintainer_pubkey": researcher_pub},
    )
    submit = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "manifest": {"tenant_id": "tcoverage", "experiment_id": "cov-1"},
            "signature": {},
        },
    ).json()
    exp_id = submit["experiment_id"]
    manifest_hash = submit["manifest_hash"]

    client.post(
        f"/api/v0/experiments/{exp_id}/actions/approve",
        headers=maintainer_headers,
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "uc",
                    "tenant_id": "tcoverage",
                    "experiment_id": "cov-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {},
                }
            ]
        },
    )

    # OAuth exchange — needs an access token registered in the FakeIdentityVerifier
    # via the fixture-level dependency injection.
    # Skip the OAuth path here — covered separately in test_accounts_route.py.

    # Worker enroll + upgrade + retire — skip upgrade here (separate test),
    # exercise enroll + retire.
    wpriv, wpub, wid = _enroll_worker(client)
    # Worker grabs assignment (creates assignment.create entry).
    _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid}/assignments",
        privkey=wpriv,
        pubkey_hex=wpub,
    )
    # Submit a result.
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/workers/{wid}/assignments/uc/result",
        privkey=wpriv,
        pubkey_hex=wpub,
        json_body={
            "unit_id": "uc",
            "worker_pubkey": wpub,
            "completed_at": "2026-05-19T12:00:00+00:00",
            "exit_code": 0,
            "payload": {},
            "worker_signature": "Zm9v",
        },
    )
    # Pause + resume + finalize.
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/pause",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/resume",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/actions/finalize-submissions",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    )
    # Retire the worker.
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/workers/{wid}/actions/retire",
        privkey=wpriv,
        pubkey_hex=wpub,
    )

    # Walk all action types that exist in the codebase. Excluded from this
    # check: account.oauth_exchange (not exercised — separate test),
    # worker.upgrade (separate test), experiment.archive (separate test),
    # experiment.auto_complete (would require replication_target=1 to fire
    # with one worker — covered in test_full_flow above).
    actions_seen = {e.action for e in audit_repository.latest(limit=200)}
    expected_present = {
        "tenant.register",
        "experiment.submit",
        "experiment.approve",
        "work_units.submit_batch",
        "worker.enroll",
        "assignment.create",
        "result.submit",
        "experiment.pause",
        "experiment.resume",
        "experiment.finalize_submissions",
        "worker.retire",
    }
    missing = expected_present - actions_seen
    assert not missing, f"audit log missing actions: {missing}"


# ---- read-side: GET work-units reflects in-flight state -----------------


def test_researcher_can_observe_unit_progress_via_list(
    client: TestClient,
    maintainer_token: str,
) -> None:
    """Researcher polls GET /experiments/{id}/work-units and sees status
    counts advance as workers complete the unit."""
    maintainer_headers = {"Authorization": f"Bearer {maintainer_token}"}
    researcher_priv, researcher_pub = _ed25519()
    client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={"tenant_id": "synth", "maintainer_pubkey": researcher_pub},
    )
    submit = _signed_request(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "manifest": {"tenant_id": "synth", "experiment_id": "exp-1"},
            "signature": {},
        },
    ).json()
    exp_id = submit["experiment_id"]
    manifest_hash = submit["manifest_hash"]
    client.post(
        f"/api/v0/experiments/{exp_id}/actions/approve",
        headers=maintainer_headers,
    )
    _signed_request(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": "u-prog",
                    "tenant_id": "synth",
                    "experiment_id": "exp-1",
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-05-19T00:00:00Z",
                    "payload": {},
                }
            ]
        },
    )

    # State 1: just submitted → pending=1.
    state = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    ).json()
    assert state["counts_by_status"] == {"pending": 1}

    # State 2: one worker grabs assignment → in_progress=1.
    wpriv, wpub, wid = _enroll_worker(client)
    _signed_request(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid}/assignments",
        privkey=wpriv,
        pubkey_hex=wpub,
    )
    state = _signed_request(
        client,
        method="GET",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=researcher_priv,
        pubkey_hex=researcher_pub,
    ).json()
    assert state["counts_by_status"] == {"in_progress": 1}
    assert state["work_units"][0]["status"] == "in_progress"
    assert state["work_units"][0]["completions_so_far"] == 0
