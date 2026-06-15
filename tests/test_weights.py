"""§9 #13b / v0_2 M3 — served-weights digest verdict (the pure enforcement)."""

from __future__ import annotations

import json

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.weights import served_weights_verdict
from tests._result_helpers import sign_result_body


def _manifest(*models):
    return {"models": list(models)}


def test_no_pin_is_ok():
    m = _manifest({"id": "gemma", "version": "1.0"})  # no expected_gguf_sha256
    assert served_weights_verdict(m, {"gemma": "a" * 64}) is None
    assert served_weights_verdict(m, None) is None  # nothing to check


def test_match_is_ok():
    m = _manifest({"id": "gemma", "expected_gguf_sha256": "a" * 64})
    assert served_weights_verdict(m, {"gemma": "a" * 64}) is None


def test_mismatch_is_rejected():
    m = _manifest({"id": "gemma", "expected_gguf_sha256": "a" * 64})
    v = served_weights_verdict(m, {"gemma": "b" * 64})
    assert v is not None and "!=" in v


def test_pinned_but_no_served_digest_is_rejected():
    """Fail-closed: a pinned model with no reported served digest can't prove the
    declared model ran."""
    m = _manifest({"id": "gemma", "expected_gguf_sha256": "a" * 64})
    assert served_weights_verdict(m, None) is not None
    assert served_weights_verdict(m, {"other-model": "a" * 64}) is not None


def test_multi_model_all_pinned_must_match():
    m = _manifest(
        {"id": "a", "expected_gguf_sha256": "1" * 64},
        {"id": "b", "expected_gguf_sha256": "2" * 64},
    )
    assert served_weights_verdict(m, {"a": "1" * 64, "b": "2" * 64}) is None
    assert served_weights_verdict(m, {"a": "1" * 64, "b": "9" * 64}) is not None


def test_mixed_only_pinned_models_checked():
    m = _manifest(
        {"id": "pinned", "expected_gguf_sha256": "1" * 64},
        {"id": "loose", "version": "1.0"},  # not pinned → ignored
    )
    assert served_weights_verdict(m, {"pinned": "1" * 64}) is None


# ── integration: the 409 reject in submit_result ────────────────────────────

_AUTH = "testserver"


def _sget(client, *, privkey, pubkey_hex, path):
    return client.get(
        path,
        headers=sign_request(
            privkey=privkey,
            pubkey_hex=pubkey_hex,
            method="GET",
            path=path,
            authority=_AUTH,
            body=b"",
        ),
    )


def _spost(client, *, privkey, pubkey_hex, path, payload):
    body = json.dumps(payload).encode()
    h = sign_request(
        privkey=privkey, pubkey_hex=pubkey_hex, method="POST", path=path, authority=_AUTH, body=body
    )
    h["Content-Type"] = "application/json"
    return client.post(path, headers=h, content=body)


def _result(privkey, unit_id, pubkey_hex, *, schema_version=None, served_weights=None):
    """A signed result body. v0 by default (heartbeat-enforced #13b); pass
    schema_version=1 + served_weights for the worker-attested (v1) path."""
    completed_at = "2026-06-14T12:00:00+00:00"
    payload = {"out": 1}
    body = {
        "unit_id": unit_id,
        "worker_pubkey": pubkey_hex,
        "completed_at": completed_at,
        "exit_code": 0,
        "payload": payload,
        "worker_signature": sign_result_body(
            privkey,
            pubkey_hex,
            unit_id=unit_id,
            completed_at=completed_at,
            exit_code=0,
            payload=payload,
            schema_version=schema_version,
            served_weights=served_weights,
        ),
    }
    if schema_version and schema_version >= 1:
        body["schema_version"] = schema_version
        body["served_weights"] = served_weights or {}
    return body


def _pinning_experiment(manifest_repository, experiment_repository, tenant_id, expected):
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={
            "tenant_id": tenant_id,
            "experiment_id": "exp-pin",
            "models": [
                {
                    "id": "gemma",
                    "version": "1.0",
                    "local_weights_required": True,
                    "expected_gguf_sha256": expected,
                }
            ],
        },
        signature_json={},
    )
    exp = experiment_repository.create(
        tenant_id=tenant_id, tenant_experiment_label="exp-pin", manifest_hash=manifest.manifest_hash
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    return exp


def test_submit_result_409_on_served_weights_mismatch(
    client,
    enrolled_worker,
    worker_repository,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    registered_tenant,
):
    privkey, worker = enrolled_worker
    _, binding = registered_tenant
    exp = _pinning_experiment(
        manifest_repository, experiment_repository, binding.tenant_id, "a" * 64
    )
    WorkUnitRepository(per_job_factory.get_or_create(exp.experiment_id)).submit_batch(
        [{"unit_id": "pu1", "payload": {"input": 1}}]
    )
    # the worker serves a DIFFERENT digest than the manifest pins
    worker_repository.record_heartbeat(
        worker.worker_id, capabilities={"os": "linux", "served_model_digests": {"gemma": "b" * 64}}
    )
    wid = worker.worker_id
    pick = _sget(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    r = _spost(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        payload=_result(privkey, unit_id, worker.pubkey_hex),
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"]["code"] == "served_weights_mismatch"


def test_submit_result_ok_when_served_digest_matches(
    client,
    enrolled_worker,
    worker_repository,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    registered_tenant,
):
    privkey, worker = enrolled_worker
    _, binding = registered_tenant
    exp = _pinning_experiment(
        manifest_repository, experiment_repository, binding.tenant_id, "a" * 64
    )
    WorkUnitRepository(per_job_factory.get_or_create(exp.experiment_id)).submit_batch(
        [{"unit_id": "pu1", "payload": {"input": 1}}]
    )
    worker_repository.record_heartbeat(
        worker.worker_id, capabilities={"os": "linux", "served_model_digests": {"gemma": "a" * 64}}
    )
    wid = worker.worker_id
    pick = _sget(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    r = _spost(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        payload=_result(privkey, unit_id, worker.pubkey_hex),
    )
    assert r.status_code == 201, r.text  # matching digest → accepted into consensus


def test_submit_v1_signed_mismatch_rejected_even_when_heartbeat_matches(
    client,
    enrolled_worker,
    worker_repository,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    registered_tenant,
):
    """§9 #13a anti-fab: the WORKER-SIGNED served_weights is authoritative. A
    worker can't dodge #13b by lying in its (unsigned) heartbeat — here the
    heartbeat reports the matching digest but the signed v1 body reports a
    different one, and the coordinator rejects on the signed value."""
    privkey, worker = enrolled_worker
    _, binding = registered_tenant
    exp = _pinning_experiment(
        manifest_repository, experiment_repository, binding.tenant_id, "a" * 64
    )
    WorkUnitRepository(per_job_factory.get_or_create(exp.experiment_id)).submit_batch(
        [{"unit_id": "pu1", "payload": {"input": 1}}]
    )
    # Heartbeat MATCHES (the spoofable channel) ...
    worker_repository.record_heartbeat(
        worker.worker_id, capabilities={"os": "linux", "served_model_digests": {"gemma": "a" * 64}}
    )
    wid = worker.worker_id
    unit_id = _sget(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()["work_unit"]["unit_id"]
    r = _spost(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        # ... but the SIGNED served_weights does NOT.
        payload=_result(
            privkey,
            unit_id,
            worker.pubkey_hex,
            schema_version=1,
            served_weights={"gemma": "b" * 64},
        ),
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"]["code"] == "served_weights_mismatch"


def test_submit_v1_signed_match_accepted(
    client,
    enrolled_worker,
    worker_repository,
    manifest_repository,
    experiment_repository,
    per_job_factory,
    registered_tenant,
):
    """The signed v1 served_weights matching the manifest is accepted — even
    with no heartbeat digest at all (the attested value stands on its own)."""
    privkey, worker = enrolled_worker
    _, binding = registered_tenant
    exp = _pinning_experiment(
        manifest_repository, experiment_repository, binding.tenant_id, "a" * 64
    )
    WorkUnitRepository(per_job_factory.get_or_create(exp.experiment_id)).submit_batch(
        [{"unit_id": "pu1", "payload": {"input": 1}}]
    )
    worker_repository.record_heartbeat(worker.worker_id, capabilities={"os": "linux"})
    wid = worker.worker_id
    unit_id = _sget(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments",
    ).json()["work_unit"]["unit_id"]
    r = _spost(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        payload=_result(
            privkey,
            unit_id,
            worker.pubkey_hex,
            schema_version=1,
            served_weights={"gemma": "a" * 64},
        ),
    )
    assert r.status_code == 201, r.text
