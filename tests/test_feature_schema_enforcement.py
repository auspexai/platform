"""Integration tests for D16.1 feature_schema enforcement through the routes.

Covers Inc 2 (submit-time validation + the certified-requires-schema gate) and
Inc 4 (result-ingest §7 structural enforcement): certified ⇒ reject + record +
surface on E14; BYOT ⇒ flag + accept.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from tests._result_helpers import sign_result_body

AUTHORITY = "testserver"

# A valid 2-feature schema whose declared shape matches the result payloads below.
SCHEMA = {
    "out": {
        "meaning": "the doubled output",
        "kind": "count",
        "role": "summary",
        "range": {"min": 0},
        "change_means": "the computed value changed",
    },
    "tag": {
        "meaning": "a fixed label",
        "kind": "categorical",
        "role": "key",
        "categories": ["ok"],
        "change_means": "a different label",
    },
}


def _ed25519() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _signed(client, *, method, path, privkey, pubkey_hex, json_body=None):
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


def _enroll_worker(client: TestClient):
    priv, pub = _ed25519()
    r = client.post(
        "/api/v0/workers/enroll",
        json={"pubkey_hex": pub, "capabilities": {"os": "linux"}},
    )
    assert r.status_code == 201, r.text
    return priv, pub, r.json()["worker_id"]


def _register_tenant(client, maintainer_headers, tenant_id="byot-tenant"):
    priv, pub = _ed25519()
    r = client.post(
        "/api/v0/tenants",
        headers=maintainer_headers,
        json={"tenant_id": tenant_id, "maintainer_pubkey": pub},
    )
    assert r.status_code == 201, r.text
    return priv, pub


def _submit_manifest(client, priv, pub, manifest: dict[str, Any]):
    return _signed(
        client,
        method="POST",
        path="/api/v0/experiments",
        privkey=priv,
        pubkey_hex=pub,
        json_body={"manifest": manifest, "signature": {}},
    )


# ── Inc 2: submit-time validation ────────────────────────────────────────────


def test_submit_rejects_malformed_feature_schema(client: TestClient, maintainer_token: str) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    r = _submit_manifest(
        client,
        priv,
        pub,
        {
            "tenant_id": "byot-tenant",
            "experiment_id": "bad-schema",
            "schema_version": "0.3",
            "replication_factor": 1,
            # free-text kind is not §7-safe
            "feature_schema": {
                "x": {"meaning": "m", "kind": "text", "role": "summary", "change_means": "c"}
            },
        },
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error"]["code"] == "feature_schema_invalid"


def test_submit_rejects_feature_schema_without_v0_3(
    client: TestClient, maintainer_token: str
) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    r = _submit_manifest(
        client,
        priv,
        pub,
        {
            "tenant_id": "byot-tenant",
            "experiment_id": "wrong-version",
            "schema_version": "0.2",  # declares feature_schema but not v0.3
            "replication_factor": 1,
            "feature_schema": SCHEMA,
        },
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error"]["code"] == "feature_schema_requires_v0_3"


def test_submit_accepts_valid_v0_3_byot(client: TestClient, maintainer_token: str) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    r = _submit_manifest(
        client,
        priv,
        pub,
        {
            "tenant_id": "byot-tenant",
            "experiment_id": "good-schema",
            "schema_version": "0.3",
            "replication_factor": 1,
            "feature_schema": SCHEMA,
        },
    )
    assert r.status_code == 201, r.text


# ── Inc 4: result-ingest §7 enforcement ──────────────────────────────────────


def _approve_with_unit(client, mh, priv, pub, exp_label, unit_id):
    """Submit a v0.3 manifest (with SCHEMA), approve it, add one work unit.
    Returns the coordinator experiment_id."""
    submit = _submit_manifest(
        client,
        priv,
        pub,
        {
            "tenant_id": "byot-tenant",
            "experiment_id": exp_label,
            "schema_version": "0.3",
            "replication_factor": 1,
            "feature_schema": SCHEMA,
        },
    ).json()
    exp_id = submit["experiment_id"]
    manifest_hash = submit["manifest_hash"]
    assert (
        client.post(f"/api/v0/experiments/{exp_id}/actions/approve", headers=mh).status_code == 200
    )
    r = _signed(
        client,
        method="POST",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=priv,
        pubkey_hex=pub,
        json_body={
            "work_units": [
                {
                    "schema_version": "0.1",
                    "unit_id": unit_id,
                    "tenant_id": "byot-tenant",
                    "experiment_id": exp_label,
                    "manifest_sha256": manifest_hash,
                    "created_at": "2026-06-29T00:00:00Z",
                    "payload": {"input": 5},
                }
            ]
        },
    )
    assert r.status_code == 201, r.text
    return exp_id


def _submit_result(client, wid, wpriv, wpub, unit_id, payload):
    return _signed(
        client,
        method="POST",
        path=f"/api/v0/workers/{wid}/assignments/{unit_id}/result",
        privkey=wpriv,
        pubkey_hex=wpub,
        json_body={
            "unit_id": unit_id,
            "worker_pubkey": wpub,
            "completed_at": "2026-06-29T12:00:00+00:00",
            "exit_code": 0,
            "payload": payload,
            "worker_signature": sign_result_body(
                wpriv,
                wpub,
                unit_id=unit_id,
                completed_at="2026-06-29T12:00:00+00:00",
                exit_code=0,
                payload=payload,
            ),
        },
    )


def test_conforming_result_accepted(client: TestClient, maintainer_token: str) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    _approve_with_unit(client, mh, priv, pub, "conform", "u-ok")
    wpriv, wpub, wid = _enroll_worker(client)
    _signed(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid}/assignments",
        privkey=wpriv,
        pubkey_hex=wpub,
    )
    r = _submit_result(client, wid, wpriv, wpub, "u-ok", {"out": 10, "tag": "ok"})
    assert r.status_code == 201, r.text


def test_byot_violation_flagged_and_accepted(
    client: TestClient, maintainer_token: str, receipt_index_repository
) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    exp_id = _approve_with_unit(client, mh, priv, pub, "byot-flag", "u-flag")
    wpriv, wpub, wid = _enroll_worker(client)
    _signed(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid}/assignments",
        privkey=wpriv,
        pubkey_hex=wpub,
    )
    # 'leak' is undeclared (§7); BYOT ⇒ recorded but ACCEPTED.
    r = _submit_result(
        client, wid, wpriv, wpub, "u-flag", {"out": 10, "tag": "ok", "leak": "raw text"}
    )
    assert r.status_code == 201, r.text

    rej = receipt_index_repository.list_schema_rejections_for_experiment(exp_id)
    assert len(rej) == 1
    assert rej[0]["certified"] is False
    assert any("leak" in v for v in rej[0]["violations"])
    # BYOT flags do NOT raise a maintainer alert.
    assert receipt_index_repository.certified_schema_rejection_counts().get(exp_id) is None


def test_certified_violation_rejected_unit_failed_and_alerted(
    client: TestClient,
    maintainer_token: str,
    experiment_repository,
    receipt_index_repository,
) -> None:
    mh = {"Authorization": f"Bearer {maintainer_token}"}
    priv, pub = _register_tenant(client, mh)
    exp_id = _approve_with_unit(client, mh, priv, pub, "cert-reject", "u-rej")
    # Promote to certified (a real cert would set this at submit; here we flip the
    # persisted flag to exercise the ingest reject path without a full profile).
    experiment_repository.set_certified(exp_id, True)

    wpriv, wpub, wid = _enroll_worker(client)
    _signed(
        client,
        method="GET",
        path=f"/api/v0/workers/{wid}/assignments",
        privkey=wpriv,
        pubkey_hex=wpub,
    )
    r = _submit_result(
        client, wid, wpriv, wpub, "u-rej", {"out": -5, "tag": "ok"}
    )  # out < range.min
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error"]["code"] == "schema_violation"

    # The unit is TERMINAL (failed), not re-offered.
    state = _signed(
        client,
        method="GET",
        path=f"/api/v0/experiments/{exp_id}/work-units",
        privkey=priv,
        pubkey_hex=pub,
    ).json()
    assert state["counts_by_status"].get("failed") == 1

    # Recorded as a CERTIFIED rejection and surfaced on the maintainer alert.
    rej = receipt_index_repository.list_schema_rejections_for_experiment(exp_id)
    assert len(rej) == 1 and rej[0]["certified"] is True
    assert receipt_index_repository.certified_schema_rejection_counts().get(exp_id) == 1

    attention = client.get("/api/v0/maintainer/experiments/attention", headers=mh)
    assert attention.status_code == 200, attention.text
    reasons = [x["reason"] for x in attention.json()["experiments"] if x["experiment_id"] == exp_id]
    assert any("feature_schema violations" in r for r in reasons)
