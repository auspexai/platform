"""End-to-end tests for /api/v0/experiments."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request


def _manifest(tenant_id: str, experiment_id: str, **extras) -> dict:
    return {
        "tenant_id": tenant_id,
        "experiment_id": experiment_id,
        "models": [],
        "replication_factor": 3,
        **extras,
    }


def _signature_blob(pubkey_hex: str) -> dict:
    return {
        "maintainer_pubkey_hex": pubkey_hex,
        "signature_b64": "dGVzdA==",
    }


def _submit_as_researcher(
    client: TestClient,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    manifest: dict,
):
    """Sign and POST /experiments. The HTTP signature covers the raw bytes
    of the JSON body, so we serialize once and pass both the bytes (signed)
    and the Content-Type so FastAPI parses them."""
    body = {"manifest": manifest, "signature": _signature_blob(pubkey_hex)}
    raw = json.dumps(body).encode("utf-8")
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path="/api/v0/experiments",
        authority="testserver",
        body=raw,
    )
    headers["Content-Type"] = "application/json"
    return client.post("/api/v0/experiments", headers=headers, content=raw)


# ---- POST /experiments — researcher only -----------------------------------


def test_submit_requires_researcher_credential(
    client: TestClient,
) -> None:
    """Anonymous POSTs should be 403, not 401 (auth resolved, authorization
    failed)."""
    response = client.post(
        "/api/v0/experiments",
        json={"manifest": {"tenant_id": "x", "experiment_id": "y"}, "signature": {}},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "researcher_required"


def test_submit_rejects_maintainer_credential(client: TestClient, maintainer_token: str) -> None:
    """Manifests are submitted by researchers, not operators."""
    response = client.post(
        "/api/v0/experiments",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={"manifest": {"tenant_id": "x", "experiment_id": "y"}, "signature": {}},
    )
    assert response.status_code == 403


def test_submit_creates_experiment(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(binding.tenant_id, "doubler-001"),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["experiment_id"].startswith("exp-")
    assert body["tenant_id"] == binding.tenant_id
    assert body["status"] == "submitted"
    # Researcher sees own tenant-scoped fields.
    assert body["tenant_experiment_label"] == "doubler-001"
    assert body["manifest_hash"]


def test_submit_derives_required_capabilities(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    # #30 (M1): models flagged local_weights_required become the experiment's
    # required_capabilities; non-required models do not.
    privkey, binding = registered_tenant
    manifest = _manifest(
        binding.tenant_id,
        "cap-exp",
        models=[
            {"id": "qwen3-q4", "version": "1", "local_weights_required": True},
            {"id": "noop", "version": "1", "local_weights_required": False},
        ],
    )
    r = _submit_as_researcher(client, privkey, binding.pubkey_hex, manifest)
    assert r.status_code == 201, r.text
    assert r.json()["required_capabilities"] == {"models": ["qwen3-q4"]}

    # No local_weights_required models → no requirement surfaced (backward-compat).
    r2 = _submit_as_researcher(
        client, privkey, binding.pubkey_hex, _manifest(binding.tenant_id, "open-exp")
    )
    assert r2.status_code == 201, r2.text
    assert not r2.json().get("required_capabilities")


def test_submit_rejects_manifest_for_other_tenant(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest("some-other-tenant", "x"),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "manifest_tenant_mismatch"


def test_submit_rejects_malformed_manifest(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        {"tenant_id": binding.tenant_id},  # missing experiment_id
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error"]["code"] == "manifest_malformed"


def test_submit_rejects_duplicate_label(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    # First submission OK.
    first = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(binding.tenant_id, "shared-label", v=1),
    )
    assert first.status_code == 201
    # Second with same label but different manifest content (so the manifest
    # itself isn't a duplicate). Should 409 on (tenant_id, label).
    second = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(binding.tenant_id, "shared-label", v=2),
    )
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "duplicate_experiment_label"


def test_submit_rejects_duplicate_manifest_content(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    manifest = _manifest(binding.tenant_id, "doubler-001")
    first = _submit_as_researcher(client, privkey, binding.pubkey_hex, manifest)
    assert first.status_code == 201
    second = _submit_as_researcher(client, privkey, binding.pubkey_hex, manifest)
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "duplicate_manifest"


def test_submit_writes_audit_log(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    privkey, binding = registered_tenant
    _submit_as_researcher(client, privkey, binding.pubkey_hex, _manifest(binding.tenant_id, "d-1"))
    audit_repo = client.app.state.audit_repository
    rows = audit_repo.latest(limit=1)
    assert rows[0].action == "experiment.submit"
    assert rows[0].actor_tenant_id == binding.tenant_id


# ---- GET /experiments — list -----------------------------------------------


@pytest.fixture
def submitted_experiment(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> tuple[Ed25519PrivateKey, object, str]:
    """Returns (privkey, binding, experiment_id) with one submitted experiment."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client, privkey, binding.pubkey_hex, _manifest(binding.tenant_id, "d-1")
    )
    assert response.status_code == 201, response.text
    return privkey, binding, response.json()["experiment_id"]


def test_list_anonymous_sees_nothing(client: TestClient, submitted_experiment) -> None:
    """Tenant-private (§3): an anonymous caller gets NO experiment rows — not
    field-filtered ones. The list endpoint must not leak the existence, count,
    or any field of experiments to non-owners."""
    response = client.get("/api/v0/experiments")
    assert response.status_code == 200
    assert response.json().get("experiments") in (None, [])


def test_list_maintainer_sees_everything(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    response = client.get(
        "/api/v0/experiments",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    item = response.json()["experiments"][0]
    assert item["tenant_experiment_label"]
    assert item["manifest_hash"]


def test_list_researcher_sees_own_tenant_full(client: TestClient, submitted_experiment) -> None:
    privkey, binding, _ = submitted_experiment
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path="/api/v0/experiments",
        authority="testserver",
        body=b"",
    )
    response = client.get("/api/v0/experiments", headers=sig_headers)
    assert response.status_code == 200, response.text
    item = response.json()["experiments"][0]
    assert item["tenant_experiment_label"]
    assert item["manifest_hash"]


# ---- tenant-private row scoping (R-D2-pre) ----------------------------------


def _list_as_researcher(client: TestClient, privkey, pubkey_hex: str) -> list[dict]:
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path="/api/v0/experiments",
        authority="testserver",
        body=b"",
    )
    response = client.get("/api/v0/experiments", headers=sig_headers)
    assert response.status_code == 200, response.text
    return response.json().get("experiments") or []


def _register_and_submit(
    client: TestClient, maintainer_token: str, tenant_id: str, label: str
) -> tuple[Ed25519PrivateKey, str, str]:
    """Register a fresh tenant and submit one experiment for it.
    Returns (privkey, pubkey_hex, experiment_id)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    reg = client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={"tenant_id": tenant_id, "maintainer_pubkey": pub},
    )
    assert reg.status_code in (200, 201), reg.text
    sub = _submit_as_researcher(client, priv, pub, _manifest(tenant_id, label))
    assert sub.status_code == 201, sub.text
    return priv, pub, sub.json()["experiment_id"]


class TestTenantPrivateScoping:
    """GET /experiments is tenant-private: a researcher sees only their own
    tenant's rows; cross-tenant detail returns 404 (no existence leak)."""

    def test_researcher_list_excludes_other_tenants(
        self, client: TestClient, submitted_experiment, maintainer_token: str
    ) -> None:
        a_priv, a_binding, a_exp_id = submitted_experiment  # tenant synth-doubler
        _b_priv, _b_pub, b_exp_id = _register_and_submit(
            client, maintainer_token, "tenant-b", "b-1"
        )
        a_ids = {
            e["experiment_id"] for e in _list_as_researcher(client, a_priv, a_binding.pubkey_hex)
        }
        assert a_ids == {a_exp_id}
        assert b_exp_id not in a_ids

    def test_each_researcher_sees_only_own(
        self, client: TestClient, submitted_experiment, maintainer_token: str
    ) -> None:
        _a_priv, _a_binding, a_exp_id = submitted_experiment
        b_priv, b_pub, b_exp_id = _register_and_submit(client, maintainer_token, "tenant-b", "b-1")
        b_ids = {e["experiment_id"] for e in _list_as_researcher(client, b_priv, b_pub)}
        assert b_ids == {b_exp_id}
        assert a_exp_id not in b_ids

    def test_researcher_cannot_get_other_tenant_detail(
        self, client: TestClient, submitted_experiment, maintainer_token: str
    ) -> None:
        _a_priv, _a_binding, a_exp_id = submitted_experiment
        b_priv, b_pub, _b_exp_id = _register_and_submit(client, maintainer_token, "tenant-b", "b-1")
        sig_headers = sign_request(
            privkey=b_priv,
            pubkey_hex=b_pub,
            method="GET",
            path=f"/api/v0/experiments/{a_exp_id}",
            authority="testserver",
            body=b"",
        )
        response = client.get(f"/api/v0/experiments/{a_exp_id}", headers=sig_headers)
        assert response.status_code == 404
        assert response.json()["detail"]["error"]["code"] == "experiment_not_found"

    def test_maintainer_list_sees_all_tenants(
        self, client: TestClient, submitted_experiment, maintainer_token: str
    ) -> None:
        _a_priv, _a_binding, a_exp_id = submitted_experiment
        _b_priv, _b_pub, b_exp_id = _register_and_submit(
            client, maintainer_token, "tenant-b", "b-1"
        )
        response = client.get(
            "/api/v0/experiments",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        ids = {e["experiment_id"] for e in response.json()["experiments"]}
        assert {a_exp_id, b_exp_id} <= ids


# ---- GET /experiments/{id} — detail ----------------------------------------


def test_get_experiment_404_when_absent(client: TestClient) -> None:
    response = client.get("/api/v0/experiments/exp-missing")
    assert response.status_code == 404


def test_get_experiment_anonymous_404(client: TestClient, submitted_experiment) -> None:
    """Tenant-private (§3): a non-owner (here anonymous) gets the SAME 404 as a
    missing experiment, so detail never confirms an id exists."""
    _, _, experiment_id = submitted_experiment
    response = client.get(f"/api/v0/experiments/{experiment_id}")
    assert response.status_code == 404
    assert response.json()["detail"]["error"]["code"] == "experiment_not_found"


def test_get_experiment_owner_sees_full_detail(client: TestClient, submitted_experiment) -> None:
    privkey, binding, experiment_id = submitted_experiment
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path=f"/api/v0/experiments/{experiment_id}",
        authority="testserver",
        body=b"",
    )
    response = client.get(f"/api/v0/experiments/{experiment_id}", headers=sig_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == experiment_id
    assert body["tenant_experiment_label"]
    assert body["manifest_hash"]


# ---- POST /actions/approve — operator only ---------------------------------


def test_approve_requires_maintainer(client: TestClient, submitted_experiment) -> None:
    _, _, experiment_id = submitted_experiment
    response = client.post(f"/api/v0/experiments/{experiment_id}/actions/approve")
    assert response.status_code == 403


def test_approve_advances_to_approved(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    response = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


# ---- POST /actions/abort — operator OR own researcher ----------------------


def test_abort_by_own_researcher_succeeds(client: TestClient, submitted_experiment) -> None:
    privkey, binding, experiment_id = submitted_experiment
    path = f"/api/v0/experiments/{experiment_id}/actions/abort"
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=b"",
    )
    response = client.post(path, headers=sig_headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "aborted"


def test_abort_by_other_researcher_forbidden(
    client: TestClient,
    submitted_experiment,
    maintainer_token: str,
) -> None:
    """A second researcher (different tenant) should be 403 on abort."""
    _, _, experiment_id = submitted_experiment
    # Generate a FRESH keypair — `tenant_keypair` fixture is already bound
    # to the synth-doubler tenant via the submitted_experiment chain, so
    # reusing it here would resolve to synth-doubler again (which can abort).
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key().public_bytes_raw().hex()
    client.post(
        "/api/v0/tenants",
        headers={"Authorization": f"Bearer {maintainer_token}"},
        json={"tenant_id": "other-tenant", "maintainer_pubkey": other_pub},
    )
    path = f"/api/v0/experiments/{experiment_id}/actions/abort"
    sig_headers = sign_request(
        privkey=other_priv,
        pubkey_hex=other_pub,
        method="POST",
        path=path,
        authority="testserver",
        body=b"",
    )
    response = client.post(path, headers=sig_headers)
    assert response.status_code == 403
    assert response.json()["detail"]["error"]["code"] == "experiment_action_forbidden"


def test_abort_by_maintainer_succeeds(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    response = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/abort",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "aborted"


def test_abort_invalid_transition_returns_409(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    """submitted → aborted is fine, but aborted → aborted should 409."""
    _, _, experiment_id = submitted_experiment
    headers = {"Authorization": f"Bearer {maintainer_token}"}
    # First abort succeeds.
    first = client.post(f"/api/v0/experiments/{experiment_id}/actions/abort", headers=headers)
    assert first.status_code == 200
    # Second one is invalid.
    second = client.post(f"/api/v0/experiments/{experiment_id}/actions/abort", headers=headers)
    assert second.status_code == 409
    assert second.json()["detail"]["error"]["code"] == "invalid_status_transition"


# ---- POST /actions/archive — operator only ---------------------------------


def test_archive_requires_maintainer(client: TestClient, submitted_experiment) -> None:
    privkey, binding, experiment_id = submitted_experiment
    path = f"/api/v0/experiments/{experiment_id}/actions/archive"
    sig_headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=b"",
    )
    response = client.post(path, headers=sig_headers)
    assert response.status_code == 403


def test_archive_after_abort(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    headers = {"Authorization": f"Bearer {maintainer_token}"}
    client.post(f"/api/v0/experiments/{experiment_id}/actions/abort", headers=headers)
    response = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/archive",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "archived"
