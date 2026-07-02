"""End-to-end tests for /api/v0/experiments."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.events import GLOBAL


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
    assert response.json()["detail"]["error"]["code"] == "researcher_or_account_required"


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


def test_submit_warns_exact_without_serving_pin(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """C7 Inc 3: an exact (hash-agreement) inference run that declares a determinism
    profile but NO serving_version_pin records an exact_without_pin advisory — the C15
    footgun (byte-exact on a heterogeneous fleet predictably diverges). Non-fatal (201)."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "exact-no-pin-001",
            reducer={"kind": "builtin_hash_agreement"},
            inference_determinism={"temperature": 0, "seed": 7},  # no serving_version_pin
        ),
    )
    assert response.status_code == 201, response.text
    actions = [a.action for a in client.app.state.audit_repository.latest(limit=20)]
    assert "experiment.exact_without_pin" in actions


def test_submit_no_warn_exact_with_serving_pin(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """A pinned deterministic cell (serving_version_pin set) is the legitimate exact
    path — no advisory."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "exact-pinned-001",
            reducer={"kind": "builtin_hash_agreement"},
            inference_determinism={
                "temperature": 0,
                "seed": 7,
                "serving_version_pin": "ollama/0.17.7",
            },
        ),
    )
    assert response.status_code == 201, response.text
    actions = [a.action for a in client.app.state.audit_repository.latest(limit=20)]
    assert "experiment.exact_without_pin" not in actions


def test_submit_rejects_sampling_with_agreement_reducer(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """inference_determinism Inc 1 (coherence gate): seeded sampling (temperature > 0)
    paired with an AGREEMENT reducer is incoherent — sampled replicas legitimately
    differ, so agreement would be meaningless or falsely claimed. Hard 422, never a
    false-consensus run."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "sampling-agree-001",
            reducer={"kind": "builtin_hash_agreement"},
            inference_determinism={"temperature": 0.7, "seed": 7},
        ),
    )
    assert response.status_code == 422, response.text
    assert (
        response.json()["detail"]["error"]["code"] == "sampling_incoherent_with_agreement_consensus"
    )


def test_submit_rejects_sampling_not_yet_enforced(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """inference_determinism Inc 1: even with a coherent (non-agreement) consensus,
    the worker does not yet honor a declared temperature (v0.2 M1 / Inc 2), so a temp>0
    manifest would silently run greedy. Reject at submit until enforcement lands.
    (Inc 2 removes THIS reject, leaving the coherence reject above.)"""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "sampling-noreducer-001",
            inference_determinism={"temperature": 0.9, "seed": 7},  # no agreement reducer
        ),
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["error"]["code"] == "seeded_sampling_not_yet_enforced"


def test_submit_publishes_experiment_submitted_event(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """M6: a new submission publishes `experiment.submitted` to the firehose so the
    operator console can surface a pending approval live (no refresh). Full payload
    (not pre-redacted by audience — the §6.1 filter applies on tenant-scoped streams)."""
    privkey, binding = registered_tenant
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        response = _submit_as_researcher(
            client, privkey, binding.pubkey_hex, _manifest(binding.tenant_id, "evt-exp")
        )
        assert response.status_code == 201, response.text
        ev = q.get_nowait()  # synchronous POST ran the publish before returning
    assert ev.type == "experiment.submitted"
    assert ev.data["status"] == "submitted"
    assert ev.data["tenant_experiment_label"] == "evt-exp"
    assert ev.data["tenant_id"] == binding.tenant_id
    assert ev.data["manifest_hash"]


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


# ---- A' approve-time clamp (sub-floor integrity-policy override) ------------
#
# These lock in the declarative-vs-enforcement guarantee: the tier floor that
# submit seeds must also be CONSULTED at the two manual maintainer overrides
# (approve `?integrity_policy=` and set-integrity-policy), so a sub-floor policy
# can't be re-opened silently. `submitted_experiment` uses the no-account
# "synth-doubler" tenant → tier T1 → floor `standard` (repl-3); `trusted`
# (repl-1) is therefore sub-floor for it.

_AUTH = lambda tok: {"Authorization": f"Bearer {tok}"}  # noqa: E731


def _promote_tenant_to_t2(account_repository, tenant_repository, tenant_id: str) -> None:
    acct = account_repository.create(
        account_id="acct-clamp-t2",
        idp=IdentityProvider.GITHUB,
        idp_sub="clamp-t2-sub",
        trust_tier=TrustTier.T2_TRUSTED,
    )
    tenant_repository.set_account(tenant_id, acct.account_id)


def test_approve_subfloor_policy_rejected_without_force(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"integrity_policy": "trusted"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"]["code"] == "sub_floor_integrity_policy"
    # the refusal happens BEFORE any state change — still submitted, untouched.
    detail = client.get(
        f"/api/v0/experiments/{experiment_id}", headers=_AUTH(maintainer_token)
    ).json()
    assert detail["status"] == "submitted"


def test_approve_subfloor_policy_with_force_and_reason_succeeds_and_audits(
    client: TestClient, submitted_experiment, maintainer_token: str, audit_repository
) -> None:
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"integrity_policy": "trusted", "force": "true", "reason": "one-off trusted run"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"
    assert r.json()["integrity_policy"] == "trusted"
    rows = [
        a
        for a in audit_repository.latest(limit=30)
        if a.action == "experiment.approve" and a.resource_id == experiment_id
    ]
    assert rows, "approve audit row missing"
    payload = rows[0].payload
    assert payload["forced_below_floor"] is True
    assert payload["floor_policy"] == "standard"
    assert payload["tenant_tier"] == int(TrustTier.T1_AUTHENTICATED)
    assert payload["force_reason"] == "one-off trusted run"


def test_approve_force_without_reason_rejected(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"integrity_policy": "trusted", "force": "true"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error"]["code"] == "force_requires_reason"


def test_approve_at_floor_policy_is_not_gated(
    client: TestClient, submitted_experiment, maintainer_token: str, audit_repository
) -> None:
    # `standard` is exactly the T1 floor — allowed with no force, no override audit.
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"integrity_policy": "standard"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    rows = [
        a
        for a in audit_repository.latest(limit=30)
        if a.action == "experiment.approve" and a.resource_id == experiment_id
    ]
    assert "forced_below_floor" not in (rows[0].payload or {})


# ---- C14 (target, floor) override — repl-2 expressible at approval ----------


def test_approve_with_replication_target_2_is_expressible(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    # C14: the maintainer sets replication_target directly — repl-2 (which the {1,3,5}
    # integrity_policy ladder could NOT express) is selectable. Tenant is T1 (floor 2).
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"replication_target": 2},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["replication_target"] == 2  # the ladder's gap — now expressible
    assert body["integrity_policy"] == "standard"  # derived coarse label


def test_approve_replication_target_floored_to_tier(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    # resolve_replication tier-floors: a T1 tenant (floor 2) can't be dropped to repl-1 via this
    # path — lowering below the earned floor stays on the legacy integrity_policy + force path.
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"replication_target": 1},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["replication_target"] == 2  # floored up to the T1 tier floor


def test_set_replication_override_after_approval(
    client: TestClient, submitted_experiment, maintainer_token: str, audit_repository
) -> None:
    _, _, experiment_id = submitted_experiment
    client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        headers=_AUTH(maintainer_token),
    )
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/set-replication",
        json={"replication_target": 5, "replication_floor": 3, "reason": "raise corroboration"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["replication_target"] == 5
    assert body["replication_floor"] == 3
    assert body["integrity_policy"] == "high"
    rows = [
        a
        for a in audit_repository.latest(limit=30)
        if a.action == "experiment.set_replication" and a.resource_id == experiment_id
    ]
    assert rows and rows[0].payload["replication_target"] == 5


def test_approve_subfloor_allowed_without_force_for_t2_tenant(
    client: TestClient,
    submitted_experiment,
    maintainer_token: str,
    account_repository,
    tenant_repository,
) -> None:
    # The floor moves with earned trust: once the tenant's account is T2,
    # `trusted`/repl-1 is no longer sub-floor and needs no force.
    _, binding, experiment_id = submitted_experiment
    _promote_tenant_to_t2(account_repository, tenant_repository, binding.tenant_id)
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/approve",
        params={"integrity_policy": "trusted"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["integrity_policy"] == "trusted"


def test_set_integrity_policy_subfloor_rejected_without_force(
    client: TestClient, submitted_experiment, maintainer_token: str
) -> None:
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/set-integrity-policy",
        json={"integrity_policy": "trusted", "reason": "want repl-1"},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"]["code"] == "sub_floor_integrity_policy"


def test_set_integrity_policy_subfloor_with_force_succeeds_and_audits(
    client: TestClient, submitted_experiment, maintainer_token: str, audit_repository
) -> None:
    _, _, experiment_id = submitted_experiment
    r = client.post(
        f"/api/v0/experiments/{experiment_id}/actions/set-integrity-policy",
        json={"integrity_policy": "trusted", "reason": "deliberate repl-1", "force": True},
        headers=_AUTH(maintainer_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["integrity_policy"] == "trusted"
    rows = [
        a
        for a in audit_repository.latest(limit=30)
        if a.action == "experiment.set_integrity_policy" and a.resource_id == experiment_id
    ]
    assert rows and rows[0].payload["forced_below_floor"] is True
    assert rows[0].payload["force_reason"] == "deliberate repl-1"


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


def test_submit_rejects_custom_reducer(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """Custom reducers aren't implemented coordinator-side (issuance runs
    builtin_hash_agreement only); a kind:custom manifest is rejected at ingest
    rather than silently falling back to hash-agreement without the tenant
    knowing (audit 2026-06-08)."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "custom-red-001",
            reducer={"kind": "custom", "command": ["./reduce"]},
        ),
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["error"]["code"] == "custom_reducer_unsupported"


def test_stuck_experiments_flags_zero_unit_approved(
    approved_experiment, per_job_factory, experiment_repository
) -> None:
    """E14: an approved experiment that submitted no work units is flagged once it's
    older than the stuck threshold — and not while it's still fresh."""
    from datetime import UTC, datetime, timedelta

    from auspexai_platform.api.experiments import _stuck_experiments

    _privkey, _binding, experiment, _hash = approved_experiment

    # Fresh (now): below the threshold → not yet flagged (driver may be starting).
    fresh = _stuck_experiments(experiment_repository, per_job_factory, datetime.now(UTC))
    assert experiment.experiment_id not in [e.experiment_id for e, _ in fresh]

    # Evaluate well past the threshold → the zero-unit approved run is flagged.
    future = datetime.now(UTC) + timedelta(hours=1)
    stuck = _stuck_experiments(experiment_repository, per_job_factory, future)
    assert experiment.experiment_id in [e.experiment_id for e, _ in stuck]


def test_stuck_experiments_ignores_runs_with_units(
    approved_experiment, per_job_factory, experiment_repository
) -> None:
    """A run that actually submitted work units is never 'stuck', however old."""
    from datetime import UTC, datetime, timedelta

    from auspexai_platform.api.experiments import _stuck_experiments
    from auspexai_platform.db.repositories.work_units import WorkUnitRepository

    _privkey, _binding, experiment, _hash = approved_experiment
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch(
        [{"unit_id": "u1", "payload": {"x": 1}}], replication_target=1
    )
    future = datetime.now(UTC) + timedelta(hours=1)
    stuck = _stuck_experiments(experiment_repository, per_job_factory, future)
    assert experiment.experiment_id not in [e.experiment_id for e, _ in stuck]


def test_experiment_phase_distinguishes_approved_states(
    approved_experiment, per_job_factory, experiment_repository
) -> None:
    """E15: run_phase splits the overloaded APPROVED into provisioning/inert/queued."""
    from datetime import UTC, datetime, timedelta

    from auspexai_platform.api.experiments import _experiment_phase
    from auspexai_platform.db.repositories.work_units import WorkUnitRepository

    _privkey, _binding, experiment, _hash = approved_experiment
    now = datetime.now(UTC)
    # Approved, no units: fresh → provisioning; aged past the threshold → inert.
    assert _experiment_phase(experiment, per_job_factory, now) == "provisioning"
    assert _experiment_phase(experiment, per_job_factory, now + timedelta(hours=1)) == "inert"
    # Work pending, nothing started → queued.
    db = per_job_factory.get_or_create(experiment.experiment_id)
    WorkUnitRepository(db).submit_batch([{"unit_id": "u1", "payload": {}}], replication_target=1)
    assert _experiment_phase(experiment, per_job_factory, now) == "queued"


def test_experiment_phase_submitted_awaits_assessment(
    approved_experiment, per_job_factory, experiment_repository
) -> None:
    """E15: a submitted experiment with no assessment decision → awaiting_assessment."""
    from datetime import UTC, datetime

    from auspexai_platform.api.experiments import _experiment_phase

    _privkey, binding, _experiment, _hash = approved_experiment
    sub = experiment_repository.create(
        tenant_id=binding.tenant_id, tenant_experiment_label="sub-phase", manifest_hash=_hash
    )
    assert _experiment_phase(sub, per_job_factory, datetime.now(UTC)) == "awaiting_assessment"


# ---- D16.2: pre-registration at submit --------------------------------------

_PR_FS = {
    "probe_id": {
        "meaning": "which probe",
        "kind": "categorical",
        "role": "key",
        "change_means": "different probe",
        "categories": ["p-a"],
    },
    "lexical.type_token_ratio": {
        "meaning": "ttr",
        "kind": "numeric",
        "role": "summary",
        "range": {"min": 0.0, "max": 1.0},
        "change_means": "vocab shift",
        "comparison": {"rule": "numeric", "rel": 0.02},
    },
}
_PR_BLOCK = {
    "hypothesis": "responses to each fixed probe are stable across rounds",
    "analysis_method": "per probe_id, compare the consensus vector round-over-round",
    "features": ["lexical.type_token_ratio"],
    "timescale": "intra_experiment_rounds",
    "decision_rule": "drift IFF the consensus vector exits the declared envelope",
    "expected_result": "no probe drifts",
    "stopping_rule": "converge-on-stability; not data-peeking-dependent",
    "comparison_keys": ["probe_id"],
}


def test_submit_pre_registered_records_anchor(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """D16.2: a valid pre-registered v0.4 manifest submits (201), and the
    coordinator COSE-signs + persists the submit-time anchor row (placeholder
    Rekor sentinels — the hourly backfill anchors) + audits it."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "prereg-001",
            schema_version="0.4",
            feature_schema=_PR_FS,
            pre_registration=dict(_PR_BLOCK),
        ),
    )
    assert response.status_code == 201, response.text
    exp_id = response.json()["experiment_id"]
    rec = client.app.state.pre_registration_repository.get(exp_id)
    assert rec is not None and not rec.anchored
    assert rec.manifest_hash == response.json()["manifest_hash"]
    actions = [a.action for a in client.app.state.audit_repository.latest(limit=20)]
    assert "pre_registration.recorded" in actions


def test_submit_invalid_pre_registration_rejected(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """A pre-registration naming an undeclared feature is refused BEFORE storage
    — a malformed design never gets an anchor."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "prereg-bad-001",
            schema_version="0.4",
            feature_schema=_PR_FS,
            pre_registration={**_PR_BLOCK, "features": ["not.declared"]},
        ),
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["error"]["code"] == "pre_registration_invalid"


def test_submit_v04_feature_schema_only_accepted(
    client: TestClient, registered_tenant: tuple[Ed25519PrivateKey, object]
) -> None:
    """The D16.1 gate accepts v0.4 (a superset of v0.3) — a v0.4 manifest
    declaring only a feature_schema must not be rejected."""
    privkey, binding = registered_tenant
    response = _submit_as_researcher(
        client,
        privkey,
        binding.pubkey_hex,
        _manifest(
            binding.tenant_id,
            "v04-fs-001",
            schema_version="0.4",
            feature_schema=_PR_FS,
        ),
    )
    assert response.status_code == 201, response.text
