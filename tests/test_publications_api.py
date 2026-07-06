"""G6+F4 endpoints: authorization signing, R-gates, prerequisite chain."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auspexai_platform.db.models import ExperimentStatus

from .test_results_mresults import _signed_get


def _signed_post(client, *, privkey, pubkey_hex, path, body):
    import json as _json

    from auspexai_platform.auth.signature import sign_request

    payload = _json.dumps(body).encode()
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path=path,
        authority="testserver",
        body=payload,
    )
    headers["Content-Type"] = "application/json"
    return client.post(path, content=payload, headers=headers)


def _complete(experiment_repository, experiment_id):
    experiment_repository.update_status(experiment_id, ExperimentStatus.COMPLETED)


class TestAuthorizeBenchmarkPublication:
    def test_signed_block_and_record(
        self,
        client,
        approved_experiment,
        experiment_repository,
        account_repository,
        tenant_repository,
    ):
        privkey, binding, experiment, _mh = approved_experiment
        _complete(experiment_repository, experiment.experiment_id)
        # Link an account (default standing R1_VERIFIED) to the tenant so the
        # R1+ gate passes — the unlinked case is the 403 test below.
        from auspexai_platform.db.models import IdentityProvider, TrustTier

        account_repository.create(
            account_id="acct-pub",
            idp=IdentityProvider.GITHUB,
            idp_sub="acct-pub-sub",
            trust_tier=TrustTier.T2_TRUSTED,
        )
        tenant_repository.set_account(experiment.tenant_id, "acct-pub")
        path = (
            f"/api/v0/experiments/{experiment.experiment_id}"
            "/actions/authorize-benchmark-publication"
        )
        r = _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=path,
            body={"reference_experiment_id": "exp-ref", "peak_eu": 6.67, "breadth": 0.33},
        )
        assert r.status_code == 200, r.text
        block = r.json()["authorization"]
        assert block["standing_at_issue"] >= 1
        assert block["publisher_pubkey"] == binding.pubkey_hex
        # The signature verifies over the canonical block sans pubkey field.
        body = {
            k: v
            for k, v in block.items()
            if k not in ("coordinator_pubkey_hex", "coordinator_signature")
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(block["coordinator_pubkey_hex"]))
        pub.verify(bytes.fromhex(block["coordinator_signature"]), canonical)
        # Claimed summary hash matches.
        claimed = {
            "reference_experiment_id": "exp-ref",
            "peak_eu": 6.67,
            "breadth": 0.33,
            "byte_divergence_rate": None,
            "entry_intent": None,
        }
        assert (
            block["summary_sha256"]
            == hashlib.sha256(
                json.dumps(claimed, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        # The record shows up on the listing surface.
        lr = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/publications",
        )
        pubs = lr.json()["publications"]
        assert len(pubs) == 1 and pubs[0]["kind"] == "benchmark"
        assert pubs[0]["summary"]["peak_eu"] == 6.67

    def test_not_completed_is_typed_409(self, client, approved_experiment):
        privkey, binding, experiment, _mh = approved_experiment
        r = _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}"
            "/actions/authorize-benchmark-publication",
            body={"reference_experiment_id": "exp-ref"},
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"]["code"] == "experiment_not_completed"


class TestMintDoiGates:
    def test_r3_gate_refuses_default_standing(
        self, client, approved_experiment, experiment_repository
    ):
        privkey, binding, experiment, _mh = approved_experiment
        _complete(experiment_repository, experiment.experiment_id)
        r = _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/actions/mint-doi",
            body={},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"]["code"] == "research_standing_too_low"
