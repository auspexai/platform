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

    def test_self_baseline_authorization_needs_no_reference(
        self,
        client,
        approved_experiment,
        experiment_repository,
        account_repository,
        tenant_repository,
    ):
        # A self-baseline entry has NO reference experiment — authorization must not
        # require reference_experiment_id (it was a required str → the field being
        # absent 422'd before). Publishing a self-baselined run's 0.0 score is valid.
        privkey, binding, experiment, _mh = approved_experiment
        _complete(experiment_repository, experiment.experiment_id)
        from auspexai_platform.db.models import IdentityProvider, TrustTier

        account_repository.create(
            account_id="acct-self",
            idp=IdentityProvider.GITHUB,
            idp_sub="acct-self-sub",
            trust_tier=TrustTier.T2_TRUSTED,
        )
        tenant_repository.set_account(experiment.tenant_id, "acct-self")
        path = (
            f"/api/v0/experiments/{experiment.experiment_id}"
            "/actions/authorize-benchmark-publication"
        )
        r = _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=path,
            body={"peak_eu": 0.0, "breadth": 0.0, "byte_divergence_rate": 0.0},
        )
        assert r.status_code == 200, r.text
        block = r.json()["authorization"]
        assert block["standing_at_issue"] >= 1
        # Recorded as a benchmark publication (so it also satisfies the DOI gate).
        lr = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/publications",
        )
        pubs = lr.json()["publications"]
        assert len(pubs) == 1 and pubs[0]["kind"] == "benchmark"

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

    def test_prereg_gate_looks_up_by_experiment_id_not_manifest_hash(
        self,
        client,
        approved_experiment,
        experiment_repository,
        account_repository,
        tenant_repository,
        db,
    ):
        """Regression: the DOI prereg gate must look up the pre-registration by
        experiment_id (like every other call site), NOT manifest_hash. The bug
        (`get(experiment.manifest_hash)`) 409'd `pre_registration_missing` on a
        genuinely pre-registered experiment — silently blocking EVERY real DOI
        mint (no production experiment ever minted one). A pre-registered, R3,
        completed+attested experiment must get PAST the prereg gate — here it
        then stops at the benchmark gate (none published), proving the prereg
        check passed."""
        from auspexai_platform.db.models import IdentityProvider, ResearchStanding, TrustTier
        from auspexai_platform.db.repositories.attestations import AttestationRepository
        from auspexai_platform.db.repositories.pre_registrations import PreRegistrationRepository

        privkey, binding, experiment, mh = approved_experiment
        eid = experiment.experiment_id
        label = getattr(experiment, "tenant_experiment_label", eid)
        _complete(experiment_repository, eid)
        # An R3 researcher (DOI issuance requires R3).
        account_repository.create(
            account_id="acct-doi",
            idp=IdentityProvider.GITHUB,
            idp_sub="acct-doi-sub",
            trust_tier=TrustTier.T2_TRUSTED,
        )
        account_repository.set_research_standing(
            "acct-doi", new_standing=ResearchStanding.R3_TRUSTED
        )
        tenant_repository.set_account(experiment.tenant_id, "acct-doi")
        # A final attestation → get_final returns one (past attestation_missing).
        AttestationRepository(db).insert(
            attestation_id="att-doi",
            experiment_id=eid,
            tenant_id=experiment.tenant_id,
            tenant_experiment_label=label,
            merkle_root="a" * 64,
            algorithm="sha256-merkle-v1",
            unit_count=1,
            cose_signed_blob=b"x",
            signing_key_pubkey_hex="00" * 32,
        )
        # Pre-registered — the real submit-time shape: keyed by experiment_id.
        PreRegistrationRepository(db).insert(
            experiment_id=eid,
            tenant_id=experiment.tenant_id,
            tenant_experiment_label=label,
            manifest_hash=mh,
            cose_signed_blob=b"x",
            signing_key_pubkey_hex="00" * 32,
            submitted_at="2026-07-09T00:00:00+00:00",
        )
        r = _signed_post(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{eid}/actions/mint-doi",
            body={},
        )
        # Past the prereg gate → stopped at the benchmark gate. With the bug this
        # was `pre_registration_missing`.
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"]["code"] == "benchmark_publication_required"
