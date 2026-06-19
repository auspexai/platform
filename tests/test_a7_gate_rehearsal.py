"""A7 gate-green REHEARSAL — prove what the maintainer will see the MOMENT they
flip the live `trust_model_policy` toggle ON.

The flip is OFF in production (gated on A7). This rehearses the ON behavior over
the real repos on a throwaway test DB: a STRICT-attested v2 DIVERGENCE earns trust
EQUAL to agreement (the firewall-#1 endpoint), while OFF earns nothing, a
permissive divergence earns nothing even ON, and the v2 signature genuinely binds
`ran_under`. Run this (via scripts/a7_gate_check.sh) before flipping — it never
touches the live coordinator DB.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import IdentityProvider, TrustTier
from auspexai_platform.db.repositories import (
    AccountRepository,
    ExperimentRepository,
    ManifestRepository,
    ReceiptIndexRepository,
    TenantRepository,
    TrustModelPolicyRepository,
    WorkerRepository,
)
from auspexai_platform.result_signature import verify_result_signature
from tests._result_helpers import sign_result_body


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = (
        priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return priv, pub


def _experiment(db):
    tenants = TenantRepository(db)
    manifests = ManifestRepository(db)
    experiments = ExperimentRepository(db)
    tenants.register(tenant_id="t", maintainer_pubkey="aa" * 32)
    m = manifests.insert(
        tenant_id="t",
        manifest_json={"tenant_id": "t", "experiment_id": "e", "models": []},
        signature_json={"maintainer_pubkey_hex": "00" * 32, "signature_b64": "dGVzdA=="},
    )
    return experiments.create(
        tenant_id="t", tenant_experiment_label="e", manifest_hash=m.manifest_hash
    )


def test_a7_flip_rehearsal_strict_v2_divergence_earns_equal_trust(db: Database):
    """The headline rehearsal: flip ON → a STRICT-attested v2 divergence earns trust
    EQUAL to agreement (OFF earned nothing). End-to-end over the #32 + flip path."""
    accounts = AccountRepository(db)
    workers = WorkerRepository(db)
    receipts = ReceiptIndexRepository(db)
    policy = TrustModelPolicyRepository(db)
    exp = _experiment(db)

    priv_a, pub_a = _keypair()
    _, pub_b = _keypair()  # worker B diverges; only A's body is signed for the #32 check
    for acct, wid, pub in (("acct-a", "w-a", pub_a), ("acct-b", "w-b", pub_b)):
        accounts.create(account_id=acct, idp=IdentityProvider.GITHUB, idp_sub=acct)
        workers.enroll(worker_id=wid, pubkey_hex=pub)
        workers.bind_account(wid, account_id=acct, trust_tier=TrustTier.T1_AUTHENTICATED)

    # 1) The #32 chain: a v2 result signed ran_under=strict verifies; a tampered
    #    containment claim does NOT — the accountability the flip rests on.
    body = dict(
        unit_id="u",
        completed_at="2026-06-19T00:00:00+00:00",
        exit_code=0,
        payload={"x": 1},
        schema_version=2,
        served_weights={},
    )
    sig_a = sign_result_body(priv_a, pub_a, **body, ran_under="strict")
    assert verify_result_signature(
        worker_pubkey=pub_a, signature_b64=sig_a, **body, ran_under="strict"
    )
    assert not verify_result_signature(
        worker_pubkey=pub_a, signature_b64=sig_a, **body, ran_under="permissive"
    )

    # 2) The unit DIVERGED (two strict workers, different answers) — record it as
    #    issuance does for a diverged STRICT-attested v2 unit.
    for wid, pub in (("w-a", pub_a), ("w-b", pub_b)):
        receipts.record_divergence(
            experiment_id=exp.experiment_id,
            worker_id=wid,
            worker_pubkey=pub,
            unit_id="u",
            ran_under_strict=True,
        )

    # 3) Production state (flip OFF): divergence earns NO trust (convergence model).
    assert policy.get().equal_trust_enabled is False
    assert receipts.account_corroboration_summary("acct-a", equal_trust_enabled=False)[0] == 0

    # 4) FLIP THE TOGGLE ON (what the maintainer does): the STRICT divergence now
    #    earns trust — equal to agreement. The firewall-#1 endpoint.
    policy.set(equal_trust_enabled=True, updated_by="gate-rehearsal", reason="A7 gate-green check")
    on = policy.get().equal_trust_enabled
    assert on is True
    assert receipts.account_corroboration_summary("acct-a", equal_trust_enabled=on)[0] == 1
    assert receipts.account_corroboration_summary("acct-b", equal_trust_enabled=on)[0] == 1


def test_a7_flip_rehearsal_permissive_divergence_earns_nothing_even_on(db: Database):
    """The guard holds: a permissive divergence has no bundle → no trust even ON."""
    accounts = AccountRepository(db)
    workers = WorkerRepository(db)
    receipts = ReceiptIndexRepository(db)
    exp = _experiment(db)
    accounts.create(account_id="acct-p", idp=IdentityProvider.GITHUB, idp_sub="p")
    workers.enroll(worker_id="w-p", pubkey_hex="22" * 32)
    workers.bind_account("w-p", account_id="acct-p", trust_tier=TrustTier.T1_AUTHENTICATED)
    receipts.record_divergence(
        experiment_id=exp.experiment_id,
        worker_id="w-p",
        worker_pubkey="22" * 32,
        unit_id="u",
        ran_under_strict=False,
    )
    assert receipts.account_corroboration_summary("acct-p", equal_trust_enabled=True)[0] == 0
