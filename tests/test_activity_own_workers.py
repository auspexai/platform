"""R-D3 own-worker enrichment on the experiment-activity rollup.

GET /api/v0/experiments/{id}/activity exposes `own_workers` — the requesting
tenant's OWN-account workers, shown non-anonymously (worker_id, pubkey, result
count, trust tier, last activity). Third-party volunteers and workers bound to a
*different* account never appear there; they stay folded into the anonymized
`active_contributor_count`. The field is ACCOUNT_SCOPED — visible to the owning
researcher (whose tenant carries the account, via b-lite `tenants.account_id`)
and the maintainer; an unlinked tenant gets the field omitted entirely.

See researcher_dashboard_design.md §11 and principles §6.9 / §9 #26.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.models import ExperimentStatus, IdentityProvider, TrustTier

AUTHORITY = "testserver"


def _signed_get(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _new_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _make_linked_experiment(
    *,
    account_repository,
    tenant_repository,
    manifest_repository,
    experiment_repository,
    account_id: str,
    tenant_id: str,
    idp_sub: str,
    link_account: bool = True,
):
    """Create an account, a tenant (optionally linked to it), and an APPROVED
    experiment for that tenant. Returns (tenant_privkey, tenant_pubkey, experiment)."""
    account_repository.create(account_id=account_id, idp=IdentityProvider.GITHUB, idp_sub=idp_sub)
    priv, pub = _new_keypair()
    tenant_repository.register(
        tenant_id=tenant_id,
        maintainer_pubkey=pub,
        account_id=account_id if link_account else None,
    )
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": "lbl"},
        signature_json={},
    )
    experiment = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label="lbl",
        manifest_hash=manifest.manifest_hash,
    )
    experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.APPROVED)
    return priv, pub, experiment_repository.get_by_id(experiment.experiment_id)


def _enroll_bound_worker(worker_repository, worker_id: str, account_id: str) -> str:
    _priv, pub = _new_keypair()
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=pub, capabilities={"os": "linux"})
    worker_repository.bind_account(
        worker_id, account_id=account_id, trust_tier=TrustTier.T1_AUTHENTICATED
    )
    return pub


def _seed_results(per_job_factory, experiment_id: str, rows: list[tuple[str, str, str]]) -> None:
    """rows = [(result_id, unit_id, worker_id, worker_pubkey_hex), ...] —
    seeds 3 work units (u0/u1 completed, u2 pending) and the given results."""
    from auspexai_platform.db.repositories.results import ResultRepository
    from auspexai_platform.db.repositories.work_units import WorkUnitRepository

    db = per_job_factory.get_or_create(experiment_id)
    work_units = WorkUnitRepository(db)
    results = ResultRepository(db)
    work_units.submit_batch(
        [{"unit_id": f"u{i}", "payload": {}} for i in range(3)], replication_target=3
    )
    for unit_id in ("u0", "u1"):
        for _ in range(3):
            work_units.increment_completions(unit_id)
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)
    for n, (result_id, unit_id, worker_id, worker_pubkey_hex) in enumerate(rows):
        results.insert(
            result_id=result_id,
            unit_id=unit_id,
            worker_id=worker_id,
            worker_pubkey_hex=worker_pubkey_hex,
            exit_code=0,
            payload={"ok": True},
            worker_signature="sig",
            completed_at=base + timedelta(minutes=n),
        )


class TestOwnWorkerEnrichment:
    def test_owner_sees_only_own_account_workers(
        self,
        client,
        account_repository,
        tenant_repository,
        worker_repository,
        manifest_repository,
        experiment_repository,
        per_job_factory,
    ) -> None:
        priv, pub, experiment = _make_linked_experiment(
            account_repository=account_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            experiment_repository=experiment_repository,
            account_id="acct-own",
            tenant_id="t-own",
            idp_sub="gh-own",
        )
        # Two own-account workers, one third-party (no account), one bound to a
        # DIFFERENT account — all contribute results.
        own1 = _enroll_bound_worker(worker_repository, "w-own-1", "acct-own")
        own2 = _enroll_bound_worker(worker_repository, "w-own-2", "acct-own")
        account_repository.create(
            account_id="acct-other", idp=IdentityProvider.GITHUB, idp_sub="gh-other"
        )
        other = _enroll_bound_worker(worker_repository, "w-other", "acct-other")
        _tp_priv, tp_pub = _new_keypair()
        worker_repository.enroll(worker_id="w-third", pubkey_hex=tp_pub, capabilities={})

        _seed_results(
            per_job_factory,
            experiment.experiment_id,
            [
                ("r0", "u0", "w-own-1", own1),
                ("r1", "u1", "w-own-1", own1),
                ("r2", "u0", "w-own-2", own2),
                ("r3", "u2", "w-other", other),
                ("r4", "u2", "w-third", tp_pub),
            ],
        )

        resp = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # All four distinct workers count toward the anonymized aggregate.
        assert body["active_contributor_count"] == 4
        # ...but own_workers lists exactly the two own-account workers.
        own = {w["worker_id"]: w for w in body["own_workers"]}
        assert set(own) == {"w-own-1", "w-own-2"}
        assert own["w-own-1"]["result_count"] == 2
        assert own["w-own-2"]["result_count"] == 1
        assert own["w-own-1"]["worker_pubkey_hex"] == own1
        assert own["w-own-1"]["trust_tier"] == int(TrustTier.T1_AUTHENTICATED)
        assert own["w-own-1"]["last_activity_at"]
        # Third-party / other-account identities never leak into own_workers.
        flat = repr(body["own_workers"])
        assert "w-third" not in flat
        assert "w-other" not in flat
        assert tp_pub not in flat
        assert other not in flat

    def test_lists_all_account_workers_with_eligibility(
        self,
        client,
        account_repository,
        tenant_repository,
        worker_repository,
        manifest_repository,
        experiment_repository,
        per_job_factory,
    ) -> None:
        # R-D #2: an account worker that can't serve THIS (model-gated) experiment
        # still shows — tagged ineligible-with-reason — instead of vanishing.
        account_repository.create(account_id="acct-e", idp=IdentityProvider.GITHUB, idp_sub="gh-e")
        priv, pub = _new_keypair()
        tenant_repository.register(tenant_id="t-e", maintainer_pubkey=pub, account_id="acct-e")
        manifest = manifest_repository.insert(
            tenant_id="t-e",
            manifest_json={"tenant_id": "t-e", "experiment_id": "lbl-e"},
            signature_json={},
        )
        exp = experiment_repository.create(
            tenant_id="t-e",
            tenant_experiment_label="lbl-e",
            manifest_hash=manifest.manifest_hash,
            required_capabilities={"models": ["m-x"]},
        )
        experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
        exp = experiment_repository.get_by_id(exp.experiment_id)

        def enroll(wid: str, caps: dict) -> str:
            _p, wp = _new_keypair()
            worker_repository.enroll(worker_id=wid, pubkey_hex=wp, capabilities=caps)
            worker_repository.bind_account(
                wid, account_id="acct-e", trust_tier=TrustTier.T2_TRUSTED
            )
            return wp

        prov = {"os": "linux", "execute_tenant_code": "provisioned"}
        pk_back = enroll("w-back", {**prov, "models": ["m-x"]})  # holds + contributes
        enroll("w-elig", {**prov, "models": ["m-x"]})  # holds, idle
        enroll("w-inelig", {"os": "linux"})  # no model, not provisioned

        _seed_results(per_job_factory, exp.experiment_id, [("r0", "u0", "w-back", pk_back)])

        resp = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/experiments/{exp.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        own = {w["worker_id"]: w for w in resp.json()["own_workers"]}
        assert set(own) == {"w-back", "w-elig", "w-inelig"}
        assert own["w-back"]["experiment_eligibility"] == "backing"
        assert own["w-elig"]["experiment_eligibility"] == "eligible"
        assert own["w-inelig"]["experiment_eligibility"] == "ineligible"
        assert own["w-inelig"]["experiment_ineligible_reason"]

    def test_logged_out_contributor_still_listed_as_backing(
        self,
        client,
        account_repository,
        tenant_repository,
        worker_repository,
        receipt_index_repository,
        manifest_repository,
        experiment_repository,
        per_job_factory,
    ) -> None:
        # A worker that backed the experiment and has since LOGGED OUT (unbind →
        # account_id NULL) must STILL appear in own_workers as "backing": its
        # receipts stay credited to the account via the account_id_at_issue
        # snapshot (0041), so the own-worker list keys off that snapshot, not the
        # live binding. The aggregate count and the unbound worker's backing both
        # survive the logout.
        priv, pub, experiment = _make_linked_experiment(
            account_repository=account_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            experiment_repository=experiment_repository,
            account_id="acct-own",
            tenant_id="t-own",
            idp_sub="gh-own",
        )
        own1 = _enroll_bound_worker(worker_repository, "w-own-1", "acct-own")
        own2 = _enroll_bound_worker(worker_repository, "w-own-2", "acct-own")
        # A genuinely third-party contributor bound to a DIFFERENT account — its
        # receipt snapshots that other account, so it must never surface here.
        account_repository.create(
            account_id="acct-other", idp=IdentityProvider.GITHUB, idp_sub="gh-other"
        )
        other = _enroll_bound_worker(worker_repository, "w-other", "acct-other")

        _seed_results(
            per_job_factory,
            experiment.experiment_id,
            [
                ("r0", "u0", "w-own-1", own1),
                ("r1", "u1", "w-own-2", own2),
                ("r2", "u2", "w-other", other),
            ],
        )
        # Index a receipt per contribution WHILE the workers are still bound, so
        # account_id_at_issue snapshots their account at issuance.
        for receipt_id, worker_id, pubkey, result_id in [
            ("rcpt-0", "w-own-1", own1, "r0"),
            ("rcpt-1", "w-own-2", own2, "r1"),
            ("rcpt-2", "w-other", other, "r2"),
        ]:
            receipt_index_repository.record(
                receipt_id=receipt_id,
                experiment_id=experiment.experiment_id,
                worker_id=worker_id,
                worker_pubkey=pubkey,
                result_id=result_id,
            )

        # w-own-2 logs out: account binding dropped, tier → T0. It is no longer
        # returned by worker_repository.list_for_account("acct-own").
        worker_repository.unbind("w-own-2")
        assert {w.worker_id for w in worker_repository.list_for_account("acct-own")} == {"w-own-1"}

        resp = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # All three distinct workers still count toward the anonymized aggregate.
        assert body["active_contributor_count"] == 3
        own = {w["worker_id"]: w for w in body["own_workers"]}
        # BOTH own-account contributors appear — the logged-out one included.
        assert set(own) == {"w-own-1", "w-own-2"}
        assert own["w-own-1"]["experiment_eligibility"] == "backing"
        assert own["w-own-2"]["experiment_eligibility"] == "backing"
        # The logged-out worker shows its current (post-unbind) state: tier 0.
        assert own["w-own-2"]["trust_tier"] == 0
        assert own["w-own-2"]["result_count"] == 1
        # The third-party contributor (different account_id_at_issue) is absent.
        flat = repr(body["own_workers"])
        assert "w-other" not in flat
        assert other not in flat

    def test_maintainer_sees_own_workers(
        self,
        client,
        maintainer_token,
        account_repository,
        tenant_repository,
        worker_repository,
        manifest_repository,
        experiment_repository,
        per_job_factory,
    ) -> None:
        _priv, _pub, experiment = _make_linked_experiment(
            account_repository=account_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            experiment_repository=experiment_repository,
            account_id="acct-own",
            tenant_id="t-own",
            idp_sub="gh-own",
        )
        own1 = _enroll_bound_worker(worker_repository, "w-own-1", "acct-own")
        _seed_results(
            per_job_factory,
            experiment.experiment_id,
            [("r0", "u0", "w-own-1", own1)],
        )
        resp = client.get(
            f"/api/v0/experiments/{experiment.experiment_id}/activity",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert [w["worker_id"] for w in body["own_workers"]] == ["w-own-1"]

    def test_unlinked_tenant_omits_own_workers(
        self,
        client,
        account_repository,
        tenant_repository,
        worker_repository,
        manifest_repository,
        experiment_repository,
        per_job_factory,
    ) -> None:
        # Tenant NOT linked to its account (account exists; tenants.account_id is
        # NULL). Even though a worker bound to that account contributes, the
        # rollup cannot attribute it — own_workers is omitted, aggregate stands.
        priv, pub, experiment = _make_linked_experiment(
            account_repository=account_repository,
            tenant_repository=tenant_repository,
            manifest_repository=manifest_repository,
            experiment_repository=experiment_repository,
            account_id="acct-unlinked",
            tenant_id="t-unlinked",
            idp_sub="gh-unlinked",
            link_account=False,
        )
        own1 = _enroll_bound_worker(worker_repository, "w-own-1", "acct-unlinked")
        _seed_results(
            per_job_factory,
            experiment.experiment_id,
            [("r0", "u0", "w-own-1", own1)],
        )
        resp = _signed_get(
            client,
            privkey=priv,
            pubkey_hex=pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/activity",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["active_contributor_count"] == 1
        assert "own_workers" not in body  # response_model_exclude_none drops it
