"""Tests for R-D1(b) — tenant-scoped experiment receipts.

GET /api/v0/experiments/{id}/receipts: the researcher dashboard's "My
Receipts" view. Researcher-own-tenant + maintainer only; worker identity
(worker_id, worker_pubkey) is stripped because it's account-scoped/
operator-only, never tenant-scoped. See researcher_dashboard_design.md §7.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.db.repositories import (
    ReceiptIndexRepository,
    WorkerRepository,
)

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


def _index_receipts(
    receipt_index_repository: ReceiptIndexRepository,
    worker_repository: WorkerRepository,
    experiment_id: str,
    n: int,
) -> list[str]:
    """Enroll n workers (FK) and index one receipt each for the experiment."""
    ids: list[str] = []
    for i in range(n):
        pub = f"{i + 1:02x}" * 32
        worker_repository.enroll(worker_id=f"wkr-{experiment_id}-{i}", pubkey_hex=pub)
        rid = f"rcpt-{experiment_id}-{i}"
        receipt_index_repository.record(
            receipt_id=rid,
            experiment_id=experiment_id,
            worker_id=f"wkr-{experiment_id}-{i}",
            worker_pubkey=pub,
        )
        ids.append(rid)
    return ids


class TestListExperimentReceipts:
    def test_researcher_own_tenant_lists_with_worker_identity_stripped(
        self,
        client: TestClient,
        approved_experiment,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        privkey, binding, experiment, _hash = approved_experiment
        rids = _index_receipts(
            receipt_index_repository, worker_repository, experiment.experiment_id, 2
        )

        response = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/receipts",
        )
        assert response.status_code == 200, response.text
        receipts = response.json()["receipts"]
        assert {r["receipt_id"] for r in receipts} == set(rids)
        # Tenant view: worker identity must NOT be present.
        for r in receipts:
            assert "worker_id" not in r
            assert "worker_pubkey" not in r
            assert r["experiment_id"] == experiment.experiment_id
            assert "issued_at" in r

    def test_maintainer_can_list_any_experiment(
        self,
        client: TestClient,
        maintainer_token: str,
        approved_experiment,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        _privkey, _binding, experiment, _hash = approved_experiment
        rids = _index_receipts(
            receipt_index_repository, worker_repository, experiment.experiment_id, 1
        )
        response = client.get(
            f"/api/v0/experiments/{experiment.experiment_id}/receipts",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert response.status_code == 200
        assert [r["receipt_id"] for r in response.json()["receipts"]] == rids

    def test_other_tenant_researcher_forbidden(
        self,
        client: TestClient,
        approved_experiment,
        tenant_registry,
        receipt_index_repository: ReceiptIndexRepository,
        worker_repository: WorkerRepository,
    ) -> None:
        _privkey, _binding, experiment, _hash = approved_experiment
        _index_receipts(receipt_index_repository, worker_repository, experiment.experiment_id, 1)
        # A second tenant with its own key tries to read the first's receipts.
        other_priv = Ed25519PrivateKey.generate()
        other_pub = other_priv.public_key().public_bytes_raw().hex()
        tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)

        response = _signed_get(
            client,
            privkey=other_priv,
            pubkey_hex=other_pub,
            path=f"/api/v0/experiments/{experiment.experiment_id}/receipts",
        )
        assert response.status_code == 403
        assert (
            response.json()["detail"]["error"]["code"]
            == "researcher_own_tenant_or_maintainer_required"
        )

    def test_missing_experiment_returns_404(self, client: TestClient, registered_tenant) -> None:
        privkey, binding = registered_tenant
        response = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path="/api/v0/experiments/exp-does-not-exist/receipts",
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error"]["code"] == "experiment_not_found"

    def test_anonymous_forbidden(self, client: TestClient, approved_experiment) -> None:
        _privkey, _binding, experiment, _hash = approved_experiment
        response = client.get(f"/api/v0/experiments/{experiment.experiment_id}/receipts")
        assert response.status_code in (401, 403)

    def test_empty_when_no_receipts(self, client: TestClient, approved_experiment) -> None:
        privkey, binding, experiment, _hash = approved_experiment
        response = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/receipts",
        )
        assert response.status_code == 200
        # No receipts → receipts field is None/excluded (response_model_exclude_none).
        assert response.json().get("receipts") in (None, [])


# ---- repository unit test --------------------------------------------------


def test_list_for_experiment_filters_and_orders(
    receipt_index_repository: ReceiptIndexRepository,
    worker_repository: WorkerRepository,
) -> None:
    worker_repository.enroll(worker_id="w-a", pubkey_hex="aa" * 32)
    worker_repository.enroll(worker_id="w-b", pubkey_hex="bb" * 32)
    receipt_index_repository.record(
        receipt_id="r-exp1-1", experiment_id="exp-1", worker_id="w-a", worker_pubkey="aa" * 32
    )
    receipt_index_repository.record(
        receipt_id="r-exp2-1", experiment_id="exp-2", worker_id="w-b", worker_pubkey="bb" * 32
    )
    exp1 = receipt_index_repository.list_for_experiment("exp-1")
    assert [e.receipt_id for e in exp1] == ["r-exp1-1"]
    assert receipt_index_repository.list_for_experiment("exp-nope") == []
