"""Result-set completion attestation (#34 §6.3) — merkle root + COSE/in-toto build."""

from __future__ import annotations

from pathlib import Path

import cbor2
import pytest

from auspexai_platform.receipts.attestation import (
    RESULT_SET_ALGORITHM,
    RESULT_SET_ALGORITHM_V1,
    ResultSetEntry,
    build_result_set_attestation,
    merkle_root,
    unit_payload_sha256,
)
from auspexai_platform.receipts.intoto import (
    AUSPEXAI_RESULT_SET_PREDICATE_TYPE,
    AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1,
)
from auspexai_platform.receipts.signing import (
    CoseVerificationError,
    cose_sign1_decode,
    load_or_generate_signing_key,
)


def _entry(uid: str, h: str = "deadbeef", rid: str = "rcpt-x") -> ResultSetEntry:
    return ResultSetEntry(unit_id=uid, consensus_result_hash=h, receipt_id=rid)


# ---- module-level merkle/build tests use the helpers above ----


def test_merkle_root_is_order_independent():
    a = [_entry("u1"), _entry("u2"), _entry("u3")]
    assert merkle_root(a) == merkle_root(list(reversed(a)))


def test_merkle_root_changes_with_any_field():
    base = [_entry("u1", "h1"), _entry("u2", "h2")]
    assert merkle_root(base) != merkle_root([_entry("u1", "h1"), _entry("u2", "CHANGED")])
    assert merkle_root(base) != merkle_root([_entry("u1", "h1"), _entry("u2", "h2", "rcpt-OTHER")])


def test_merkle_root_empty_is_sentinel_and_stable():
    assert merkle_root([]) == merkle_root([])
    assert merkle_root([]) != merkle_root([_entry("u1")])


def test_merkle_root_single_and_odd_counts():
    # total function across cardinalities (1, odd, even)
    assert isinstance(merkle_root([_entry("u1")]), str)
    assert len(merkle_root([_entry(f"u{i}") for i in range(3)])) == 64  # hex sha256
    assert len(merkle_root([_entry(f"u{i}") for i in range(4)])) == 64


def test_build_attestation_signs_and_round_trips(tmp_path: Path):
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [_entry("u2", "h2", "rcpt-2"), _entry("u1", "h1", "rcpt-1")]
    att = build_result_set_attestation(
        attestation_id="att-test",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
    )
    assert att.merkle_root == merkle_root(entries, schema_version=1)
    assert att.unit_count == 2
    assert att.algorithm == RESULT_SET_ALGORITHM_V1
    # entries are returned sorted by unit_id
    assert [e.unit_id for e in att.entries] == ["u1", "u2"]

    # COSE signature verifies against the signing key's public key.
    payload, kid = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    assert kid == key.pubkey_hex
    # ... and the in-toto statement decodes to the result-set predicate + attested root.
    statement = cbor2.loads(payload)
    assert statement["predicateType"] == AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1
    body = cbor2.loads(statement["predicate"])
    assert body["merkle_root"] == att.merkle_root
    assert body["unit_count"] == 2
    assert [u["unit_id"] for u in body["units"]] == ["u1", "u2"]
    # v1 predicate units carry the input-binding hash (empty-string when unknown).
    assert all("unit_payload_sha256" in u for u in body["units"])


def test_build_attestation_schema_version_0_reproduces_legacy_format(tmp_path: Path):
    """Honor-forever: schema_version=0 must reproduce the M7 byte format —
    v0 algorithm, v0 predicate type, v0 leaves (no input hash member)."""
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [_entry("u1", "h1", "rcpt-1")]
    att = build_result_set_attestation(
        attestation_id="att-legacy",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
        schema_version=0,
    )
    assert att.algorithm == RESULT_SET_ALGORITHM
    assert att.merkle_root == merkle_root(entries)  # default = v0 leaves
    payload, _ = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    statement = cbor2.loads(payload)
    assert statement["predicateType"] == AUSPEXAI_RESULT_SET_PREDICATE_TYPE
    body = cbor2.loads(statement["predicate"])
    assert body["algorithm"] == RESULT_SET_ALGORITHM
    assert all("unit_payload_sha256" not in u for u in body["units"])


def test_v1_leaves_bind_the_unit_payload_hash():
    """EB-1 reproducibility triple: changing the INPUT hash changes the v1
    root (input is leaf-bound) but not the v0 root (legacy leaves ignore it)."""
    a = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32)]
    b = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="bb" * 32)]
    assert merkle_root(a, schema_version=1) != merkle_root(b, schema_version=1)
    assert merkle_root(a) == merkle_root(b)  # v0: input hash not in the leaf
    # environment is predicate metadata, NEVER leaf material — same root.
    c = [
        ResultSetEntry(
            "u1", "h1", "r1", unit_payload_sha256="aa" * 32, environment={"x": 1}
        )
    ]
    assert merkle_root(a, schema_version=1) == merkle_root(c, schema_version=1)


def test_unit_payload_sha256_is_canonical():
    """The input-hash convention is over the canonical re-serialization, so
    storage formatting differences don't change the hash."""
    assert unit_payload_sha256('{"b": 1, "a": 2}') == unit_payload_sha256(
        '{"a":2,"b":1}'
    )


def test_build_attestation_signature_rejects_wrong_key(tmp_path: Path):
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    other = load_or_generate_signing_key(tmp_path / "other.key")
    att = build_result_set_attestation(
        attestation_id="att-test",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=[_entry("u1")],
        signing_key=key,
    )
    with pytest.raises(CoseVerificationError):
        cose_sign1_decode(att.cose_signed_blob, expected_pubkey=other.public_key)


def test_partial_flag_signs_in_predicate_but_does_not_change_root(tmp_path: Path):
    """M9 leg 2: partial=True is carried in the COSE-signed predicate (tamper-
    evident) but the Merkle root is purely over entries — so a checkpoint and the
    eventual completed attestation over the SAME set share a root. partial=False
    omits the key entirely (completed predicate stays byte-identical to M7)."""
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [_entry("u1", "h1", "rcpt-1"), _entry("u2", "h2", "rcpt-2")]
    complete = build_result_set_attestation(
        attestation_id="att-c",
        tenant_experiment_label="x",
        tenant_id="t",
        entries=entries,
        signing_key=key,
        partial=False,
    )
    chkpt = build_result_set_attestation(
        attestation_id="att-p",
        tenant_experiment_label="x",
        tenant_id="t",
        entries=entries,
        signing_key=key,
        partial=True,
    )
    assert complete.merkle_root == chkpt.merkle_root  # root unaffected by partial
    assert complete.partial is False and chkpt.partial is True

    comp_payload, _ = cose_sign1_decode(complete.cose_signed_blob, expected_pubkey=key.public_key)
    chk_payload, _ = cose_sign1_decode(chkpt.cose_signed_blob, expected_pubkey=key.public_key)
    comp_pred = cbor2.loads(cbor2.loads(comp_payload)["predicate"])
    chk_pred = cbor2.loads(cbor2.loads(chk_payload)["predicate"])
    assert "partial" not in comp_pred  # omitted when False — byte-stable completed predicate
    assert chk_pred["partial"] is True


# ---- route: GET /experiments/{id}/attestation ------------------------------

from datetime import UTC, datetime  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from auspexai_platform.auth.signature import sign_request  # noqa: E402
from auspexai_platform.db.models import ExperimentStatus  # noqa: E402
from auspexai_platform.db.per_job import PerJobDatabaseFactory  # noqa: E402
from auspexai_platform.db.repositories import ResultRepository  # noqa: E402

AUTHORITY = "testserver"


def _signed_get(client, *, privkey, pubkey_hex, path):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )
    return client.get(path, headers=headers)


def _seed_consensus_unit(
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository,
    experiment_id: str,
    *,
    unit_id: str,
    payload: dict,
    worker_id: str,  # must be an enrolled worker (receipt_index FKs workers)
) -> tuple[str, str, str]:
    """Completed unit + consensus result + a receipt-index entry. Returns
    (unit_id, consensus semantic_hash, receipt_id)."""
    db = per_job_factory.get_or_create(experiment_id)
    now = datetime.now(UTC)
    db.execute(
        "INSERT OR IGNORE INTO work_units "
        "(unit_id, payload_json, status, replication_target, completions_so_far, created_at) "
        "VALUES (?, '{}', 'completed', 1, 1, ?)",
        (unit_id, now.isoformat()),
    )
    repo = ResultRepository(db)
    result = repo.insert(
        result_id=f"res-{unit_id}",
        unit_id=unit_id,
        worker_id=worker_id,
        worker_pubkey_hex="ab" * 32,
        exit_code=0,
        payload=payload,
        worker_signature="c2ln",
        completed_at=now,
    )
    repo.promote_consensus(unit_id, result.result_id)
    receipt_id = f"rcpt-{unit_id}"
    receipt_index_repository.record(
        receipt_id=receipt_id,
        experiment_id=experiment_id,
        worker_id=worker_id,
        worker_pubkey="ab" * 32,
        result_id=result.result_id,
    )
    return unit_id, result.semantic_hash, receipt_id


class TestAttestationRoute:
    def test_425_when_not_completed(self, client: TestClient, approved_experiment):
        privkey, binding, experiment, _ = approved_experiment
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/attestation",
        )
        assert resp.status_code == 425
        assert resp.json()["detail"]["error"]["code"] == "experiment_not_completed"

    def test_attestation_root_matches_recompute_and_verifies(
        self,
        client: TestClient,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
        experiment_repository,
    ):
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        e1 = _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        e2 = _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u2",
            payload={"v": 2},
            worker_id=worker.worker_id,
        )
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)

        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/attestation",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["unit_count"] == 2
        # The endpoint's root matches a local recompute from the seeded set.
        ph = unit_payload_sha256("{}")  # the seeded work-unit payload
        expected = merkle_root(
            [
                ResultSetEntry(*e1, unit_payload_sha256=ph),
                ResultSetEntry(*e2, unit_payload_sha256=ph),
            ],
            schema_version=1,
        )
        assert body["merkle_root"] == expected
        # COSE blob verifies against the coordinator's signing key.
        from base64 import b64decode

        key = client.app.state.receipt_signing_key
        payload, kid = cose_sign1_decode(
            b64decode(body["cose_b64"]), expected_pubkey=key.public_key
        )
        assert kid == key.pubkey_hex
        statement = cbor2.loads(payload)
        assert cbor2.loads(statement["predicate"])["merkle_root"] == expected
        # A completed attestation is not partial.
        assert body.get("partial") in (False, None)

    def test_checkpoint_partial_attestation_when_not_completed(
        self,
        client: TestClient,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
    ):
        """M9 leg 2: ?checkpoint=true on a still-APPROVED experiment returns a
        partial attestation over the consensus-so-far set, marked partial both in
        the response and in the COSE-signed predicate."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        e1 = _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        # experiment stays APPROVED (not completed) — the stall/partial case.
        # Sign the bare @path; checkpoint rides as an unsigned query param.
        bare = f"/api/v0/experiments/{experiment.experiment_id}/attestation"
        headers = sign_request(
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            method="GET",
            path=bare,
            authority=AUTHORITY,
            body=b"",
        )
        resp = client.get(bare, headers=headers, params={"checkpoint": "true"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["partial"] is True
        assert body["unit_count"] == 1
        assert body["merkle_root"] == merkle_root(
            [ResultSetEntry(*e1, unit_payload_sha256=unit_payload_sha256("{}"))],
            schema_version=1,
        )
        # the partial flag is in the SIGNED predicate, not just the response
        from base64 import b64decode

        key = client.app.state.receipt_signing_key
        payload, _ = cose_sign1_decode(b64decode(body["cose_b64"]), expected_pubkey=key.public_key)
        pred = cbor2.loads(cbor2.loads(payload)["predicate"])
        assert pred["partial"] is True

    def test_checkpoint_on_completed_is_not_partial(
        self,
        client: TestClient,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
        experiment_repository,
    ):
        """?checkpoint=true on an already-COMPLETED experiment is just the final
        attestation — partial reflects set-finality, not the caller's flag."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        bare = f"/api/v0/experiments/{experiment.experiment_id}/attestation"
        headers = sign_request(
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            method="GET",
            path=bare,
            authority=AUTHORITY,
            body=b"",
        )
        resp = client.get(bare, headers=headers, params={"checkpoint": "true"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["partial"] is False


# ---- A1: attestation persistence + canonicalization ------------------------

from auspexai_platform.db.database import Database  # noqa: E402
from auspexai_platform.db.repositories import (  # noqa: E402
    AttestationRepository,
    AuditRepository,
)
from auspexai_platform.db.repositories.attestations import (  # noqa: E402
    DuplicateAttestationError,
)


class TestAttestationRepository:
    """Unit tests for the control-DB attestations store (A1)."""

    def test_insert_get_final_and_duplicate_is_idempotent(self, db: Database):
        repo = AttestationRepository(db)
        rec = repo.insert(
            attestation_id="att-1",
            experiment_id="exp-A",
            tenant_id="t",
            tenant_experiment_label="label",
            merkle_root="root1",
            algorithm=RESULT_SET_ALGORITHM,
            unit_count=3,
            cose_signed_blob=b"\x01\x02\x03",
            signing_key_pubkey_hex="ab" * 32,
        )
        assert rec.partial is False
        assert rec.rekor_log_index == 0  # NoOp placeholder until A2
        assert rec.doi is None
        got = repo.get_final("exp-A")
        assert got is not None and got.attestation_id == "att-1"
        assert got.cose_signed_blob == b"\x01\x02\x03"  # BLOB round-trips as bytes

        # A second FINAL attestation for the same experiment is refused by the
        # partial-unique index — the first row stays canonical.
        with pytest.raises(DuplicateAttestationError):
            repo.insert(
                attestation_id="att-2",
                experiment_id="exp-A",
                tenant_id="t",
                tenant_experiment_label="label",
                merkle_root="root2",
                algorithm=RESULT_SET_ALGORITHM,
                unit_count=4,
                cose_signed_blob=b"\x09",
                signing_key_pubkey_hex="ab" * 32,
            )
        assert repo.get_final("exp-A").attestation_id == "att-1"

    def test_set_rekor_and_doi_and_list_unanchored(self, db: Database):
        repo = AttestationRepository(db)
        repo.insert(
            attestation_id="att-R",
            experiment_id="exp-R",
            tenant_id="t",
            tenant_experiment_label="label",
            merkle_root="root",
            algorithm=RESULT_SET_ALGORITHM,
            unit_count=1,
            cose_signed_blob=b"\x00",
            signing_key_pubkey_hex="ab" * 32,
        )
        assert any(r.attestation_id == "att-R" for r in repo.list_unanchored())
        repo.set_rekor("att-R", log_index=42, entry_uuid="uuid-42")
        repo.set_doi("att-R", "10.5281/zenodo.999")
        got = repo.get_by_id("att-R")
        assert got.rekor_log_index == 42 and got.rekor_entry_uuid == "uuid-42"
        assert got.doi == "10.5281/zenodo.999"
        # No longer un-anchored.
        assert all(r.attestation_id != "att-R" for r in repo.list_unanchored())


class TestAttestationPersistence:
    """A1: the FINAL attestation is persisted (canonical + durable), served from
    the store on COMPLETED, and persisted lazily on first GET as a backstop."""

    def test_emit_hook_persists_and_is_idempotent(
        self,
        client: TestClient,
        db: Database,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
        experiment_repository,
    ):
        from auspexai_platform.api.assignments import _maybe_emit_completion_attestation

        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        attestation_repository = AttestationRepository(db)
        kwargs = {
            "experiment_id": experiment.experiment_id,
            "per_job_db": per_job_factory.get(experiment.experiment_id),
            "experiment_repository": experiment_repository,
            "receipt_index_repository": receipt_index_repository,
            "signing_key": client.app.state.receipt_signing_key,
            "audit_repository": AuditRepository(db),
            "attestation_repository": attestation_repository,
        }
        _maybe_emit_completion_attestation(**kwargs)
        first = attestation_repository.get_final(experiment.experiment_id)
        assert first is not None and first.partial is False
        # Calling again (e.g. a late result) does NOT mint a new canonical row.
        _maybe_emit_completion_attestation(**kwargs)
        again = attestation_repository.get_final(experiment.experiment_id)
        assert again.attestation_id == first.attestation_id

    def test_route_serves_persisted_canonical_and_is_stable(
        self,
        client: TestClient,
        db: Database,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
        experiment_repository,
    ):
        """First GET on a COMPLETED experiment with no persisted row canonicalizes
        lazily; the attestation_id is then STABLE across calls (the pre-A1
        on-demand path minted a fresh id every call)."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
        )
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        path = f"/api/v0/experiments/{experiment.experiment_id}/attestation"

        r1 = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path)
        assert r1.status_code == 200, r1.text
        b1 = r1.json()

        # Lazy-persisted on that first GET.
        persisted = AttestationRepository(db).get_final(experiment.experiment_id)
        assert persisted is not None
        assert persisted.attestation_id == b1["attestation_id"]
        assert persisted.merkle_root == b1["merkle_root"]

        # Second GET serves the SAME canonical artifact (stable id + bytes).
        r2 = _signed_get(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, path=path)
        b2 = r2.json()
        assert b2["attestation_id"] == b1["attestation_id"]
        assert b2["cose_b64"] == b1["cose_b64"]
        assert b2["unit_count"] == 1 and b2["units"]  # convenience units re-derived
