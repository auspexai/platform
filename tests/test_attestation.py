"""Result-set completion attestation (#34 §6.3) — merkle root + COSE/in-toto build."""

from __future__ import annotations

from pathlib import Path

import cbor2
import pytest

from auspexai_platform.receipts.attestation import (
    INTEGRITY_BASIS_DIVERGED,
    INTEGRITY_BASIS_EXACT,
    INTEGRITY_BASIS_PROCESS_ONLY,
    INTEGRITY_BASIS_TOLERANCE,
    RESULT_SET_ALGORITHM,
    RESULT_SET_ALGORITHM_V1,
    DivergedUnitEntry,
    ResultSetEntry,
    build_result_set_attestation,
    classify_consensus_basis,
    collect_diverged_units,
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


def test_classify_consensus_basis():
    """Firewall #1: >=2 corroborating replicas → exact; repl-1 → process_only
    (a worker cannot corroborate itself, D3)."""
    assert classify_consensus_basis(3) == INTEGRITY_BASIS_EXACT
    assert classify_consensus_basis(2) == INTEGRITY_BASIS_EXACT
    assert classify_consensus_basis(1) == INTEGRITY_BASIS_PROCESS_ONLY
    assert classify_consensus_basis(0) == INTEGRITY_BASIS_PROCESS_ONLY


def test_classify_consensus_basis_tolerance():
    """C7 Inc 2: a tolerance unit with >=2 agreeing replicas is within_cell_tolerance
    (agreed within the envelope, NOT byte-exact); a single replica is still
    process_only regardless of method (no peer to corroborate)."""
    tol = "builtin_within_cell_tolerance"
    hashm = "builtin_hash_agreement"
    assert classify_consensus_basis(3, tol) == INTEGRITY_BASIS_TOLERANCE
    assert classify_consensus_basis(2, tol) == INTEGRITY_BASIS_TOLERANCE
    assert classify_consensus_basis(1, tol) == INTEGRITY_BASIS_PROCESS_ONLY
    # exact reducer keeps the exact basis; the default (no method) is exact-or-process
    assert classify_consensus_basis(2, hashm) == INTEGRITY_BASIS_EXACT
    assert classify_consensus_basis(2) == INTEGRITY_BASIS_EXACT


def test_integrity_basis_rides_predicate_not_leaf(tmp_path: Path):
    """The per-unit integrity_basis is coordinator-asserted predicate metadata:
    it appears in the signed predicate units but does NOT change the Merkle root
    (leaf-bound fields are unchanged), so a verifier's root recompute is stable."""
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    bare = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32)]
    tagged = [
        ResultSetEntry(
            "u1",
            "h1",
            "r1",
            unit_payload_sha256="aa" * 32,
            integrity_basis=INTEGRITY_BASIS_EXACT,
        )
    ]
    # root identical — integrity_basis is not leaf-bound
    assert merkle_root(bare, schema_version=1) == merkle_root(tagged, schema_version=1)

    att = build_result_set_attestation(
        attestation_id="att-basis",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=tagged,
        signing_key=key,
    )
    assert att.merkle_root == merkle_root(bare, schema_version=1)
    payload, _ = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    body = cbor2.loads(cbor2.loads(payload)["predicate"])
    assert body["units"][0]["integrity_basis"] == INTEGRITY_BASIS_EXACT


def test_diverged_units_ride_predicate_without_touching_root(tmp_path: Path):
    """Firewall #1 G4: diverged units appear in the signed predicate but never in
    the Merkle set — the root over the agreed entries is unchanged, divergence is
    recorded alongside, never adjudicated."""
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32)]
    diverged = [
        DivergedUnitEntry(unit_id="u2", unit_payload_sha256="bb" * 32, result_hashes=["c0", "c1"])
    ]
    att = build_result_set_attestation(
        attestation_id="att-div",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
        diverged_units=diverged,
    )
    # root is over `entries` only — diverged units do not move it
    assert att.merkle_root == merkle_root(entries, schema_version=1)
    assert att.unit_count == 1
    payload, _ = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    body = cbor2.loads(cbor2.loads(payload)["predicate"])
    assert [u["unit_id"] for u in body["units"]] == ["u1"]  # agreed set only
    assert len(body["diverged_units"]) == 1
    d = body["diverged_units"][0]
    assert d["unit_id"] == "u2"
    assert d["integrity_basis"] == INTEGRITY_BASIS_DIVERGED
    assert d["result_hashes"] == ["c0", "c1"]


def test_empty_diverged_units_omits_predicate_key(tmp_path: Path):
    """An all-agreeing run's predicate stays byte-identical to the pre-firewall
    format — the diverged_units key is omitted entirely, not emitted empty."""
    key = load_or_generate_signing_key(tmp_path / "sign.key")
    entries = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32)]
    att = build_result_set_attestation(
        attestation_id="att-none",
        tenant_experiment_label="exp-label",
        tenant_id="tenant-a",
        entries=entries,
        signing_key=key,
        diverged_units=[],
    )
    payload, _ = cose_sign1_decode(att.cose_signed_blob, expected_pubkey=key.public_key)
    body = cbor2.loads(cbor2.loads(payload)["predicate"])
    assert "diverged_units" not in body


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
    c = [ResultSetEntry("u1", "h1", "r1", unit_payload_sha256="aa" * 32, environment={"x": 1})]
    assert merkle_root(a, schema_version=1) == merkle_root(c, schema_version=1)


def test_unit_payload_sha256_is_canonical():
    """The input-hash convention is over the canonical re-serialization, so
    storage formatting differences don't change the hash."""
    assert unit_payload_sha256('{"b": 1, "a": 2}') == unit_payload_sha256('{"a":2,"b":1}')


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


def insert_per_job_receipt(
    db,
    *,
    receipt_id: str,
    unit_id: str,
    worker_pubkey_hex: str = "ab" * 32,
    agreeing_workers: int = 1,
    method: str = "hash-equality",
) -> None:
    """Seed the AUTHORITATIVE per-job receipt row. Since the 2026-06-12
    signature-scope fix, attestation/bundle membership is derived from the
    per-job receipts ⨝ results join — the receipt_index is display-only."""
    import json as _json

    from auspexai_platform.receipts.models import (
        QuorumAgreement,
        Receipt,
        ResultHashAnchor,
        TimeWindow,
        encode_cbor,
    )

    now = datetime.now(UTC)
    body = encode_cbor(
        Receipt(
            version="0.1",
            tenant_id="tenant-x",
            experiment_id="label-x",
            worker_pubkey=bytes.fromhex(worker_pubkey_hex),
            work_unit_ids=[unit_id],
            time_window=TimeWindow(start=now, end=now),
            quorum_agreement=QuorumAgreement(
                replication_factor=agreeing_workers,
                agreeing_workers=agreeing_workers,
                method=method,
            ),
            result_hash_anchors=[
                ResultHashAnchor(
                    rekor_log_index=0,
                    rekor_entry_uuid="lab-mode-no-rekor",
                    result_sha256="00" * 32,
                )
            ],
        )
    )
    db.execute(
        "INSERT INTO receipts (receipt_id, work_unit_ids_json, cose_signed_blob, "
        "receipt_body_cbor, signing_key_pubkey_hex, issued_at) VALUES (?, ?, ?, ?, ?, ?)",
        (receipt_id, _json.dumps([unit_id]), b"\x00", body, "aa" * 32, now.isoformat()),
    )


def _seed_consensus_unit(
    per_job_factory: PerJobDatabaseFactory,
    receipt_index_repository,
    experiment_id: str,
    *,
    unit_id: str,
    payload: dict,
    worker_id: str,  # must be an enrolled worker (receipt_index FKs workers)
    replication_target: int = 1,
    method: str = "hash-equality",
) -> tuple[str, str, str]:
    """Completed unit + consensus result + the authoritative per-job receipt
    row + a receipt-index entry. Returns (unit_id, consensus semantic_hash,
    receipt_id)."""
    db = per_job_factory.get_or_create(experiment_id)
    now = datetime.now(UTC)
    db.execute(
        "INSERT OR IGNORE INTO work_units "
        "(unit_id, payload_json, status, replication_target, completions_so_far, created_at) "
        "VALUES (?, '{}', 'completed', ?, ?, ?)",
        (unit_id, replication_target, replication_target, now.isoformat()),
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
    insert_per_job_receipt(
        db,
        receipt_id=receipt_id,
        unit_id=unit_id,
        agreeing_workers=replication_target,
        method=method,
    )
    receipt_index_repository.record(
        receipt_id=receipt_id,
        experiment_id=experiment_id,
        worker_id=worker_id,
        worker_pubkey="ab" * 32,
        result_id=result.result_id,
    )
    return unit_id, result.semantic_hash, receipt_id


def _seed_diverged_unit(
    per_job_factory: PerJobDatabaseFactory,
    experiment_id: str,
    *,
    unit_id: str,
    worker_ids: list[str],
) -> None:
    """A completed unit whose replicas DISAGREED: distinct-payload results
    inserted, but NO consensus promotion and NO receipt (the reducer's
    disagreement branch). This is the state collect_diverged_units detects."""
    db = per_job_factory.get_or_create(experiment_id)
    now = datetime.now(UTC)
    db.execute(
        "INSERT OR IGNORE INTO work_units "
        "(unit_id, payload_json, status, replication_target, completions_so_far, created_at) "
        "VALUES (?, '{}', 'completed', ?, ?, ?)",
        (unit_id, len(worker_ids), len(worker_ids), now.isoformat()),
    )
    repo = ResultRepository(db)
    for i, wid in enumerate(worker_ids):
        repo.insert(
            result_id=f"res-{unit_id}-{i}",
            unit_id=unit_id,
            worker_id=wid,
            worker_pubkey_hex=f"{i:02x}" * 32,
            exit_code=0,
            payload={"v": i},  # distinct payloads → distinct semantic_hash → disagree
            worker_signature="c2ln",
            completed_at=now,
        )
    # deliberately: no promote_consensus, no receipt


class TestDivergedUnits:
    def test_collect_diverged_excludes_consensus(
        self, approved_experiment, enrolled_worker, per_job_factory, receipt_index_repository
    ):
        """Firewall #1 G4: a disagreed unit is collected as diverged; an agreeing
        unit (consensus + receipt) is NOT — divergence ≠ consensus."""
        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u_agree",
            payload={"v": 1},
            worker_id=worker.worker_id,
            replication_target=2,
        )
        _seed_diverged_unit(
            per_job_factory,
            experiment.experiment_id,
            unit_id="u_div",
            worker_ids=["w-a", "w-b"],
        )
        per_job_db = per_job_factory.get(experiment.experiment_id)
        diverged = collect_diverged_units(per_job_db)
        assert [d.unit_id for d in diverged] == ["u_div"]
        assert diverged[0].integrity_basis == INTEGRITY_BASIS_DIVERGED
        assert len(diverged[0].result_hashes) == 2  # two distinct hashes recorded


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

    def test_collect_classifies_integrity_basis_by_replication(
        self,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
    ):
        """Firewall #1: collect_result_set_entries tags each consensus unit's
        integrity_basis from its receipt's agreeing_workers (seeded here = replication_target,
        but it is the achieved consensus count under C14 regime-2) — >=2 → exact, repl-1 →
        process_only — straight onto the entries the predicate carries."""
        from auspexai_platform.receipts.attestation import (
            collect_result_set_entries,
            receipt_map_from_per_job,
        )

        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u_exact",
            payload={"v": 1},
            worker_id=worker.worker_id,
            replication_target=3,
        )
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u_solo",
            payload={"v": 2},
            worker_id=worker.worker_id,
            replication_target=1,
        )
        per_job_db = per_job_factory.get(experiment.experiment_id)
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=receipt_map_from_per_job(per_job_db)
        )
        basis = {e.unit_id: e.integrity_basis for e in entries}
        assert basis["u_exact"] == INTEGRITY_BASIS_EXACT
        assert basis["u_solo"] == INTEGRITY_BASIS_PROCESS_ONLY

    def test_collect_classifies_tolerance_basis(
        self,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
    ):
        """C7 Inc 2: a unit reduced under within_cell_tolerance (>=2 agreeing) attests as
        within_cell_tolerance, NOT within_cell_exact — the basis reads the receipt's
        quorum_agreement.method, so the attestation never overclaims byte-exact agreement.
        A single tolerance replica is still process_only (no peer to corroborate)."""
        from auspexai_platform.receipts.attestation import (
            collect_result_set_entries,
            receipt_map_from_per_job,
        )

        _, _, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        for unit_id, target in (("u_tol", 2), ("u_tol_solo", 1)):
            _seed_consensus_unit(
                per_job_factory,
                receipt_index_repository,
                experiment.experiment_id,
                unit_id=unit_id,
                payload={"v": unit_id},
                worker_id=worker.worker_id,
                replication_target=target,
                method="builtin_within_cell_tolerance",
            )
        per_job_db = per_job_factory.get(experiment.experiment_id)
        entries = collect_result_set_entries(
            per_job_db, receipt_id_by_result=receipt_map_from_per_job(per_job_db)
        )
        basis = {e.unit_id: e.integrity_basis for e in entries}
        assert basis["u_tol"] == INTEGRITY_BASIS_TOLERANCE
        assert basis["u_tol_solo"] == INTEGRITY_BASIS_PROCESS_ONLY

    def test_governance_footprint_in_signed_predicate(
        self,
        client: TestClient,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
        experiment_repository,
    ):
        """Firewall #2 end-to-end: the attestation route's signed predicate carries
        a governance_footprint whose recomputable integrity_basis counts match the
        attested set (the main.py builder + the sign-time F6 guard are wired)."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
            replication_target=2,
        )
        experiment_repository.update_status(experiment.experiment_id, ExperimentStatus.COMPLETED)
        resp = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/attestation",
        )
        assert resp.status_code == 200, resp.text
        # Firewall #2 researcher surface: the footprint is echoed in the RESPONSE
        # (so the verbatim dashboard proxy carries it without a COSE decode)...
        resp_fp = resp.json()["governance_footprint"]
        assert resp_fp["schema_version"] == 1
        assert resp_fp["integrity_basis"]["counts"]["within_cell_exact"] == 1
        # ...and equals the authoritative signed predicate.
        from base64 import b64decode

        key = client.app.state.receipt_signing_key
        payload, _ = cose_sign1_decode(
            b64decode(resp.json()["cose_b64"]), expected_pubkey=key.public_key
        )
        fp = cbor2.loads(cbor2.loads(payload)["predicate"])["governance_footprint"]
        assert fp == resp_fp
        assert fp["schema_version"] == 1
        assert fp["tenant"]["tier"].startswith("T")
        assert "integrity_policy" in fp["replication"]
        assert fp["approval"]["experiment"] in ("auto", "human")
        assert fp["independence"]["basis"] == "account-level"
        # one repl-2 consensus unit → exactly one within_cell_exact, no diverged
        assert fp["integrity_basis"]["counts"]["within_cell_exact"] == 1
        assert fp["integrity_basis"]["counts"]["diverged"] == 0

    def test_finalize_path_persists_governance_footprint(
        self,
        client: TestClient,
        approved_experiment,
        enrolled_worker,
        per_job_factory: PerJobDatabaseFactory,
        receipt_index_repository,
    ):
        """Regression (live D6 run, 2026-06-14): the finalize-submissions emit path
        — not just the on-demand route — must persist the governance_footprint.
        finalize → auto-complete → emit-on-complete via the EXPERIMENTS router."""
        privkey, binding, experiment, _ = approved_experiment
        _, worker = enrolled_worker
        _seed_consensus_unit(
            per_job_factory,
            receipt_index_repository,
            experiment.experiment_id,
            unit_id="u1",
            payload={"v": 1},
            worker_id=worker.worker_id,
            replication_target=2,
        )
        path = f"/api/v0/experiments/{experiment.experiment_id}/actions/finalize-submissions"
        headers = sign_request(
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            method="POST",
            path=path,
            authority=AUTHORITY,
            body=b"",
        )
        resp = client.post(path, headers=headers)
        assert resp.status_code == 200, resp.text
        # The now-PERSISTED attestation (served by the on-demand GET) MUST carry the
        # footprint — the bug was the finalize emit dropping it.
        att = _signed_get(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            path=f"/api/v0/experiments/{experiment.experiment_id}/attestation",
        ).json()
        assert att.get("governance_footprint") is not None, (
            "finalize-path attestation lacks footprint"
        )
        assert att["governance_footprint"]["integrity_basis"]["counts"]["within_cell_exact"] == 1

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
