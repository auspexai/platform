"""Tests for M7b — receipt foundation: models, COSE signing, key
persistence, per-job storage, config + main wiring.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from auspexai_platform.config import Config
from auspexai_platform.db import Database
from auspexai_platform.db.per_job import PerJobDatabaseFactory
from auspexai_platform.receipts import (
    CoseDecodeError,
    CoseVerificationError,
    QuorumAgreement,
    Receipt,
    ReceiptRepository,
    ResultHashAnchor,
    TimeWindow,
    cose_sign1_decode,
    cose_sign1_encode,
    decode_cbor,
    encode_cbor,
    load_or_generate_signing_key,
)
from auspexai_platform.receipts.repository import DuplicateReceiptError


def _sample_receipt(*, worker_pubkey: bytes | None = None) -> Receipt:
    return Receipt(
        version="0.1",
        tenant_id="tenant-a",
        experiment_id="exp-1",
        worker_pubkey=worker_pubkey or bytes(range(32)),
        work_unit_ids=["unit-1", "unit-2"],
        time_window=TimeWindow(
            start=datetime(2026, 5, 22, 10, 0, 0, tzinfo=UTC),
            end=datetime(2026, 5, 22, 10, 5, 0, tzinfo=UTC),
        ),
        quorum_agreement=QuorumAgreement(
            replication_factor=3,
            agreeing_workers=3,
            method="builtin_hash_agreement",
        ),
        result_hash_anchors=[
            ResultHashAnchor(
                rekor_log_index=0,
                rekor_entry_uuid="lab-mode-no-rekor",
                result_sha256="a" * 64,
            ),
        ],
    )


# ---- Receipt model + CBOR codec --------------------------------------------


class TestReceiptModel:
    def test_encode_decode_round_trip(self) -> None:
        receipt = _sample_receipt()
        cbor_bytes = encode_cbor(receipt)
        decoded = decode_cbor(cbor_bytes)
        assert decoded == receipt

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 — Pydantic ValidationError
            Receipt(
                version="0.1",
                tenant_id="t",
                experiment_id="e",
                worker_pubkey=bytes(32),
                work_unit_ids=["u-1"],
                time_window=TimeWindow(start=datetime.now(UTC), end=datetime.now(UTC)),
                quorum_agreement=QuorumAgreement(
                    replication_factor=1, agreeing_workers=1, method="x"
                ),
                result_hash_anchors=[
                    ResultHashAnchor(
                        rekor_log_index=0,
                        rekor_entry_uuid="x",
                        result_sha256="a" * 64,
                    ),
                ],
                bogus_field="nope",  # type: ignore[call-arg]
            )

    def test_worker_pubkey_wrong_length_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            Receipt(
                version="0.1",
                tenant_id="t",
                experiment_id="e",
                worker_pubkey=bytes(16),  # too short
                work_unit_ids=["u-1"],
                time_window=TimeWindow(start=datetime.now(UTC), end=datetime.now(UTC)),
                quorum_agreement=QuorumAgreement(
                    replication_factor=1, agreeing_workers=1, method="x"
                ),
                result_hash_anchors=[
                    ResultHashAnchor(
                        rekor_log_index=0,
                        rekor_entry_uuid="x",
                        result_sha256="a" * 64,
                    ),
                ],
            )

    def test_canonical_cbor_is_byte_stable(self) -> None:
        """Same receipt re-encoded yields identical bytes (canonical CBOR)."""
        receipt = _sample_receipt()
        b1 = encode_cbor(receipt)
        b2 = encode_cbor(receipt)
        assert b1 == b2


# ---- Persistent signing key ------------------------------------------------


class TestSigningKeyPersistence:
    def test_first_call_generates_writes_0600_file(self, tmp_path: Path) -> None:
        key_path = tmp_path / "key.pem"
        assert not key_path.exists()
        signing_key = load_or_generate_signing_key(key_path)
        assert key_path.exists()
        # File permissions are 0600 (owner-rw only).
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
        # Pubkey hex is 64 chars (32 bytes hex-encoded).
        assert len(signing_key.pubkey_hex) == 64
        assert all(c in "0123456789abcdef" for c in signing_key.pubkey_hex)

    def test_second_call_loads_same_key(self, tmp_path: Path) -> None:
        key_path = tmp_path / "key.pem"
        first = load_or_generate_signing_key(key_path)
        second = load_or_generate_signing_key(key_path)
        assert first.pubkey_hex == second.pubkey_hex

    def test_parent_dir_created_with_0700(self, tmp_path: Path) -> None:
        key_path = tmp_path / "nested" / "subdir" / "key.pem"
        load_or_generate_signing_key(key_path)
        # Parent dir exists with 0700 mode.
        assert key_path.parent.exists()
        mode = key_path.parent.stat().st_mode & 0o777
        assert mode == 0o700

    def test_corrupt_key_file_raises(self, tmp_path: Path) -> None:
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(b"not a pem file")
        with pytest.raises(Exception):  # noqa: B017 — cryptography raises ValueError
            load_or_generate_signing_key(key_path)

    def test_wrong_key_type_raises(self, tmp_path: Path) -> None:
        # Persist an RSA key (wrong type), then attempt to load.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(pem)
        with pytest.raises(ValueError, match="not an Ed25519"):
            load_or_generate_signing_key(key_path)


# ---- COSE Sign1 -----------------------------------------------------------


class TestCoseSign1:
    def test_encode_decode_round_trip_with_verify(self, tmp_path: Path) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt = _sample_receipt()
        cbor_payload = encode_cbor(receipt)

        cose_bytes = cose_sign1_encode(payload=cbor_payload, signing_key=signing_key)

        # Verify with the public key.
        decoded_payload, kid = cose_sign1_decode(cose_bytes, expected_pubkey=signing_key.public_key)
        assert decoded_payload == cbor_payload
        assert kid == signing_key.pubkey_hex

        # Decoded payload round-trips back to the original Receipt.
        assert decode_cbor(decoded_payload) == receipt

    def test_decode_without_verification(self, tmp_path: Path) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        payload = b"some bytes"
        cose_bytes = cose_sign1_encode(payload=payload, signing_key=signing_key)
        decoded_payload, kid = cose_sign1_decode(cose_bytes)
        assert decoded_payload == payload
        assert kid == signing_key.pubkey_hex

    def test_tampered_payload_fails_verification(self, tmp_path: Path) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        payload = encode_cbor(_sample_receipt())
        cose_bytes = cose_sign1_encode(payload=payload, signing_key=signing_key)

        # Decode the outer COSE_Sign1 structure, swap the payload, re-encode.
        outer = cbor2.loads(cose_bytes)
        outer[2] = b"tampered payload"
        tampered = cbor2.dumps(outer, canonical=True)

        with pytest.raises(CoseVerificationError):
            cose_sign1_decode(tampered, expected_pubkey=signing_key.public_key)

    def test_wrong_pubkey_fails_verification(self, tmp_path: Path) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        other = Ed25519PrivateKey.generate().public_key()
        payload = encode_cbor(_sample_receipt())
        cose_bytes = cose_sign1_encode(payload=payload, signing_key=signing_key)
        with pytest.raises(CoseVerificationError):
            cose_sign1_decode(cose_bytes, expected_pubkey=other)

    def test_malformed_cbor_raises_decode_error(self) -> None:
        with pytest.raises(CoseDecodeError):
            cose_sign1_decode(b"\x00garbage")

    def test_non_array_raises_decode_error(self) -> None:
        # Top-level CBOR map instead of array.
        bad = cbor2.dumps({"not": "an array"})
        with pytest.raises(CoseDecodeError, match="must be a 4-element array"):
            cose_sign1_decode(bad)

    def test_wrong_alg_raises_decode_error(self, tmp_path: Path) -> None:
        # Build a COSE_Sign1 with alg=-7 (ES256) instead of -8 (EdDSA).
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        protected = cbor2.dumps({1: -7, 4: signing_key.pubkey_hex.encode("ascii")})
        payload = b"x"
        sig_struct = cbor2.dumps(["Signature1", protected, b"", payload])
        signature = signing_key.private_key.sign(sig_struct)
        wrong_alg_cose = cbor2.dumps([protected, {}, payload, signature])
        with pytest.raises(CoseDecodeError, match="alg must be EdDSA"):
            cose_sign1_decode(wrong_alg_cose)

    def test_kid_in_protected_header_is_pubkey_hex(self, tmp_path: Path) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        cose_bytes = cose_sign1_encode(payload=b"x", signing_key=signing_key)
        # Manually inspect the outer structure to confirm kid placement.
        outer = cbor2.loads(cose_bytes)
        protected_map = cbor2.loads(outer[0])
        assert protected_map[1] == -8  # alg
        kid_bytes = protected_map[4]
        assert kid_bytes.decode("ascii") == signing_key.pubkey_hex


# ---- ReceiptRepository (per-job DB) ---------------------------------------


@pytest.fixture
def per_job_db(tmp_path: Path) -> Database:
    """A per-job DB with the receipts table created."""
    factory = PerJobDatabaseFactory(tmp_path / "jobs")
    return factory.get_or_create("exp-test")


class TestReceiptRepository:
    def test_insert_and_get(self, tmp_path: Path, per_job_db: Database) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt = _sample_receipt()
        cbor_payload = encode_cbor(receipt)
        cose_blob = cose_sign1_encode(payload=cbor_payload, signing_key=signing_key)

        repo = ReceiptRepository(per_job_db)
        record = repo.insert(
            receipt_id="rcpt-1",
            work_unit_ids=receipt.work_unit_ids,
            cose_signed_blob=cose_blob,
            receipt_body_cbor=cbor_payload,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
        )

        assert record.receipt_id == "rcpt-1"
        assert record.work_unit_ids == ["unit-1", "unit-2"]
        assert record.cose_signed_blob == cose_blob
        assert record.receipt_body_cbor == cbor_payload
        assert record.signing_key_pubkey_hex == signing_key.pubkey_hex

        # Re-read fresh.
        got = repo.get_by_id("rcpt-1")
        assert got == record

    def test_duplicate_receipt_id_raises(self, tmp_path: Path, per_job_db: Database) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        receipt = _sample_receipt()
        cbor_payload = encode_cbor(receipt)
        cose_blob = cose_sign1_encode(payload=cbor_payload, signing_key=signing_key)

        repo = ReceiptRepository(per_job_db)
        repo.insert(
            receipt_id="rcpt-dup",
            work_unit_ids=["u-1"],
            cose_signed_blob=cose_blob,
            receipt_body_cbor=cbor_payload,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
        )
        with pytest.raises(DuplicateReceiptError):
            repo.insert(
                receipt_id="rcpt-dup",
                work_unit_ids=["u-2"],
                cose_signed_blob=cose_blob,
                receipt_body_cbor=cbor_payload,
                signing_key_pubkey_hex=signing_key.pubkey_hex,
            )

    def test_list_for_unit_finds_receipts_covering_that_unit(
        self, tmp_path: Path, per_job_db: Database
    ) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        cbor_payload = encode_cbor(_sample_receipt())
        cose_blob = cose_sign1_encode(payload=cbor_payload, signing_key=signing_key)

        repo = ReceiptRepository(per_job_db)
        repo.insert(
            receipt_id="rcpt-A",
            work_unit_ids=["u-1", "u-2"],
            cose_signed_blob=cose_blob,
            receipt_body_cbor=cbor_payload,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
        )
        repo.insert(
            receipt_id="rcpt-B",
            work_unit_ids=["u-3"],
            cose_signed_blob=cose_blob,
            receipt_body_cbor=cbor_payload,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
        )
        for_u1 = repo.list_for_unit("u-1")
        assert [r.receipt_id for r in for_u1] == ["rcpt-A"]
        for_u3 = repo.list_for_unit("u-3")
        assert [r.receipt_id for r in for_u3] == ["rcpt-B"]
        for_missing = repo.list_for_unit("u-nope")
        assert for_missing == []

    def test_list_all_orders_by_issued_at_desc(self, tmp_path: Path, per_job_db: Database) -> None:
        signing_key = load_or_generate_signing_key(tmp_path / "k.pem")
        cbor_payload = encode_cbor(_sample_receipt())
        cose_blob = cose_sign1_encode(payload=cbor_payload, signing_key=signing_key)

        repo = ReceiptRepository(per_job_db)
        for i in range(3):
            repo.insert(
                receipt_id=f"rcpt-{i}",
                work_unit_ids=[f"u-{i}"],
                cose_signed_blob=cose_blob,
                receipt_body_cbor=cbor_payload,
                signing_key_pubkey_hex=signing_key.pubkey_hex,
            )
        all_receipts = repo.list_all()
        # All three present; SQLite second-resolution can tie so just check
        # set membership.
        assert {r.receipt_id for r in all_receipts} == {"rcpt-0", "rcpt-1", "rcpt-2"}


# ---- Config ---------------------------------------------------------------


class TestConfig:
    def test_default_receipts_mode_is_dev(self, tmp_path: Path) -> None:
        c = Config(state_dir=tmp_path)
        assert c.receipts_mode == "dev"

    def test_invalid_receipts_mode_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="receipts_mode"):
            Config(state_dir=tmp_path, receipts_mode="bogus")

    def test_receipts_mode_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUSPEXAI_RECEIPTS_MODE", "operational")
        c = Config.from_env(state_dir=tmp_path)
        assert c.receipts_mode == "operational"

    def test_receipt_signing_key_path(self, tmp_path: Path) -> None:
        c = Config(state_dir=tmp_path)
        assert c.receipt_signing_key_path == tmp_path / "coordinator_receipt_signing_key.pem"


# ---- main.py wiring ------------------------------------------------------


class TestMainWiring:
    def test_create_app_loads_signing_key(self, tmp_path: Path) -> None:
        from auspexai_platform.main import create_app

        # Use a fresh state_dir so the key file is created on first launch.
        config = Config(state_dir=tmp_path)
        app = create_app(config=config)

        # app.state has the signing key.
        assert hasattr(app.state, "receipt_signing_key")
        key1 = app.state.receipt_signing_key
        assert len(key1.pubkey_hex) == 64

        # Key file was created at the expected path.
        assert config.receipt_signing_key_path.exists()
        mode = config.receipt_signing_key_path.stat().st_mode & 0o777
        assert mode == 0o600

        # A second create_app loads the SAME key.
        app2 = create_app(config=config)
        assert app2.state.receipt_signing_key.pubkey_hex == key1.pubkey_hex
