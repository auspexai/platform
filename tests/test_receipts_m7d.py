"""Tests for M7d — POST /api/v0/receipts/verify (anonymous-public).

Covers the happy path against a coordinator-issued receipt, the failure
modes (malformed base64, malformed COSE, tampered signature, wrong kid,
schema-invalid inner payload), and the trust-posture fields (mode,
authorized_signer always null pre-§5.16).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

import cbor2
from fastapi.testclient import TestClient

from auspexai_platform.config import Config
from auspexai_platform.main import create_app
from auspexai_platform.receipts import (
    QuorumAgreement,
    Receipt,
    ResultHashAnchor,
    SigningKey,
    TimeWindow,
    cose_sign1_encode,
    encode_cbor,
    load_or_generate_signing_key,
)

# ---- helpers --------------------------------------------------------------


def _sample_receipt() -> Receipt:
    return Receipt(
        version="0.1",
        tenant_id="tenant-a",
        experiment_id="doubler-v1",
        worker_pubkey=bytes(range(32)),
        work_unit_ids=["u-1"],
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


def _signed_cose_blob(signing_key: SigningKey, receipt: Receipt | None = None) -> bytes:
    """Build a real COSE-Sign1 receipt blob signed by `signing_key`."""
    return cose_sign1_encode(
        payload=encode_cbor(receipt or _sample_receipt()),
        signing_key=signing_key,
    )


# ---- happy path -----------------------------------------------------------


class TestVerifyHappyPath:
    def test_coordinator_signed_receipt_verifies(self, client: TestClient) -> None:
        """A receipt signed by the coord's own runtime key verifies against
        the coord's own /receipts/verify endpoint — the natural baseline."""
        signing_key: SigningKey = client.app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")

        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["signature_valid"] is True
        assert body["schema_valid"] is True
        assert body["signer_kid"] == signing_key.pubkey_hex
        # Default config is dev mode.
        assert body["coordinator_mode"] == "dev"
        # M7d defers AUTHORIZED_SIGNERS.md verification.
        assert "authorized_signer" not in body  # None excluded by exclude_none
        assert "Authoritative roster verification arrives" in body["authorized_signer_note"]
        # Receipt body round-trips.
        assert body["receipt"]["tenant_id"] == "tenant-a"
        assert body["receipt"]["experiment_id"] == "doubler-v1"
        assert body["receipt"]["quorum_agreement"]["agreeing_workers"] == 3

    def test_receipt_from_a_different_kid_still_verifies_if_signature_valid(
        self, tmp_path: Path, client: TestClient
    ) -> None:
        """Schema-only verification: any well-signed COSE_Sign1 with a kid
        whose pubkey verifies the signature passes. Whether the kid is
        actually on the AuspexAI roster is the §5.16 question (deferred)."""
        other_signing_key = load_or_generate_signing_key(tmp_path / "other.pem")
        cose_blob = _signed_cose_blob(other_signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")

        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["signature_valid"] is True
        assert body["schema_valid"] is True
        assert body["signer_kid"] == other_signing_key.pubkey_hex


# ---- failure modes --------------------------------------------------------


class TestVerifyFailureModes:
    def test_invalid_base64_returns_400(self, client: TestClient) -> None:
        response = client.post(
            "/api/v0/receipts/verify", json={"receipt_cose_b64": "not valid base64 !!!"}
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"]["code"] == "invalid_base64"

    def test_malformed_cose_returns_200_with_invalid(self, client: TestClient) -> None:
        # Valid base64 but the decoded bytes are not COSE_Sign1.
        b64 = base64.b64encode(b"garbage that is not cbor at all").decode("ascii")
        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200
        body = response.json()
        assert body["signature_valid"] is False
        assert body["schema_valid"] is False
        assert body.get("signer_kid") is None
        assert "errors" in body
        assert any("cose_decode" in e for e in body["errors"])

    def test_tampered_payload_signature_fails(self, client: TestClient) -> None:
        """COSE-Sign1 with valid header but tampered payload — kid is
        readable, but the signature won't verify."""
        signing_key: SigningKey = client.app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        outer = cbor2.loads(cose_blob)
        outer[2] = b"tampered_payload"
        tampered = cbor2.dumps(outer, canonical=True)
        b64 = base64.b64encode(tampered).decode("ascii")

        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200
        body = response.json()
        # Kid was still readable.
        assert body["signer_kid"] == signing_key.pubkey_hex
        # Signature verification fails.
        assert body["signature_valid"] is False
        # Schema validation also fails (tampered_payload isn't a CBOR receipt).
        assert body["schema_valid"] is False
        assert any("signature" in e for e in body["errors"])

    def test_kid_not_a_valid_pubkey_fails(self, client: TestClient) -> None:
        """Build a COSE_Sign1 with a kid that's not 64-hex-char Ed25519 pubkey.
        The verifier can't even construct a public key to check against."""
        # Manually build a COSE_Sign1 with a malformed kid.
        protected = cbor2.dumps({1: -8, 4: b"not-a-hex-pubkey"})
        payload = encode_cbor(_sample_receipt())
        # Use a real signature so cose decode doesn't fail earlier — the
        # signature won't verify anyway since the kid won't parse.
        signing_key = client.app.state.receipt_signing_key
        sig_struct = cbor2.dumps(["Signature1", protected, b"", payload])
        signature = signing_key.private_key.sign(sig_struct)
        cose_blob = cbor2.dumps([protected, {}, payload, signature])
        b64 = base64.b64encode(cose_blob).decode("ascii")

        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200
        body = response.json()
        assert body["signature_valid"] is False
        assert body["schema_valid"] is False
        assert any("kid_invalid" in e for e in body["errors"])

    def test_schema_invalid_payload(self, client: TestClient) -> None:
        """COSE-Sign1 with valid signature but inner CBOR isn't a Receipt
        (e.g., missing required fields)."""
        signing_key: SigningKey = client.app.state.receipt_signing_key
        # Build a CBOR map that's NOT a valid receipt (missing fields).
        bogus_payload = cbor2.dumps({"version": "0.1", "tenant_id": "t"}, canonical=True)
        cose_blob = cose_sign1_encode(payload=bogus_payload, signing_key=signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")

        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200
        body = response.json()
        # Signature is genuinely valid — we just signed a bogus payload.
        assert body["signature_valid"] is True
        # Schema validation fails because required fields are missing.
        assert body["schema_valid"] is False
        assert any("schema" in e for e in body["errors"])
        # No receipt body returned because schema didn't validate.
        assert body.get("receipt") is None


# ---- trust-posture fields -------------------------------------------------


class TestTrustPosture:
    def test_dev_mode_response(self, client: TestClient) -> None:
        signing_key: SigningKey = client.app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")
        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        body = response.json()
        assert body["coordinator_mode"] == "dev"

    def test_operational_mode_response(self, state_dir: Path) -> None:
        """When AUSPEXAI_RECEIPTS_MODE=operational, the response reflects that.
        Authoritative-roster check is still deferred to §5.16."""
        config = Config(state_dir=state_dir, receipts_mode="operational")
        app = create_app(config=config)
        signing_key: SigningKey = app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")

        with TestClient(app) as cl:
            response = cl.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        body = response.json()
        assert body["coordinator_mode"] == "operational"
        # M7d STILL doesn't perform the authoritative-roster check, even
        # in operational mode — that's §5.16's job.
        assert "authorized_signer" not in body  # None excluded
        assert "§5.16" in body["authorized_signer_note"]

    def test_authorized_signer_always_null_pre_section_5_16(self, client: TestClient) -> None:
        """The M7d contract: signature_valid + schema_valid are real;
        authorized_signer is null until §5.16 ships."""
        signing_key: SigningKey = client.app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")
        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        body = response.json()
        # Even on a mathematically perfect signature, authorized_signer
        # stays null because the Fulcio attestation chain doesn't exist yet.
        assert "authorized_signer" not in body  # excluded because None
        assert "AUTHORIZED_SIGNERS" in body["authorized_signer_note"]


# ---- anonymous-public access ----------------------------------------------


class TestAnonymousAccess:
    def test_no_credentials_required(self, client: TestClient) -> None:
        """The endpoint is anonymous-public — no Authorization header, no
        RFC 9421 signature."""
        signing_key: SigningKey = client.app.state.receipt_signing_key
        cose_blob = _signed_cose_blob(signing_key)
        b64 = base64.b64encode(cose_blob).decode("ascii")
        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200
        body = response.json()
        assert body["signature_valid"] is True


# ---- end-to-end integration: coord-issued receipt → verified --------------


class TestEndToEndVerification:
    """A coord-issued receipt (M7c) can be verified by the M7d endpoint.
    This is the dogfooding test — the bytes the coord produces in
    submit_result are the bytes the verifier accepts."""

    def test_issued_receipt_verifies(self, client: TestClient, tmp_path: Path) -> None:
        # Use the existing M7c issuance flow's in-memory fixtures to
        # produce a real coord-signed receipt.
        from auspexai_platform.db.models import (
            Experiment,
            ExperimentStatus,
            Result,
            WorkUnit,
            WorkUnitStatus,
        )
        from auspexai_platform.db.per_job import PerJobDatabaseFactory
        from auspexai_platform.receipts import (
            ReceiptRepository,
            issue_receipts_for_completed_unit,
        )

        signing_key: SigningKey = client.app.state.receipt_signing_key
        factory = PerJobDatabaseFactory(tmp_path / "jobs")
        per_job_db = factory.get_or_create("exp-e2e")
        receipt_repo = ReceiptRepository(per_job_db)

        experiment = Experiment(
            experiment_id="exp-e2e",
            tenant_id="tenant-x",
            tenant_experiment_label="end-to-end",
            manifest_hash="0" * 64,
            status=ExperimentStatus.APPROVED,
            submitted_at=datetime(2026, 5, 22, 8, 0, tzinfo=UTC),
            revision=1,
        )
        work_unit = WorkUnit(
            unit_id="u-1",
            payload={"input": 1},
            status=WorkUnitStatus.COMPLETED,
            replication_target=3,
            completions_so_far=3,
            created_at=datetime(2026, 5, 22, 9, 0, tzinfo=UTC),
        )
        results = [
            Result(
                result_id=f"r-{i}",
                unit_id="u-1",
                worker_id=f"wkr-{i}",
                worker_pubkey_hex=f"{i:02x}" * 32,
                exit_code=0,
                payload={"answer": 42},
                worker_signature="sig",
                completed_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
                received_at=datetime(2026, 5, 22, 10, 0, 1, tzinfo=UTC),
            )
            for i in range(3)
        ]
        outcome = issue_receipts_for_completed_unit(
            work_unit=work_unit,
            experiment=experiment,
            results=results,
            receipt_repo=receipt_repo,
            signing_key=signing_key,
        )
        assert outcome.agreement.agreed is True
        assert len(outcome.issued_receipt_ids) == 3

        # Take one of the issued receipts, base64-encode, and POST to verify.
        records = receipt_repo.list_all()
        b64 = base64.b64encode(records[0].cose_signed_blob).decode("ascii")
        response = client.post("/api/v0/receipts/verify", json={"receipt_cose_b64": b64})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["signature_valid"] is True
        assert body["schema_valid"] is True
        assert body["signer_kid"] == signing_key.pubkey_hex
        assert body["receipt"]["tenant_id"] == "tenant-x"
        assert body["receipt"]["experiment_id"] == "end-to-end"
        assert body["receipt"]["quorum_agreement"]["agreeing_workers"] == 3
