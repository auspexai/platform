"""G6+F4 substrate: publication records — coordinator facts beside researcher
claims, and the benchmark-before-DOI prerequisite."""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.migrations import MigrationRunner
from auspexai_platform.db.repositories.publications import PublicationRepository


def _db(tmp_path):
    db = Database(tmp_path / "control.db")
    MigrationRunner(db).apply_all()
    return db


def test_record_roundtrip_and_doi_prereq(tmp_path):
    repo = PublicationRepository(_db(tmp_path))
    assert repo.has_benchmark_publication("exp-a") is False
    rec = repo.record(
        experiment_id="exp-a",
        kind="benchmark",
        tenant_id="vigiles-lab",
        publisher_pubkey="ab" * 32,
        standing_at_issue=2,
        summary={"peak_eu": 6.67, "breadth": 0.33, "reference_experiment_id": "exp-ref"},
        obs_merkle_root="r" * 64,
        obs_rekor_uuid="uuid-obs",
        ref_merkle_root="s" * 64,
        ref_rekor_uuid="uuid-ref",
    )
    assert rec.summary["peak_eu"] == 6.67
    assert rec.obs_rekor_uuid == "uuid-obs"  # coordinator fact rides the record
    assert repo.has_benchmark_publication("exp-a") is True
    assert repo.has_benchmark_publication("exp-b") is False
    rows = repo.list_for_experiment("exp-a")
    assert len(rows) == 1 and rows[0].kind == "benchmark"


def test_opted_in_contributors_query(tmp_path):
    # Exercise the consent-filter SQL directly (bypassing FK-bound record()):
    # only public_attribution_at_issue=1 AND non-null account_id_at_issue count,
    # distinct.
    from auspexai_platform.db.repositories.receipt_index import ReceiptIndexRepository

    db = _db(tmp_path)
    db.execute("PRAGMA foreign_keys=OFF")
    rows = [
        ("r1", "exp-a", "acct-x", 1),  # opted-in
        ("r2", "exp-a", "acct-x", 1),  # dup account → one entry
        ("r3", "exp-a", "acct-y", 1),  # opted-in
        ("r4", "exp-a", "acct-z", 0),  # opted-out → excluded
        ("r5", "exp-a", None, 1),  # anonymous/T0 → excluded
        ("r6", "exp-b", "acct-w", 1),  # other experiment → excluded
    ]
    for rid, exp, acct, pub in rows:
        db.execute(
            "INSERT INTO receipt_index (receipt_id, experiment_id, worker_id, "
            "worker_pubkey, issued_at, public_attribution_at_issue, account_id_at_issue) "
            "VALUES (?, ?, 'w', 'p', '2026-07-06T00:00:00Z', ?, ?)",
            (rid, exp, pub, acct),
        )
    got = ReceiptIndexRepository(db).opted_in_account_ids("exp-a")
    assert got == ["acct-x", "acct-y"]


def test_account_contribution_credential_signed(tmp_path):
    # F4-B5: the credential endpoint returns a coordinator-signed claim.
    # Signing round-trip is exercised via the receipts signing key in the
    # integration suite; here assert the claim canonicalization + verify shape.
    import json as _json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from auspexai_platform.api.accounts import build_router  # noqa: F401  (import-safety)
    from auspexai_platform.receipts.signing import load_or_generate_signing_key

    key = load_or_generate_signing_key(tmp_path / "k.json")
    claim = {
        "schema": "auspexai-contribution-credential/v0",
        "account_id": "acct-x",
        "trust_tier": 2,
        "research_standing": 1,
        "distinct_verified_completions": 3,
        "total_receipts": 12,
        "distinct_tenants": 2,
        "issued_at": "2026-07-06T00:00:00+00:00",
    }
    payload = _json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    sig = key.private_key.sign(payload)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.pubkey_hex)).verify(sig, payload)
