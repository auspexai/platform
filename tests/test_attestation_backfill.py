"""A2: Rekor backfill sweep — anchor persisted attestations out-of-band."""

from __future__ import annotations

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories import AttestationRepository
from auspexai_platform.receipts.attestation_backfill import backfill_rekor_anchors
from auspexai_platform.receipts.rekor import (
    REKOR_PLACEHOLDER_UUID,
    NoOpRekorClient,
    RekorEntry,
)


class _FakeRekor:
    """Returns real-looking entries; counts calls."""

    def __init__(self) -> None:
        self.calls = 0

    def record(self, cose_blob: bytes) -> RekorEntry:
        self.calls += 1
        return RekorEntry(log_index=1000 + self.calls, entry_uuid=f"uuid-{self.calls}")


class _RaisesOnceRekor:
    """Raises on the first call, then succeeds — models a transient Rekor hiccup."""

    def __init__(self) -> None:
        self.calls = 0

    def record(self, cose_blob: bytes) -> RekorEntry:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("rekor unreachable")
        return RekorEntry(log_index=2000 + self.calls, entry_uuid=f"uuid-{self.calls}")


def test_placeholder_sentinels_agree():
    """The db-layer sentinel (queried in list_unanchored / column default) must
    equal the receipts-layer one the NoOpRekorClient emits — they live in two
    modules to avoid a circular import."""
    from auspexai_platform.db.repositories.attestations import (
        REKOR_PLACEHOLDER_UUID as DB_SENTINEL,
    )

    assert DB_SENTINEL == REKOR_PLACEHOLDER_UUID


def _insert(repo: AttestationRepository, attestation_id: str, experiment_id: str):
    return repo.insert(
        attestation_id=attestation_id,
        experiment_id=experiment_id,
        tenant_id="t",
        tenant_experiment_label="label",
        merkle_root="root",
        algorithm="alg",
        unit_count=1,
        cose_signed_blob=b"\x01\x02",
        signing_key_pubkey_hex="ab" * 32,
    )


def test_backfill_anchors_and_is_idempotent(db: Database):
    repo = AttestationRepository(db)
    _insert(repo, "att-1", "exp-1")
    _insert(repo, "att-2", "exp-2")
    client = _FakeRekor()

    report = backfill_rekor_anchors(db, rekor_client=client, apply=True)
    assert report.candidates == 2
    assert sorted(report.anchored) == ["att-1", "att-2"]
    assert not report.failed
    # Both rows now carry the real anchor.
    a1 = repo.get_by_id("att-1")
    assert a1.rekor_log_index >= 1000 and a1.rekor_entry_uuid != REKOR_PLACEHOLDER_UUID
    assert repo.list_unanchored() == []

    # Re-running finds nothing left to anchor (idempotent) and makes no calls.
    again = _FakeRekor()
    report2 = backfill_rekor_anchors(db, rekor_client=again, apply=True)
    assert report2.candidates == 0 and report2.anchored == []
    assert again.calls == 0


def test_dry_run_counts_without_anchoring(db: Database):
    repo = AttestationRepository(db)
    _insert(repo, "att-d", "exp-d")
    client = _FakeRekor()
    report = backfill_rekor_anchors(db, rekor_client=client, apply=False)
    assert report.candidates == 1
    assert report.anchored == []
    assert client.calls == 0  # dry-run never contacts Rekor
    # Row untouched — still the placeholder.
    assert repo.get_by_id("att-d").rekor_entry_uuid == REKOR_PLACEHOLDER_UUID


def test_noop_client_does_not_stamp_placeholder(db: Database):
    repo = AttestationRepository(db)
    _insert(repo, "att-n", "exp-n")
    report = backfill_rekor_anchors(db, rekor_client=NoOpRekorClient(), apply=True)
    # A placeholder response is treated as "still un-anchored", never recorded.
    assert report.anchored == []
    assert report.failed == ["att-n"]
    assert repo.get_by_id("att-n").rekor_entry_uuid == REKOR_PLACEHOLDER_UUID
    assert len(repo.list_unanchored()) == 1


def test_per_row_failure_leaves_row_and_continues(db: Database):
    repo = AttestationRepository(db)
    _insert(repo, "att-a", "exp-a")  # processed first (issued_at order) → raises
    _insert(repo, "att-b", "exp-b")  # processed second → succeeds
    report = backfill_rekor_anchors(db, rekor_client=_RaisesOnceRekor(), apply=True)
    assert report.failed == ["att-a"]
    assert report.anchored == ["att-b"]
    # The failed row is left for the next run; the good one is anchored.
    assert repo.get_by_id("att-a").rekor_entry_uuid == REKOR_PLACEHOLDER_UUID
    assert repo.get_by_id("att-b").rekor_entry_uuid != REKOR_PLACEHOLDER_UUID
    assert [r.attestation_id for r in repo.list_unanchored()] == ["att-a"]
