"""A11 Rekor attempt-counter — a structurally-un-anchorable row (permanent 4xx)
goes terminal and stops being retried; a transient outage is retried forever."""

from __future__ import annotations

import httpx

from auspexai_platform.db.repositories import AnchorOutcomeRepository
from auspexai_platform.receipts.attestation_backfill import (
    TERMINAL_AFTER_PERMANENT,
    _attempt_anchor,
    _is_permanent_rejection,
)
from auspexai_platform.receipts.rekor import REKOR_PLACEHOLDER_UUID, RekorEntry


def _http_error(code: int) -> httpx.HTTPStatusError:
    req = httpx.Request("POST", "https://rekor.example/api/v1/log/entries")
    return httpx.HTTPStatusError(f"{code}", request=req, response=httpx.Response(code, request=req))


class _FakeRekor:
    def __init__(self, behavior) -> None:
        self.behavior = behavior  # 'ok' | 'placeholder' | an Exception to raise
        self.calls = 0

    def record(self, blob: bytes) -> RekorEntry:
        self.calls += 1
        if isinstance(self.behavior, Exception):
            raise self.behavior
        if self.behavior == "placeholder":
            return RekorEntry(log_index=0, entry_uuid=REKOR_PLACEHOLDER_UUID)
        return RekorEntry(log_index=42, entry_uuid="real-uuid")


def test_permanent_vs_transient_classification() -> None:
    assert _is_permanent_rejection(_http_error(400)) is True  # the Ed25519/cose rejection
    assert _is_permanent_rejection(_http_error(422)) is True
    assert _is_permanent_rejection(_http_error(408)) is False  # timeout — transient
    assert _is_permanent_rejection(_http_error(429)) is False  # rate limit — transient
    assert _is_permanent_rejection(_http_error(500)) is False
    assert _is_permanent_rejection(_http_error(503)) is False
    assert _is_permanent_rejection(httpx.ConnectError("down")) is False
    assert _is_permanent_rejection(ValueError("bad blob")) is False


def test_transient_failures_never_go_terminal(db) -> None:
    repo = AnchorOutcomeRepository(db)
    for _ in range(25):
        assert (
            repo.record_failure(
                "attestation", "att-t", permanent=False, error="503", now="t", terminal_after=3
            )
            is False
        )
    assert repo.terminal_ids("attestation") == set()  # a long outage is ridden out, not abandoned


def test_permanent_failures_go_terminal_after_cap(db) -> None:
    repo = AnchorOutcomeRepository(db)
    kw = dict(permanent=True, error="400 unsupported algorithm ed25519", now="t", terminal_after=3)
    assert repo.record_failure("attestation", "att-p", **kw) is False  # 1
    assert repo.record_failure("attestation", "att-p", **kw) is False  # 2
    assert repo.record_failure("attestation", "att-p", **kw) is True  # 3 → terminal
    assert repo.terminal_ids("attestation") == {"att-p"}
    repo.clear("attestation", "att-p")
    assert repo.terminal_ids("attestation") == set()


def test_transient_does_not_advance_the_permanent_count(db) -> None:
    repo = AnchorOutcomeRepository(db)
    repo.record_failure(
        "attestation", "att-m", permanent=True, error="400", now="t", terminal_after=3
    )
    for _ in range(20):  # transient noise between permanent rejections must not count
        repo.record_failure(
            "attestation", "att-m", permanent=False, error="500", now="t", terminal_after=3
        )
    assert repo.terminal_ids("attestation") == set()  # still 1 permanent < 3
    repo.record_failure(
        "attestation", "att-m", permanent=True, error="400", now="t", terminal_after=3
    )
    assert (
        repo.record_failure(
            "attestation", "att-m", permanent=True, error="400", now="t", terminal_after=3
        )
        is True
    )


def test_attempt_anchor_success_clears_prior_failure_state(db) -> None:
    repo = AnchorOutcomeRepository(db)
    repo.record_failure(
        "attestation", "att-s", permanent=False, error="500", now="t", terminal_after=3
    )
    entry, note = _attempt_anchor(
        _FakeRekor("ok"),
        b"blob",
        repo,
        artifact_type="attestation",
        artifact_id="att-s",
        terminal_ids=set(),
        now="t",
    )
    assert note == "ok" and entry is not None
    assert db.execute("SELECT * FROM anchor_outcomes WHERE artifact_id = 'att-s'") == []


def test_attempt_anchor_permanent_goes_terminal_then_is_skipped(db) -> None:
    repo = AnchorOutcomeRepository(db)
    fake = _FakeRekor(_http_error(400))
    note = ""
    for _ in range(TERMINAL_AFTER_PERMANENT):
        _, note = _attempt_anchor(
            fake,
            b"blob",
            repo,
            artifact_type="attestation",
            artifact_id="att-x",
            terminal_ids=repo.terminal_ids("attestation"),
            now="t",
        )
    assert note == "newly_terminal"
    assert fake.calls == TERMINAL_AFTER_PERMANENT
    # Next sweep: it's terminal → skipped, Rekor is NOT called again (the leak is closed).
    entry, note = _attempt_anchor(
        fake,
        b"blob",
        repo,
        artifact_type="attestation",
        artifact_id="att-x",
        terminal_ids=repo.terminal_ids("attestation"),
        now="t",
    )
    assert note == "skipped_terminal" and entry is None
    assert fake.calls == TERMINAL_AFTER_PERMANENT  # unchanged — no forever-retry
