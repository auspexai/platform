"""Citation/contributor ledger (System B, D) — the aggregation behind
GET /experiments/{id}/citation: opted-in accounts are NAMED, everyone else is
aggregated anonymously, and unlinked (T0) workers don't count as accounts.
"""

from __future__ import annotations

from typing import ClassVar

from auspexai_platform.api.receipts import (
    _experiment_contributors,
    _format_acknowledgment,
)


class _Row(dict):
    pass


class _DB:
    def execute(self, _query: str):
        return [_Row(worker_id="w1"), _Row(worker_id="w2"), _Row(worker_id="w3")]


class _Factory:
    def get(self, _eid: str):
        return _DB()


class _Worker:
    def __init__(self, account_id: str | None) -> None:
        self.account_id = account_id


class _WorkerRepo:
    _map: ClassVar[dict] = {
        "w1": _Worker("a1"),
        "w2": _Worker("a2"),
        "w3": _Worker(None),
    }  # w3 = T0, no acct

    def get_by_id(self, wid: str):
        return self._map.get(wid)


class _Account:
    def __init__(self, public: bool, name: str | None, display: str | None) -> None:
        self.public_attribution = public
        self.attribution_name = name
        self.display_name = display


class _AcctRepo:
    _map: ClassVar[dict] = {
        "a1": _Account(True, "Ada Lovelace", "ada"),  # opted in, custom name
        "a2": _Account(False, None, "bob"),  # not opted in → anonymous
    }

    def get_by_id(self, aid: str):
        return self._map.get(aid)


def test_contributors_named_vs_anonymous_with_unlinked_worker() -> None:
    named, anonymous, total = _experiment_contributors(
        "exp-x", _Factory(), _WorkerRepo(), _AcctRepo()
    )
    assert named == ["Ada Lovelace"]  # a1 opted in (custom name beats display_name)
    assert anonymous == 1  # a2 did not opt in
    assert total == 2  # a1 + a2; w3 has no account → not a contributor account


def test_contributors_empty_when_no_per_job_db() -> None:
    class _NoneFactory:
        def get(self, _eid: str):
            return None

    assert _experiment_contributors("exp-x", _NoneFactory(), _WorkerRepo(), _AcctRepo()) == (
        [],
        0,
        0,
    )


def test_acknowledgment_formatting() -> None:
    assert "Ada, Grace and 3 anonymous volunteers" in _format_acknowledgment(["Ada", "Grace"], 3)
    assert "1 anonymous volunteer." in _format_acknowledgment([], 1)
    assert _format_acknowledgment(["Solo"], 0).endswith("by Solo.")
    assert "no attributed contributors" in _format_acknowledgment([], 0)
