"""Citation/contributor ledger (System B) — the aggregation behind
GET /experiments/{id}/citation. NON-RETROACTIVE consent: an account is named only if
it was opted in AT CONTRIBUTION (the receipt's `public_attribution_at_issue` snapshot)
AND is still opted in now. The snapshot blocks retroactive opt-IN; the current flag
preserves reversible opt-OUT. Unlinked (T0) workers aren't contributor accounts.
"""

from __future__ import annotations

from typing import ClassVar

from auspexai_platform.api.receipts import (
    _experiment_contributors,
    _format_acknowledgment,
)


class _Entry:
    def __init__(self, worker_id: str, at_issue: bool) -> None:
        self.worker_id = worker_id
        self.public_attribution_at_issue = at_issue


class _ReceiptIndex:
    # One receipt per agreeing worker's contribution to this experiment.
    _entries: ClassVar[list] = [
        _Entry("w_named", True),  # opted in AT issue
        _Entry("w_optout", True),  # opted in AT issue (but withdrew since)
        _Entry("w_late", False),  # NOT opted in at issue (opted in afterwards)
        _Entry("w_t0", False),  # unlinked worker, no account
    ]

    def list_for_experiment(self, _eid: str):
        return self._entries


class _Worker:
    def __init__(self, account_id: str | None) -> None:
        self.account_id = account_id


class _WorkerRepo:
    _map: ClassVar[dict] = {
        "w_named": _Worker("a_named"),
        "w_optout": _Worker("a_optout"),
        "w_late": _Worker("a_late"),
        "w_t0": _Worker(None),
    }

    def get_by_id(self, wid: str):
        return self._map.get(wid)


class _Account:
    def __init__(self, public: bool, name: str | None, display: str | None) -> None:
        self.public_attribution = public
        self.attribution_name = name
        self.display_name = display


class _AcctRepo:
    _map: ClassVar[dict] = {
        "a_named": _Account(True, "Ada Lovelace", "ada"),  # at_issue=T, now=T → NAMED
        "a_optout": _Account(False, None, "bob"),  # at_issue=T, now=F → anon (opt-out)
        "a_late": _Account(True, "Grace", "grace"),  # at_issue=F, now=T → anon (non-retroactive)
    }

    def get_by_id(self, aid: str):
        return self._map.get(aid)


def test_contributors_non_retroactive_and_reversible() -> None:
    named, anonymous, total = _experiment_contributors(
        "exp-x", _ReceiptIndex(), _WorkerRepo(), _AcctRepo()
    )
    # Only a_named: opted in at contribution AND still opted in.
    assert named == ["Ada Lovelace"]
    # a_optout (withdrew consent) + a_late (opted in only AFTER contributing) both anonymous.
    assert anonymous == 2
    # 3 contributor accounts; w_t0 has no account → not counted.
    assert total == 3


def test_contributors_empty_experiment() -> None:
    class _Empty:
        def list_for_experiment(self, _eid: str):
            return []

    assert _experiment_contributors("exp-x", _Empty(), _WorkerRepo(), _AcctRepo()) == ([], 0, 0)


def test_acknowledgment_formatting() -> None:
    assert "Ada, Grace and 3 anonymous volunteers" in _format_acknowledgment(["Ada", "Grace"], 3)
    assert "1 anonymous volunteer." in _format_acknowledgment([], 1)
    assert _format_acknowledgment(["Solo"], 0).endswith("by Solo.")
    assert "no attributed contributors" in _format_acknowledgment([], 0)
