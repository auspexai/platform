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
    def __init__(self, worker_id: str, at_issue: bool, account_id_at_issue: str | None) -> None:
        self.worker_id = worker_id
        self.public_attribution_at_issue = at_issue
        self.account_id_at_issue = account_id_at_issue  # 0041 snapshot (None = anon at issue)


class _ReceiptIndex:
    # One receipt per agreeing worker's contribution to this experiment.
    _entries: ClassVar[list] = [
        _Entry("w_named", True, "a_named"),  # opted in AT issue
        _Entry("w_optout", True, "a_optout"),  # opted in AT issue (but withdrew since)
        _Entry("w_late", False, "a_late"),  # bound at issue, NOT citation-opted (opted in later)
        _Entry("w_t0", False, None),  # anonymous AT issue (no account)
        # Regression: anonymous AT issue, but the worker LOGGED IN since (live account set). The
        # None snapshot must win — never resolved to the worker's current account (non-retroactive).
        _Entry("w_relogged", False, None),
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
        "w_relogged": _Worker("a_relogged"),  # logged in AFTER its anonymous contribution
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
        # at_issue=T, now=T → NAMED as the verified display_name "ada" (the GitHub
        # login); the attribution_name "Ada Lovelace" is IGNORED (hardened — no fake names).
        "a_named": _Account(True, "Ada Lovelace", "ada"),
        "a_optout": _Account(False, None, "bob"),  # at_issue=T, now=F → anon (opt-out)
        "a_late": _Account(True, "Grace", "grace"),  # at_issue=F, now=T → anon (non-retroactive)
    }

    def get_by_id(self, aid: str):
        return self._map.get(aid)


def test_contributors_non_retroactive_and_reversible() -> None:
    named, anonymous, total = _experiment_contributors(
        "exp-x", _ReceiptIndex(), _WorkerRepo(), _AcctRepo()
    )
    # Only a_named: opted in at contribution AND still opted in. Credit = the verified
    # display_name ("ada"), NOT the now-ignored attribution_name ("Ada Lovelace").
    assert named == ["ada"]
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
