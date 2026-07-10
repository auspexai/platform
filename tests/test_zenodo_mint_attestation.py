"""Regression + idempotency guards for the Zenodo DOI mint (2026-07-09).

Two bugs this pins:
  1. Content: the route minted with no `verification=`, so every DOI shipped a
     2-byte `{}` attestation.json — the file that IS the evidence the DOI cites.
  2. Exactly-once: the mint is a multi-step external transaction; a failure after
     the irreversible publish (a lost final response) would, on a naive retry,
     mint a SECOND real DOI for the same result (a permanent duplicate + gaming
     vector), and a mid-draft failure orphaned drafts. The mint now reserves +
     persists the draft before publish and reconciles on retry.

These drive ZenodoClient.mint_doi against a fake records API that records every
call, so we can assert both the uploaded bytes and that a retry never re-creates.
"""

import json

import httpx

from auspexai_platform.zenodo import ZenodoClient


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload


class _FakeAPI:
    """Walks the records-API happy path offline. `published` maps a record id to a
    published body (drives the reconcile short-circuit); `live_drafts` is the set
    of record ids whose draft still exists (drives resume). Records every call."""

    def __init__(self, sink: dict, *, published: dict | None = None, live_drafts=None):
        self._sink = sink
        self._published = published or {}
        self._live_drafts = set(live_drafts or [])
        sink.setdefault("calls", [])
        sink.setdefault("content", None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _rec(self, method: str, url: str):
        self._sink["calls"].append((method, url))

    def get(self, url: str, **_kw) -> _Resp:
        self._rec("GET", url)
        # reconcile: published record?
        for rid, body in self._published.items():
            if url.endswith(f"/api/records/{rid}"):
                return _Resp(200, body)
        # reconcile: live draft?
        for rid in self._live_drafts:
            if url.endswith(f"/api/records/{rid}/draft"):
                return _Resp(200, {"id": rid})
        if url.endswith("/draft/files"):
            return _Resp(200, {"entries": []})  # nothing uploaded yet
        return _Resp(404, {})

    def post(self, url: str, **_kw) -> _Resp:
        self._rec("POST", url)
        if url.endswith("/api/records"):
            return _Resp(201, {"id": "draft-new"})
        if url.endswith("/draft/pids/doi"):
            return _Resp(201, {"pids": {"doi": {"identifier": "10.5072/zenodo.NEW"}}})
        if url.endswith("/actions/publish"):
            return _Resp(
                202,
                {
                    "pids": {"doi": {"identifier": "10.5072/zenodo.NEW"}},
                    "is_published": True,
                    "links": {"self_html": "https://sandbox/record/draft-new"},
                },
            )
        return _Resp(201, {})  # file register / commit

    def put(self, url: str, *, content: bytes, **_kw) -> _Resp:
        self._rec("PUT", url)
        if url.endswith("/attestation.json/content"):
            self._sink["content"] = content
        return _Resp(201, {})


def _client(tmp_path, monkeypatch, **api_kw):
    (tmp_path / "zenodo.json").write_text(json.dumps({"token": "t", "mode": "sandbox"}))
    sink: dict = {}
    monkeypatch.setattr(httpx, "Client", lambda **kw: _FakeAPI(sink, **api_kw))
    return ZenodoClient(tmp_path), sink


_META = {"title": "x", "resource_type": {"id": "dataset"}, "creators": []}
_VERIF = {
    "schema": "auspexai-doi-verification/v1",
    "experiment_id": "exp-abc",
    "result_set": {"merkle_root": "c7123de0deadbeef", "unit_count": 500},
}


def _created_records(sink) -> int:
    return sum(1 for m, u in sink["calls"] if m == "POST" and u.endswith("/api/records"))


def _published(sink) -> int:
    return sum(1 for m, u in sink["calls"] if m == "POST" and u.endswith("/actions/publish"))


def test_verification_payload_is_uploaded_not_empty(tmp_path, monkeypatch):
    zc, sink = _client(tmp_path, monkeypatch)
    out = zc.mint_doi(_META, verification=_VERIF)
    assert out["doi"] == "10.5072/zenodo.NEW"
    # The file is the evidence — it must carry the actual payload, never `{}`.
    assert sink["content"] != b"{}"
    uploaded = json.loads(sink["content"])
    assert uploaded["result_set"]["merkle_root"] == "c7123de0deadbeef"


def test_absent_verification_stays_empty_object(tmp_path, monkeypatch):
    zc, sink = _client(tmp_path, monkeypatch)
    zc.mint_doi(_META)
    assert sink["content"] == b"{}"


def test_on_draft_fires_with_reserved_doi_before_publish(tmp_path, monkeypatch):
    zc, _sink = _client(tmp_path, monkeypatch)
    seen: list = []
    zc.mint_doi(_META, verification=_VERIF, on_draft=lambda rid, doi: seen.append((rid, doi)))
    # persisted the reserved draft exactly once, with the reserved DOI
    assert seen == [("draft-new", "10.5072/zenodo.NEW")]


def test_resume_already_published_returns_doi_without_duplicating(tmp_path, monkeypatch):
    # The lost-final-response case: publish landed last time, our DOI never got
    # persisted. A retry must return the SAME DOI and create NOTHING new.
    published_body = {
        "id": "rec-9",
        "is_published": True,
        "pids": {"doi": {"identifier": "10.5072/zenodo.9"}},
        "links": {"self_html": "https://sandbox/record/rec-9"},
    }
    zc, sink = _client(tmp_path, monkeypatch, published={"rec-9": published_body})
    out = zc.mint_doi(_META, verification=_VERIF, resume_record_id="rec-9")
    assert out["doi"] == "10.5072/zenodo.9"
    assert _created_records(sink) == 0  # no second record
    assert _published(sink) == 0  # no second publish


def test_resume_live_draft_publishes_without_new_draft(tmp_path, monkeypatch):
    # Mid-mint death: the draft survived but never published. Resume it — no new
    # draft, no second reserved DOI.
    zc, sink = _client(tmp_path, monkeypatch, live_drafts={"rec-5"})
    out = zc.mint_doi(_META, verification=_VERIF, resume_record_id="rec-5")
    assert out["doi"] == "10.5072/zenodo.NEW"
    assert _created_records(sink) == 0  # resumed, did NOT create a new draft
    assert _published(sink) == 1
    # published the RESUMED record, not a fresh one
    assert any(u.endswith("/api/records/rec-5/draft/actions/publish") for _, u in sink["calls"])
