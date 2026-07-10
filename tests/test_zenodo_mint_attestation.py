"""Regression guard for the DOI's attestation.json payload (2026-07-09).

The bug: the mint route called `mint_doi(metadata)` with no `verification=`, so
every DOI shipped a 2-byte `{}` attestation.json — the file that is supposed to
BE the durable, independently-verifiable evidence the DOI cites. Nothing asserted
its content, so it went silent. These tests pin the serialization contract at the
enforcement point: a passed verification lands as non-empty JSON carrying the
result-set root; the absent case (defensive) stays `{}`.
"""

import json

import httpx
import pytest

from auspexai_platform.zenodo import ZenodoClient


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload


class _CapturingClient:
    """Stands in for httpx.Client — records the uploaded attestation bytes and
    walks the records-API happy path so mint_doi() runs end to end offline."""

    def __init__(self, sink: dict, **_kw):
        self._sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url: str, **_kw) -> _FakeResponse:
        if url.endswith("/api/records"):
            return _FakeResponse(201, {"id": "draft-1"})
        if url.endswith("/actions/publish"):
            return _FakeResponse(
                202,
                {"doi": "10.5072/zenodo.1", "links": {"self_html": "https://example/record/1"}},
            )
        # pids/doi reserve, files register, commit
        return _FakeResponse(201, {})

    def put(self, url: str, *, content: bytes, **_kw) -> _FakeResponse:
        if url.endswith("/attestation.json/content"):
            self._sink["content"] = content
        return _FakeResponse(201, {})


@pytest.fixture()
def client(tmp_path, monkeypatch):
    (tmp_path / "zenodo.json").write_text(json.dumps({"token": "t", "mode": "sandbox"}))
    sink: dict = {}
    monkeypatch.setattr(httpx, "Client", lambda **kw: _CapturingClient(sink, **kw))
    return ZenodoClient(tmp_path), sink


_META = {"title": "x", "resource_type": {"id": "dataset"}, "creators": []}


def test_verification_payload_is_uploaded_not_empty(client):
    zc, sink = client
    verification = {
        "schema": "auspexai-doi-verification/v1",
        "experiment_id": "exp-abc",
        "result_set": {"merkle_root": "c7123de0deadbeef", "unit_count": 500},
    }
    out = zc.mint_doi(_META, verification=verification)
    assert out["doi"] == "10.5072/zenodo.1"
    # The file is the evidence — it must carry the actual payload, never `{}`.
    assert sink["content"] != b"{}"
    uploaded = json.loads(sink["content"])
    assert uploaded["result_set"]["merkle_root"] == "c7123de0deadbeef"
    assert uploaded["experiment_id"] == "exp-abc"


def test_absent_verification_stays_empty_object(client):
    # Defensive path only: the route always passes a payload now.
    zc, sink = client
    zc.mint_doi(_META)
    assert sink["content"] == b"{}"
