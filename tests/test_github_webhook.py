"""§9 #46 follow-on — GitHub release webhook → draft announcement.

The webhook is HMAC-authenticated (X-Hub-Signature-256 over the raw body);
it only ever creates DRAFT registry rows, which heartbeats skip until a
maintainer publishes via the announce action.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

SECRET = "test-webhook-secret"
PATH = "/api/v0/webhooks/github/releases"


@pytest.fixture(autouse=True)
def _webhook_secret(monkeypatch) -> None:
    monkeypatch.setenv("AUSPEXAI_GITHUB_WEBHOOK_SECRET", SECRET)


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _release_event(
    *,
    tag: str = "v0.9.9",
    action: str = "published",
    repo: str = "auspexai/worker",
    draft: bool = False,
    prerelease: bool = False,
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "release": {
                "tag_name": tag,
                "name": f"worker {tag}",
                "body": "release notes from github",
                "html_url": f"https://github.com/{repo}/releases/tag/{tag}",
                "draft": draft,
                "prerelease": prerelease,
            },
            "repository": {"full_name": repo},
        }
    ).encode()


def _post(client: TestClient, body: bytes, *, event: str = "release", sig: str | None = ""):
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    if sig is not None:
        headers["X-Hub-Signature-256"] = sig if sig else _sign(body)
    return client.post(PATH, content=body, headers=headers)


def _mtnr(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


class TestSignature:
    def test_valid_signature_creates_draft(self, client: TestClient, maintainer_token) -> None:
        r = _post(client, _release_event())
        assert r.status_code == 201, r.text
        assert r.json() == {"draft": True, "version": "0.9.9", "channel": "worker"}
        listing = client.get(
            "/api/v0/releases?include_drafts=true", headers=_mtnr(maintainer_token)
        ).json()
        (rel,) = [x for x in listing["releases"] if x["version"] == "0.9.9"]
        assert rel["draft"] is True
        assert rel["source"] == "github-webhook"
        assert rel["announced_by"] == "github-webhook"
        assert rel["notes"] == "release notes from github"

    def test_bad_signature_rejected(self, client: TestClient) -> None:
        body = _release_event()
        r = _post(client, body, sig=_sign(body, "wrong-secret"))
        assert r.status_code == 401

    def test_missing_signature_rejected(self, client: TestClient) -> None:
        r = _post(client, _release_event(), sig=None)
        assert r.status_code == 401

    def test_ping_pongs(self, client: TestClient) -> None:
        body = b'{"zen": "Design for failure."}'
        r = _post(client, body, event="ping")
        assert r.status_code == 200
        assert r.json()["pong"] is True


class TestFiltering:
    @pytest.mark.parametrize(
        "event_body",
        [
            _release_event(action="created"),
            _release_event(prerelease=True),
            _release_event(draft=True),
            _release_event(repo="auspexai/unknown-repo"),
        ],
        ids=["non-published-action", "prerelease", "github-draft", "unknown-repo"],
    )
    def test_ignored_events_return_200_no_draft(
        self, client: TestClient, maintainer_token, event_body: bytes
    ) -> None:
        r = _post(client, event_body)
        assert r.status_code == 200
        assert "ignored" in r.json()
        listing = client.get(
            "/api/v0/releases?include_drafts=true", headers=_mtnr(maintainer_token)
        ).json()
        assert all(x["version"] != "0.9.9" for x in listing["releases"])

    def test_duplicate_version_ignored(self, client: TestClient) -> None:
        assert _post(client, _release_event()).status_code == 201
        r = _post(client, _release_event())
        assert r.status_code == 200
        assert "already recorded" in r.json()["ignored"]


class TestDraftInvisibility:
    def test_draft_not_in_default_listing(self, client: TestClient, maintainer_token) -> None:
        _post(client, _release_event())
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        assert all(x["version"] != "0.9.9" for x in listing["releases"])

    def test_draft_not_relayed_as_latest(self, client: TestClient, db) -> None:
        # The fleet must never hear about an unannounced draft.
        from auspexai_platform.db.repositories import ReleaseRepository

        _post(client, _release_event())
        assert ReleaseRepository(db).latest(channel="worker") is None


class TestAnnounce:
    def test_announce_publishes_with_edits(self, client: TestClient, maintainer_token) -> None:
        _post(client, _release_event())
        r = client.post(
            "/api/v0/releases/0.9.9/actions/announce",
            json={"headline": "Volunteer-facing headline", "fulfils_request_ids": []},
            headers=_mtnr(maintainer_token),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["draft"] is False
        assert body["headline"] == "Volunteer-facing headline"
        assert body["notes"] == "release notes from github"  # kept when not edited
        # Now (and only now) the fleet-facing listing carries it.
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        assert any(x["version"] == "0.9.9" for x in listing["releases"])

    def test_announce_404_on_unknown(self, client: TestClient, maintainer_token) -> None:
        r = client.post(
            "/api/v0/releases/9.9.9/actions/announce",
            json={},
            headers=_mtnr(maintainer_token),
        )
        assert r.status_code == 404

    def test_announce_409_on_already_published(self, client: TestClient, maintainer_token) -> None:
        _post(client, _release_event())
        first = client.post(
            "/api/v0/releases/0.9.9/actions/announce", json={}, headers=_mtnr(maintainer_token)
        )
        assert first.status_code == 200
        again = client.post(
            "/api/v0/releases/0.9.9/actions/announce", json={}, headers=_mtnr(maintainer_token)
        )
        assert again.status_code == 409
        assert again.json()["detail"]["error"]["code"] == "not_a_draft"


class TestUnconfigured:
    def test_no_secret_means_disabled(self, client: TestClient, monkeypatch) -> None:
        # The router captures the secret at app build; simulate an
        # unconfigured deployment with a fresh router.
        from fastapi import FastAPI

        from auspexai_platform.api.github_webhook import build_router

        app = FastAPI()
        app.include_router(
            build_router(None, None, webhook_secret=None),
            prefix="/api/v0",  # type: ignore[arg-type]
        )
        local = TestClient(app)
        r = local.post(PATH, content=b"{}", headers={"X-GitHub-Event": "release"})
        assert r.status_code == 503
