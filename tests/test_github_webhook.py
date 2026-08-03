"""§9 #46 follow-on — GitHub release webhook → DIRECT fleet announcement.

The webhook is HMAC-authenticated (X-Hub-Signature-256 over the raw body)
and records the release PUBLISHED — the GitHub release gate is the human
gate (ratified 2026-06-11). `Fulfils: swr-…` lines in the description link
approved software requests. The draft/announce machinery stays dormant
(announce-action tests seed drafts via the repository directly).
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from auspexai_platform.db.repositories import SoftwareRequestRepository

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
    body_text: str = "release notes from github",
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "release": {
                "tag_name": tag,
                "name": f"worker {tag}",
                "body": body_text,
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
    def test_valid_signature_announces_directly(self, client: TestClient, maintainer_token) -> None:
        r = _post(client, _release_event())
        assert r.status_code == 201, r.text
        assert r.json() == {
            "announced": True,
            "version": "0.9.9",
            "channel": "worker",
            "fulfilled_request_ids": [],
        }
        # Published immediately: visible in the DEFAULT (fleet-facing) listing.
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        (rel,) = [x for x in listing["releases"] if x["version"] == "0.9.9"]
        assert rel["draft"] is False
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


class TestRelay:
    def test_webhook_release_is_latest(self, client: TestClient, db) -> None:
        # Direct announce: the fleet hears about it on the next heartbeat.
        from auspexai_platform.db.repositories import ReleaseRepository

        _post(client, _release_event())
        latest = ReleaseRepository(db).latest(channel="worker")
        assert latest is not None and latest.version == "0.9.9"

    def test_manual_draft_still_invisible(self, client: TestClient, db, maintainer_token) -> None:
        # The dormant draft machinery keeps its invariant.
        from auspexai_platform.db.repositories import ReleaseRepository

        ReleaseRepository(db).create(
            version="0.9.8", channel="worker", headline="x", announced_by="t", draft=True
        )
        assert ReleaseRepository(db).latest(channel="worker") is None
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        assert all(x["version"] != "0.9.8" for x in listing["releases"])


class TestFulfils:
    def test_fulfils_line_links_approved_request(
        self, client: TestClient, registered_tenant, maintainer_token, db
    ) -> None:
        from tests.test_releases import _approved_request

        rid = _approved_request(db, registered_tenant[1].tenant_id)
        body = _release_event(body_text=f"Good stuff for volunteers.\n\nFulfils: {rid}")
        r = _post(client, body)
        assert r.status_code == 201, r.text
        assert r.json()["fulfilled_request_ids"] == [rid]
        sr = SoftwareRequestRepository(db).get_by_id(rid)
        assert sr.status == "released"
        assert sr.release_version == "0.9.9"
        # Plumbing line stripped from the volunteer-facing notes.
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        (rel,) = [x for x in listing["releases"] if x["version"] == "0.9.9"]
        assert rel["notes"] == "Good stuff for volunteers."

    def test_bad_fulfils_id_never_blocks_announcement(
        self, client: TestClient, maintainer_token
    ) -> None:
        body = _release_event(body_text="Notes.\nFulfils: swr-doesnotexist")
        r = _post(client, body)
        assert r.status_code == 201, r.text
        assert r.json()["fulfilled_request_ids"] == []
        listing = client.get("/api/v0/releases", headers=_mtnr(maintainer_token)).json()
        assert any(x["version"] == "0.9.9" for x in listing["releases"])


class TestAnnounce:
    @staticmethod
    def _seed_draft(db) -> None:
        from auspexai_platform.db.repositories import ReleaseRepository

        ReleaseRepository(db).create(
            version="0.9.9",
            channel="worker",
            headline="worker v0.9.9",
            notes="release notes from github",
            announced_by="github-webhook",
            draft=True,
            source="github-webhook",
        )

    def test_announce_publishes_with_edits(self, client: TestClient, db, maintainer_token) -> None:
        self._seed_draft(db)
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

    def test_announce_409_on_already_published(
        self, client: TestClient, db, maintainer_token
    ) -> None:
        self._seed_draft(db)
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


class TestFulfilsParsingIsBounded:
    """CodeQL py/polynomial-redos on `_FULFILS_LINE`.

    Only reachable with the webhook HMAC secret (`_signature_ok` runs before any
    parsing), so this was never remotely triggerable — but it was a genuine
    quadratic and the fix is also the more correct expression.
    """

    def test_no_overlapping_quantifiers(self):
        from auspexai_platform.api.github_webhook import _FULFILS_LINE

        pattern = _FULFILS_LINE.pattern
        # `\s` would match the line terminator and overlap with MULTILINE `$`.
        assert "\\s" not in pattern
        # And a TRAILING whitespace class would overlap with the capture group,
        # because `.` matches space and tab — fixing only the `\s` half leaves
        # the quadratic in place. Capture to end of line instead.
        assert pattern.endswith("(.*)$")

    def test_still_parses_the_real_shapes(self):
        from auspexai_platform.api.github_webhook import _parse_fulfils

        ids, notes = _parse_fulfils("Some notes.\n  Fulfils: swr-abc, swr-def  \nMore notes.\n")
        assert ids == ["swr-abc", "swr-def"]
        assert "Fulfils" not in notes
        assert "Some notes." in notes and "More notes." in notes

    def test_case_insensitive_and_no_match_is_inert(self):
        from auspexai_platform.api.github_webhook import _parse_fulfils

        assert _parse_fulfils("FULFILS: swr-x\n")[0] == ["swr-x"]
        assert _parse_fulfils("no marker here\n") == ([], "no marker here")

    def test_body_is_truncated_before_parsing(self):
        from auspexai_platform.api.github_webhook import (
            MAX_PARSED_BODY_LENGTH,
            _parse_fulfils,
        )

        # MAX_NOTES_LENGTH bounds only what is STORED, and it is applied after
        # parsing — so the parser needs its own bound.
        _ids, notes = _parse_fulfils("x" * (MAX_PARSED_BODY_LENGTH * 3))
        assert len(notes) <= MAX_PARSED_BODY_LENGTH

    def test_pathological_input_completes_promptly(self):
        import time

        from auspexai_platform.api.github_webhook import _parse_fulfils

        # The old pattern's worst case: a `Fulfils:` line trailed by a long run
        # of horizontal whitespace with no terminator to anchor on.
        started = time.monotonic()
        _parse_fulfils("Fulfils: swr-a" + " " * 60_000)
        assert time.monotonic() - started < 2.0
