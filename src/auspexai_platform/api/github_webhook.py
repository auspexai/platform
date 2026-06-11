"""GitHub release webhook → DRAFT announcement (§9 #46 follow-on).

GitHub POSTs a `release` event when a release is published on a watched
repo. The handler creates a DRAFT row in the release registry — drafts are
invisible to the fleet (heartbeats skip them); a maintainer reviews the
volunteer-facing wording in the console and publishes via the announce
action. A compromised webhook path can therefore at worst create drafts,
never push an update prompt at the fleet.

Auth is GitHub's HMAC signature (X-Hub-Signature-256) over the raw body
with a shared secret — no coordinator credential is parked on GitHub's
side. Unconfigured secret = endpoint disabled (503).

Replies are 2xx for "understood but ignored" cases (wrong action,
prerelease, unknown repo, duplicate) so GitHub doesn't queue redeliveries
for events we deliberately skip.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from auspexai_platform.auth.credential import CredentialClass
from auspexai_platform.db.repositories import AuditRepository, ReleaseRepository
from auspexai_platform.events import EventBus

logger = logging.getLogger(__name__)

# repo full_name → release channel. Single worker channel today; adding a
# channel (e.g. tenant-sdk) = one more entry.
REPO_CHANNELS: dict[str, str] = {
    "auspexai/worker": "worker",
}

MAX_NOTES_LENGTH = 8000
MAX_HEADLINE_LENGTH = 500


def _signature_ok(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def build_router(
    release_repository: ReleaseRepository,
    audit_repository: AuditRepository,
    *,
    webhook_secret: str | None,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post("/webhooks/github/releases")
    async def github_release_webhook(request: Request) -> JSONResponse:
        if not webhook_secret:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"error": "webhook not configured (no AUSPEXAI_GITHUB_WEBHOOK_SECRET)"},
            )
        body = await request.body()
        if not _signature_ok(webhook_secret, body, request.headers.get("X-Hub-Signature-256")):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "invalid or missing X-Hub-Signature-256"},
            )

        event = request.headers.get("X-GitHub-Event", "")
        if event == "ping":
            return JSONResponse(status_code=status.HTTP_200_OK, content={"ok": True, "pong": True})
        if event != "release":
            return JSONResponse(
                status_code=status.HTTP_200_OK, content={"ignored": f"event {event!r}"}
            )

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid JSON body"}
            )

        action = payload.get("action")
        if action != "published":
            return JSONResponse(
                status_code=status.HTTP_200_OK, content={"ignored": f"action {action!r}"}
            )

        release = payload.get("release") or {}
        repo_name = (payload.get("repository") or {}).get("full_name", "")
        channel = REPO_CHANNELS.get(repo_name)
        if channel is None:
            return JSONResponse(
                status_code=status.HTTP_200_OK, content={"ignored": f"repo {repo_name!r}"}
            )
        # GitHub drafts haven't happened yet; prereleases are deliberately
        # never offered to volunteers.
        if release.get("draft") or release.get("prerelease"):
            return JSONResponse(
                status_code=status.HTTP_200_OK, content={"ignored": "draft/prerelease"}
            )

        tag = str(release.get("tag_name") or "")
        version = tag.removeprefix("v").strip()
        if not version:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content={"error": "no tag_name"}
            )
        if release_repository.get(version=version, channel=channel) is not None:
            # Already recorded (draft OR published — e.g. announced manually
            # before the webhook landed).
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"ignored": f"{channel}/{version} already recorded"},
            )

        headline = str(release.get("name") or f"{channel} v{version}")[:MAX_HEADLINE_LENGTH]
        notes = str(release.get("body") or "")[:MAX_NOTES_LENGTH] or None
        release_url = str(release.get("html_url") or "") or None
        created = release_repository.create(
            version=version,
            channel=channel,
            headline=headline,
            notes=notes,
            release_url=release_url,
            announced_by="github-webhook",
            draft=True,
            source="github-webhook",
        )
        audit_repository.append(
            actor_class=CredentialClass.SYSTEM,
            actor_identifier="github-webhook",
            action="release.draft_created",
            resource_type="release",
            resource_id=f"{channel}/{version}",
            payload={"version": version, "channel": channel, "repo": repo_name, "tag": tag},
        )
        if event_bus is not None:
            event_bus.publish(
                "release.draft_created",
                experiment_id=None,
                data={"version": version, "channel": channel, "headline": headline},
            )
        logger.info("github webhook: draft announcement created for %s/%s", channel, version)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"draft": True, "version": created.version, "channel": created.channel},
        )

    return router
