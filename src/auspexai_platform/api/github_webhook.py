"""GitHub release webhook → direct fleet announcement (§9 #46 follow-on).

GitHub POSTs a `release` event when a release is published on a watched
repo; the handler records it PUBLISHED — the next worker heartbeat carries
the banner. Publishing the GitHub release IS the maintainer's "what is
offered" gate (tag + CI-built signed assets), and the installer already
pulls latest-from-GitHub, so a console review step added no supply-chain
protection — only editorial delay (ratified 2026-06-11; the draft/announce
machinery stays dormant underneath as the re-enable path if a regretted
announcement ever ships at scale).

Release-description conventions:
  - The description IS the volunteer-facing notes — write it for them.
  - `Fulfils: swr-a, swr-b` lines link approved software requests, flipping
    them to `released` (invalid/unapproved ids are skipped + audited, never
    fatal). The lines are stripped from the published notes.

Auth is GitHub's HMAC signature (X-Hub-Signature-256) over the raw body
with a shared secret — no coordinator credential is parked on GitHub's
side. Unconfigured secret = endpoint disabled (503).

Replies are 2xx for "understood but ignored" cases (wrong action,
prerelease, unknown repo, duplicate) so GitHub doesn't queue redeliveries
for events we deliberately skip.
"""

# NOTE: deliberately NO `from __future__ import annotations` here — this route
# carries slowapi's `@limiter.limit`, and stringized annotations under the
# limiter wrapper break FastAPI's signature resolution (see the CI-red postmortem
# 2026-05-30 + the matching notes in api/receipts.py / api/accounts.py). All
# annotations in this module are runtime-safe on 3.11/3.12 without it.

import hashlib
import hmac
import json
import logging
import re

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from auspexai_platform.auth.credential import CredentialClass
from auspexai_platform.db.repositories import (
    AuditRepository,
    ReleaseRepository,
    SoftwareRequestRepository,
)
from auspexai_platform.events import EventBus
from auspexai_platform.rate_limit import limiter

logger = logging.getLogger(__name__)

# repo full_name → release channel. Single worker channel today; adding a
# channel (e.g. tenant-sdk) = one more entry.
REPO_CHANNELS: dict[str, str] = {
    "auspexai/worker": "worker",
}

MAX_NOTES_LENGTH = 8000
MAX_HEADLINE_LENGTH = 500

# `Fulfils: swr-a, swr-b` lines in the release description (maintainer
# plumbing — parsed out, stripped from the volunteer-facing notes).
_FULFILS_LINE = re.compile(r"^\s*fulfils:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_REQUEST_ID = re.compile(r"swr-[A-Za-z0-9_-]+")


def _parse_fulfils(body_text: str) -> tuple[list[str], str]:
    """Extract fulfilled request ids; return (ids, notes-without-those-lines)."""
    ids: list[str] = []
    for m in _FULFILS_LINE.finditer(body_text):
        ids.extend(_REQUEST_ID.findall(m.group(1)))
    stripped = _FULFILS_LINE.sub("", body_text).strip()
    return ids, stripped


def _signature_ok(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def build_router(
    release_repository: ReleaseRepository,
    audit_repository: AuditRepository,
    software_request_repository: SoftwareRequestRepository | None = None,
    *,
    webhook_secret: str | None,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post("/webhooks/github/releases")
    @limiter.limit("30/minute")
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
        fulfils_ids, notes_text = _parse_fulfils(str(release.get("body") or ""))
        notes = notes_text[:MAX_NOTES_LENGTH] or None
        release_url = str(release.get("html_url") or "") or None

        # Fulfils linkage rides in the release description; a bad id must
        # never block the announcement — skip it, audit it.
        fulfilled: list[str] = []
        skipped: list[dict[str, str]] = []
        for request_id in fulfils_ids:
            req = (
                software_request_repository.get_by_id(request_id)
                if software_request_repository is not None
                else None
            )
            if req is not None and req.status == "approved":
                fulfilled.append(request_id)
            else:
                skipped.append(
                    {
                        "request_id": request_id,
                        "reason": "not found" if req is None else f"status {req.status}",
                    }
                )
                logger.warning(
                    "github webhook: skipping fulfils id %s (%s)",
                    request_id,
                    skipped[-1]["reason"],
                )

        created = release_repository.create(
            version=version,
            channel=channel,
            headline=headline,
            notes=notes,
            release_url=release_url,
            announced_by="github-webhook",
            draft=False,
            source="github-webhook",
        )
        for request_id in fulfilled:
            software_request_repository.mark_released(request_id, release_version=version)
        audit_repository.append(
            actor_class=CredentialClass.SYSTEM,
            actor_identifier="github-webhook",
            action="release.publish",
            resource_type="release",
            resource_id=f"{channel}/{version}",
            payload={
                "version": version,
                "channel": channel,
                "repo": repo_name,
                "tag": tag,
                "source": "github-webhook",
                "fulfils_request_ids": fulfilled,
                **({"skipped_fulfils": skipped} if skipped else {}),
            },
        )
        if event_bus is not None:
            event_bus.publish(
                "release.published",
                experiment_id=None,
                data={
                    "version": version,
                    "channel": channel,
                    "headline": headline,
                    "fulfils_request_ids": fulfilled,
                },
            )
        logger.info("github webhook: announced %s/%s to the fleet", channel, version)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "announced": True,
                "version": created.version,
                "channel": created.channel,
                "fulfilled_request_ids": fulfilled,
            },
        )

    return router
