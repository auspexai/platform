"""Zenodo DOI client (F4, ratified 2026-07-06 Q3).

Metadata-ONLY deposits, permanently: title, creators (from citation-consent
snapshots), the attestation root + Rekor link, the board/track URL. NO content
files ever — researcher-owned content gets its own separate DOI under the
researcher's identity/liability (the custody model), cross-linked via DataCite
relatedIdentifiers.

Config: `<state_dir>/zenodo.json` — `{"token": "...", "mode": "sandbox"}`
(the maintainer.token precedent: jason-owned, chmod 600, outside every repo).
A missing file or an unrecognized mode can never mint anything.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx

_BASES = {
    "sandbox": "https://sandbox.zenodo.org",
    "production": "https://zenodo.org",
}
TIMEOUT_S = 30.0


def _extract_doi(body: dict) -> str | None:
    """The DOI from a record/reserve response (top-level or under pids.doi)."""
    return body.get("doi") or ((body.get("pids") or {}).get("doi") or {}).get("identifier")


class ZenodoNotConfiguredError(Exception):
    """No zenodo.json, unreadable token, or mode not sandbox/production."""


class ZenodoError(Exception):
    """The Zenodo API refused a deposit/publish step."""


class ZenodoClient:
    def __init__(self, state_dir: Path):
        cfg_path = state_dir / "zenodo.json"
        try:
            cfg = json.loads(cfg_path.read_text())
            self._token = str(cfg["token"])
            self.mode = str(cfg.get("mode", ""))
        except (OSError, ValueError, KeyError) as e:
            raise ZenodoNotConfiguredError(f"zenodo.json unusable: {e}") from e
        if self.mode not in _BASES:
            raise ZenodoNotConfiguredError(f"zenodo mode {self.mode!r} is not sandbox/production")
        self._base = _BASES[self.mode]

    def mint_doi(
        self,
        metadata: dict,
        verification: dict | None = None,
        *,
        resume_record_id: str | None = None,
        on_draft: Callable[[str, str | None], None] | None = None,
    ) -> dict:
        """Create a METADATA-ONLY record (files disabled — the ratified Q3
        shape) via the modern records API and publish it. Returns
        {doi, record_url, mode}.

        Idempotent + resumable. The mint is a multi-step external transaction, so
        a failure after the irreversible publish (e.g. a lost final response)
        would, on a naive retry, mint a SECOND DOI for the same result. To make it
        exactly-once:

        - `on_draft(record_id, reserved_doi)` fires the moment the draft's DOI is
          reserved — BEFORE publish — so the caller can persist the record id and
          reconcile on a later retry.
        - `resume_record_id` reconciles against Zenodo instead of minting anew:
          already published → return that DOI (no duplicate); still a draft →
          resume the SAME draft (no new orphan, no second reserved DOI)."""
        headers = {"Authorization": f"Bearer {self._token}"}
        # Zenodo reserves true metadata-only records (files.enabled=false 400s at
        # publish for regular accounts). The compliant-in-spirit shape: ONE tiny
        # attestation.json — verification data (roots + Rekor ids + how-to-verify),
        # never experiment content (ratified Q3: content is the researcher's own
        # separate DOI).
        att_bytes = json.dumps(verification, indent=2).encode() if verification else b"{}"
        with httpx.Client(timeout=TIMEOUT_S) as client:
            fid: str | None = None
            if resume_record_id is not None:
                done = self._reconcile(client, headers, resume_record_id)
                if done is not None and "doi" in done:
                    return done  # already published on a prior attempt — no duplicate
                if done is not None and done.get("resume"):
                    fid = resume_record_id  # a live draft survived — resume it
            if fid is None:
                fid = self._create_and_reserve(client, headers, metadata, on_draft)
            self._ensure_attestation_file(client, headers, fid, att_bytes)
            body = self._publish(client, headers, fid)
        doi = _extract_doi(body)
        if not doi:
            raise ZenodoError("publish succeeded but no DOI in the response")
        return {
            "doi": doi,
            "record_url": (body.get("links") or {}).get("self_html"),
            "mode": self.mode,
        }

    def _reconcile(self, client, headers, record_id: str) -> dict | None:
        """Inspect an existing record before acting. Returns {doi, record_url,
        mode} if it already published (short-circuit), {'resume': True} if a live
        draft remains, or None if neither (mint fresh)."""
        pub = client.get(f"{self._base}/api/records/{record_id}", headers=headers)
        if pub.status_code == 200:
            body = pub.json()
            doi = _extract_doi(body)
            if body.get("is_published") and doi:
                return {
                    "doi": doi,
                    "record_url": (body.get("links") or {}).get("self_html"),
                    "mode": self.mode,
                }
        draft = client.get(f"{self._base}/api/records/{record_id}/draft", headers=headers)
        if draft.status_code == 200:
            return {"resume": True}
        return None

    def _create_and_reserve(self, client, headers, metadata: dict, on_draft) -> str:
        created = client.post(
            f"{self._base}/api/records",
            headers=headers,
            json={
                "access": {"record": "public", "files": "public"},
                "files": {"enabled": True},  # one attestation.json only — never content
                "metadata": metadata,
            },
        )
        if created.status_code not in (200, 201):
            raise ZenodoError(
                f"draft create failed: HTTP {created.status_code} {created.text[:300]}"
            )
        fid = str(created.json()["id"])
        # Reserve the DOI on the draft — without this, publish succeeds WITHOUT
        # registering any DOI (found live on the sandbox).
        reserved = client.post(f"{self._base}/api/records/{fid}/draft/pids/doi", headers=headers)
        if reserved.status_code not in (200, 201):
            raise ZenodoError(
                f"DOI reserve failed: HTTP {reserved.status_code} {reserved.text[:200]}"
            )
        # Persist the reserved draft BEFORE the irreversible publish, so a crash
        # here is resumable rather than a duplicate on retry.
        if on_draft is not None:
            on_draft(fid, _extract_doi(reserved.json()))
        return fid

    def _ensure_attestation_file(self, client, headers, fid: str, att_bytes: bytes) -> None:
        """Register + upload + commit attestation.json — tolerant of a partial
        prior attempt (a resumed draft may already have the file in some state)."""
        listing = client.get(f"{self._base}/api/records/{fid}/draft/files", headers=headers)
        state = None
        if listing.status_code == 200:
            for e in listing.json().get("entries") or []:
                if e.get("key") == "attestation.json":
                    state = e.get("status")  # "completed" once committed
                    break
        if state == "completed":
            return  # already uploaded + committed on a prior attempt
        if state is None:
            reg = client.post(
                f"{self._base}/api/records/{fid}/draft/files",
                headers=headers,
                json=[{"key": "attestation.json"}],
            )
            if reg.status_code not in (200, 201):
                raise ZenodoError(f"file register failed: HTTP {reg.status_code} {reg.text[:200]}")
        up = client.put(
            f"{self._base}/api/records/{fid}/draft/files/attestation.json/content",
            headers={**headers, "Content-Type": "application/octet-stream"},
            content=att_bytes,
        )
        if up.status_code not in (200, 201):
            raise ZenodoError(f"file upload failed: HTTP {up.status_code} {up.text[:200]}")
        commit = client.post(
            f"{self._base}/api/records/{fid}/draft/files/attestation.json/commit", headers=headers
        )
        if commit.status_code not in (200, 201):
            raise ZenodoError(f"file commit failed: HTTP {commit.status_code} {commit.text[:200]}")

    def _publish(self, client, headers, fid: str) -> dict:
        published = client.post(
            f"{self._base}/api/records/{fid}/draft/actions/publish", headers=headers
        )
        if published.status_code not in (200, 202):
            raise ZenodoError(
                f"publish failed: HTTP {published.status_code} {published.text[:300]}"
            )
        return published.json()


def experiment_doi_metadata(
    *,
    title: str,
    description_html: str,
    creators: list[dict],
    related_urls: list[str],
    contributors: list[str] | None = None,
) -> dict:
    """The RDM metadata shape for a metadata-only record."""
    from datetime import UTC, datetime

    return {
        "title": title,
        "publication_date": datetime.now(UTC).date().isoformat(),
        "resource_type": {"id": "dataset"},
        "description": description_html,
        "creators": creators
        or [{"person_or_org": {"type": "organizational", "name": "AuspexAI Network"}}],
        "rights": [{"id": "cc-by-4.0"}],
        "publisher": "AuspexAI",
        # Opted-in volunteer contributors (System B, forward-only consent snapshot).
        # DataCite "contributors" with type Other — the citable, permanent public
        # credit surface that replaces a standalone contributors page (USER 2026-07-06).
        "contributors": [
            {"person_or_org": {"type": "personal", "family_name": c}, "role": {"id": "other"}}
            for c in (contributors or [])
        ],
        "related_identifiers": [
            {"identifier": u, "scheme": "url", "relation_type": {"id": "issupplementedby"}}
            for u in related_urls
        ],
    }
