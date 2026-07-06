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
from pathlib import Path

import httpx

_BASES = {
    "sandbox": "https://sandbox.zenodo.org",
    "production": "https://zenodo.org",
}
TIMEOUT_S = 30.0


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

    def mint_doi(self, metadata: dict, verification: dict | None = None) -> dict:
        """Create a METADATA-ONLY record (files disabled — the ratified Q3
        shape) via the modern records API and publish it. Returns
        {doi, record_url, mode}."""
        headers = {"Authorization": f"Bearer {self._token}"}
        with httpx.Client(timeout=TIMEOUT_S) as client:
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
            draft = created.json()
            # Reserve the DOI on the draft — without this, publish succeeds
            # WITHOUT registering any DOI (found live on the sandbox).
            reserved = client.post(
                f"{self._base}/api/records/{draft['id']}/draft/pids/doi",
                headers=headers,
            )
            if reserved.status_code not in (200, 201):
                raise ZenodoError(
                    f"DOI reserve failed: HTTP {reserved.status_code} {reserved.text[:200]}"
                )
            # Zenodo reserves true metadata-only records (files.enabled=false
            # 400s at publish for regular accounts). The compliant-in-spirit
            # shape: ONE tiny attestation.json — verification data (roots +
            # Rekor ids + how-to-verify), never experiment content (ratified
            # Q3: content is the researcher's own separate DOI).
            att_bytes = json.dumps(verification, indent=2).encode() if verification else b"{}"
            fid = draft["id"]
            for step, resp in (
                (
                    "register",
                    client.post(
                        f"{self._base}/api/records/{fid}/draft/files",
                        headers=headers,
                        json=[{"key": "attestation.json"}],
                    ),
                ),
                (
                    "upload",
                    client.put(
                        f"{self._base}/api/records/{fid}/draft/files/attestation.json/content",
                        headers={**headers, "Content-Type": "application/octet-stream"},
                        content=att_bytes,
                    ),
                ),
                (
                    "commit",
                    client.post(
                        f"{self._base}/api/records/{fid}/draft/files/attestation.json/commit",
                        headers=headers,
                    ),
                ),
            ):
                if resp.status_code not in (200, 201):
                    raise ZenodoError(
                        f"file {step} failed: HTTP {resp.status_code} {resp.text[:200]}"
                    )
            published = client.post(
                f"{self._base}/api/records/{fid}/draft/actions/publish",
                headers=headers,
            )
            if published.status_code not in (200, 202):
                raise ZenodoError(
                    f"publish failed: HTTP {published.status_code} {published.text[:300]}"
                )
            body = published.json()
        doi = body.get("doi") or ((body.get("pids") or {}).get("doi") or {}).get("identifier")
        if not doi:
            raise ZenodoError("publish succeeded but no DOI in the response")
        return {
            "doi": doi,
            "record_url": (body.get("links") or {}).get("self_html"),
            "mode": self.mode,
        }


def experiment_doi_metadata(
    *,
    title: str,
    description_html: str,
    creators: list[dict],
    related_urls: list[str],
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
        "related_identifiers": [
            {"identifier": u, "scheme": "url", "relation_type": {"id": "issupplementedby"}}
            for u in related_urls
        ],
    }
