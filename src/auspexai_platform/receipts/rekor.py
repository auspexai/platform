"""Rekor transparency log client for receipt recording.

Posts COSE-signed in-toto Statements to the Sigstore Rekor instance and
returns the log entry metadata (log index + entry UUID). The coordinator
records these on the receipt's result_hash_anchors so verifiers can check
the transparency log independently.

Uses httpx (already a platform dependency) for HTTP calls. Designed for
synchronous use from the receipt issuance path; async upgrade is trivial
if needed.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

# Sentinel anchor values for a not-yet-Rekor-anchored artifact (dev/lab mode or
# pre-anchor). The A2 backfill sweep keys "unanchored" on the UUID sentinel.
REKOR_PLACEHOLDER_LOG_INDEX = 0
REKOR_PLACEHOLDER_UUID = "lab-mode-no-rekor"


@dataclass(frozen=True)
class RekorEntry:
    """Metadata returned by Rekor after a successful log entry."""

    log_index: int
    entry_uuid: str


class RekorClient:
    """Minimal Rekor HTTP client for posting COSE-signed attestations."""

    def __init__(self, rekor_url: str = DEFAULT_REKOR_URL, timeout: float = 10.0):
        self.rekor_url = rekor_url.rstrip("/")
        self.timeout = timeout

    def record(self, cose_blob: bytes) -> RekorEntry:
        """Post a COSE-signed blob to Rekor as an intoto:0.0.2 entry.

        Returns the log index and entry UUID on success.
        Raises httpx.HTTPError or ValueError on failure.
        """
        payload = {
            "apiVersion": "0.0.2",
            "kind": "intoto",
            "spec": {
                "content": {
                    "envelope": base64.b64encode(cose_blob).decode("ascii"),
                    "payloadType": "application/vnd.in-toto+cbor",
                }
            },
        }
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(
                f"{self.rekor_url}/api/v1/log/entries",
                json=payload,
            )
            r.raise_for_status()
            body = r.json()

        entry_uuid = next(iter(body.keys()))
        entry_data = body[entry_uuid]
        log_index = entry_data.get("logIndex", 0)
        logger.info("rekor: recorded entry logIndex=%d uuid=%s", log_index, entry_uuid)
        return RekorEntry(log_index=log_index, entry_uuid=entry_uuid)


class NoOpRekorClient:
    """Placeholder client for dev/lab mode — returns placeholder values
    without contacting Rekor."""

    def record(self, cose_blob: bytes) -> RekorEntry:
        return RekorEntry(log_index=REKOR_PLACEHOLDER_LOG_INDEX, entry_uuid=REKOR_PLACEHOLDER_UUID)
