"""Rekor transparency log client for receipt recording.

Anchors COSE-signed attestation artifacts in the Sigstore Rekor instance and
returns the log entry metadata (log index + entry UUID). The coordinator
records these on the attestation row so verifiers can check the transparency
log independently.

Entry kind = `rekord` (artifact + detached signature + public key), NOT
`intoto` or `cose`: verified against the live rekor.sigstore.dev API
2026-06-09 — the `intoto` kind requires a DSSE JSON envelope (ours is COSE
CBOR), and both the `cose` and `hashedrekord` kinds reject Ed25519 keys
("unsupported algorithm type ed25519.PublicKey" / digest-class mismatch).
`rekord` carries the full artifact content, so Rekor can verify a *pure*
Ed25519 signature server-side at upload. The detached signature is made by
the same operational signing key that signed the COSE blob internally; the
canonicalized log entry retains sha256(artifact) + signature + public key.

Uses httpx (already a platform dependency) for HTTP calls. Designed for
synchronous use from the backfill sweep (the sole real-Rekor caller —
anchor-the-aggregate, plan L2); async upgrade is trivial if needed.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

import httpx

from auspexai_platform.receipts.signing import SigningKey

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
    """Minimal Rekor HTTP client for anchoring COSE-signed attestations.

    Requires the coordinator's signing key: the `rekord` entry kind carries a
    detached signature over the artifact bytes, which Rekor verifies at upload.
    `transport` is a testability seam (httpx.MockTransport) — None uses real HTTP.
    """

    def __init__(
        self,
        rekor_url: str = DEFAULT_REKOR_URL,
        timeout: float = 10.0,
        *,
        signing_key: SigningKey | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self.rekor_url = rekor_url.rstrip("/")
        self.timeout = timeout
        self.signing_key = signing_key
        self.transport = transport

    def record(self, cose_blob: bytes) -> RekorEntry:
        """Anchor a COSE-signed blob in Rekor as a rekord:0.0.1 entry.

        The detached Ed25519 signature over the blob bytes is made with the
        coordinator signing key (the same key that signed the blob internally).
        Returns the log index and entry UUID on success.
        Raises httpx.HTTPError or ValueError on failure.
        """
        if self.signing_key is None:
            raise ValueError(
                "RekorClient.record requires the coordinator signing key "
                "(rekord entries carry a detached signature Rekor verifies at upload)"
            )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        detached_sig = self.signing_key.private_key.sign(cose_blob)
        public_key_pem = self.signing_key.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        payload = {
            "apiVersion": "0.0.1",
            "kind": "rekord",
            "spec": {
                "data": {"content": base64.b64encode(cose_blob).decode("ascii")},
                "signature": {
                    "format": "x509",
                    "content": base64.b64encode(detached_sig).decode("ascii"),
                    "publicKey": {"content": base64.b64encode(public_key_pem).decode("ascii")},
                },
            },
        }
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
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
