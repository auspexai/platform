"""RekorClient — rekord:0.0.1 entry construction (live-API-shape regression).

The live rekor.sigstore.dev API rejects our artifacts under the `intoto`
kind (requires a DSSE JSON envelope; ours is COSE CBOR) and under the
`cose`/`hashedrekord` kinds (no pure-Ed25519 support) — verified against
the live API 2026-06-09. These tests pin the `rekord` entry shape and the
detached-signature contract so a regression is caught without network.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.receipts.rekor import RekorClient
from auspexai_platform.receipts.signing import SigningKey


def _signing_key() -> SigningKey:
    return SigningKey._from_private(Ed25519PrivateKey.generate())


def test_record_posts_rekord_entry_with_valid_detached_signature():
    key = _signing_key()
    blob = b"\x84\x58\x46not-a-real-cose-blob-but-arbitrary-bytes"
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json={"uuid-abc": {"logIndex": 123}})

    client = RekorClient(
        "https://rekor.example",
        signing_key=key,
        transport=httpx.MockTransport(handler),
    )
    entry = client.record(blob)

    assert entry.log_index == 123
    assert entry.entry_uuid == "uuid-abc"
    assert captured["url"].endswith("/api/v1/log/entries")

    body = captured["body"]
    assert body["kind"] == "rekord"
    assert body["apiVersion"] == "0.0.1"
    assert base64.b64decode(body["spec"]["data"]["content"]) == blob
    assert body["spec"]["signature"]["format"] == "x509"

    # Rekor verifies the detached signature server-side at upload; pin that
    # the signature we send actually verifies under the PEM key we send.
    sig = base64.b64decode(body["spec"]["signature"]["content"])
    pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
    pub = serialization.load_pem_public_key(pem)
    pub.verify(sig, blob)  # raises InvalidSignature on mismatch

    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert raw.hex() == key.pubkey_hex


def test_record_without_signing_key_raises():
    client = RekorClient("https://rekor.example")
    with pytest.raises(ValueError, match="signing key"):
        client.record(b"blob")
