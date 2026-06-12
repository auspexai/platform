"""Live-Rekor release smoke (§9 #47 follow-up, external-review rec).

Records ONE throwaway entry in the PUBLIC rekor.sigstore.dev transparency log
with the real `RekorClient` payload shape, then fetches it back — pinning the
beliefs our mocks encode against the actual service:

  - the rekord:0.0.1 + detached-Ed25519 payload is still accepted (the
    2026-06-09 discovery: cose/hashedrekord kinds REJECT pure-Ed25519);
  - the create-entry response still carries `verification.inclusionProof`
    (EB-1 v0.1.28 captures + persists it for offline bundle verification —
    until this smoke, that capture had only ever seen mocked responses);
  - the entry is retrievable by UUID at the cited logIndex.

Opt-in: skipped unless AUSPEXAI_LIVE_REKOR=1 (network + a permanent public log
write are not normal-CI behavior). Run as a release-checklist step:

    AUSPEXAI_LIVE_REKOR=1 uv run pytest -m live_rekor
"""

from __future__ import annotations

import os
import secrets

import httpx
import pytest

from auspexai_platform.receipts.rekor import REKOR_PLACEHOLDER_UUID, RekorClient
from auspexai_platform.receipts.signing import load_or_generate_signing_key

pytestmark = [
    pytest.mark.live_rekor,
    pytest.mark.skipif(
        os.environ.get("AUSPEXAI_LIVE_REKOR") != "1",
        reason="live public-Rekor write; opt in with AUSPEXAI_LIVE_REKOR=1 (release checklist)",
    ),
    pytest.mark.timeout(120),
]

REKOR_URL = "https://rekor.sigstore.dev"


def test_record_and_fetch_round_trip(tmp_path):
    # Throwaway key + unique blob — this is a smoke of the WIRE CONTRACT, not
    # of our production key (which never leaves the coordinator).
    key = load_or_generate_signing_key(tmp_path / "smoke.key")
    blob = b"auspexai release smoke (throwaway, ignore): " + secrets.token_bytes(16)

    entry = RekorClient(REKOR_URL, signing_key=key).record(blob)

    assert entry.entry_uuid != REKOR_PLACEHOLDER_UUID
    assert entry.log_index > 0
    # EB-1: the proof must be in the create-entry response, with the fields the
    # persisted-proof/offline path consumes.
    assert entry.inclusion_proof, "live Rekor response missing verification.inclusionProof"
    for field in ("hashes", "rootHash", "treeSize", "logIndex", "checkpoint"):
        assert field in entry.inclusion_proof, f"inclusionProof missing {field!r}"

    # Round-trip: the entry is retrievable by UUID at the cited index.
    r = httpx.get(f"{REKOR_URL}/api/v1/log/entries/{entry.entry_uuid}", timeout=30)
    r.raise_for_status()
    fetched = r.json()
    assert entry.entry_uuid in fetched
    assert fetched[entry.entry_uuid]["logIndex"] == entry.log_index
