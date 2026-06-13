"""§9 #13b / manifest v0_2 M3 — served-weights digest enforcement.

The result-set attestation proves the bytes ran deterministically and were
signed; it does NOT prove the worker served the *declared* model (§11 amendment
2). When a manifest model declares `expected_gguf_sha256`, the coordinator
checks the worker-reported served digest (heartbeat-declared capabilities —
coordinator-asserted, the current trust posture; per-unit-signed digests are the
§41 untrusted-scale hardening) against it and REJECTS a mismatch. That makes
"the declared model provably ran", which unlocks cross-model PERFORMANCE
auto-approval (§9 #48). A manifest pinning nothing ⇒ behavioral-only (status quo);
the check is dormant until a manifest pins AND the (rolled) worker reports
`served_model_digests`.
"""

from __future__ import annotations

from typing import Any


def served_weights_verdict(
    manifest_json: dict[str, Any], served_digests: dict[str, str] | None
) -> str | None:
    """`None` when OK — no model pins a digest, or every pinned model's served
    digest matches. Otherwise a short mismatch reason (for the 409 + audit). A
    pinned model with no reported served digest is a mismatch (fail-closed):
    you cannot prove the declared model ran without the worker reporting one."""
    served = served_digests or {}
    for model in manifest_json.get("models") or []:
        expected = model.get("expected_gguf_sha256")
        if not expected:
            continue
        mid = model.get("id")
        got = served.get(mid)
        if got is None:
            return f"model {mid!r} pins served weights but the worker reported no served digest"
        if got != expected:
            return f"model {mid!r} served digest {got[:12]}... != declared {expected[:12]}..."
    return None
