"""Rate-limiting for anonymous-public endpoints on the coordinator.

Phase 2 open-beta posture: minimal defense-in-depth for the routes any
internet visitor can hit. The three endpoints decorated below are the
ones that create coordinator state (`/workers/enroll` → durable worker
row; `/accounts/oauth/exchange` → talks to GitHub on caller's behalf,
mints binding token) or do expensive computation
(`/receipts/verify` → COSE-sign1 verify + Sigstore chain inspection).
Authenticated routes (worker heartbeat / assignment poll, researcher
job-submission, maintainer) are not rate-limited here — their auth
already bounds the abuse surface, and they're the load-bearing happy
paths where adding a limit creates more risk than it prevents at Phase 2
scale.

In-memory backend: one limiter instance per coord process. With one
coord process (single-replica deployment on rage), this is a single
source of truth. If we ever scale to multiple coord replicas (Phase 4+
HA per §5.13), the in-memory backend would need to be swapped for a
shared store (Redis); the slowapi interface stays the same.

IP extraction respects `CF-Connecting-IP`: the coord sits behind
Cloudflare Tunnel, so `request.client.host` is a Cloudflare edge IP, not
the real volunteer's IP. Cloudflare sets `CF-Connecting-IP` to the real
client IP for any tunnel-forwarded request. The fallback to
`get_remote_address` is for tests + direct-localhost requests where the
header isn't set.
"""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _client_key(request: Request) -> str:
    """Return the rate-limiting key for `request`.

    Prefers `CF-Connecting-IP` (the real client IP behind Cloudflare
    Tunnel). Falls back to the raw remote-address (for tests + any
    request that doesn't traverse the tunnel).
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    return get_remote_address(request)


# Module-level singleton. Decorators on route handlers reference this
# instance at import time. `create_app()` mounts it on `app.state.limiter`
# and wires the RateLimitExceeded exception handler.
#
# No `default_limits` here: slowapi 0.1.9 surprised us by applying
# default_limits *in addition to* per-route limits AND tracking them in
# a global-per-IP bucket that caps cross-route activity at the default.
# A catch-all 600/min on any decorated route would mean a worker doing
# legitimate heartbeats every 60s alongside an assignment-poll every
# 30s would burn the bucket within a minute. Per-route limits are the
# bounded surface we actually want here.
limiter = Limiter(key_func=_client_key)


def reset_for_tests() -> None:
    """Clear all rate-limit state. Called from pytest fixtures so each
    test starts with a fresh window — otherwise tests that exhaust a
    bucket leak state into subsequent tests in the same process.

    Resets BOTH the storage (counters) AND the per-route registry. The
    registry needs clearing because each test fixture's `create_app()`
    call re-decorates the route handlers, and slowapi's @limiter.limit
    appends to the per-route list with no idempotency — without this
    reset, each test inherits N+1 stacked copies of every decorator,
    which slowapi treats as N+1 separate buckets and halves/thirds/...
    the effective limit.
    """
    limiter.reset()
    limiter._route_limits.clear()
    limiter._default_limits.clear()
