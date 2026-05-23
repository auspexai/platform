"""Tests for slowapi rate limits on anonymous-public coord endpoints.

Three routes have explicit limits (per `auspexai_platform.rate_limit`):
  - POST /api/v0/workers/enroll          → 10/hour per IP
  - POST /api/v0/accounts/oauth/exchange → 30/hour per IP
  - POST /api/v0/receipts/verify         → 60/minute per IP

Test strategy: send N+1 requests of each type and confirm the first N
succeed (or at least don't earn 429 — they may earn other status codes
based on body validity) and the N+1th earns 429. The conftest
`_reset_rate_limiter_between_tests` autouse fixture clears state at the
start of each test so the bucket starts empty.

IP-isolation is exercised by varying the `CF-Connecting-IP` header,
which `_client_key` in `rate_limit.py` prefers over `get_remote_address`.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def _enroll_payload() -> dict:
    """Fresh enrollable worker payload — each call uses a new pubkey so
    the request body isn't itself the source of duplicate-key 409s."""
    priv = Ed25519PrivateKey.generate()
    return {
        "pubkey_hex": priv.public_key().public_bytes_raw().hex(),
        "capabilities": {"os": "linux"},
    }


def test_enroll_429_after_10_in_one_hour(client: TestClient) -> None:
    # Hammer one IP. 10 enrollments per hour is the limit.
    for i in range(10):
        r = client.post(
            "/api/v0/workers/enroll",
            json=_enroll_payload(),
            headers={"CF-Connecting-IP": "203.0.113.10"},
        )
        # Any non-429 status is fine — we only care about not hitting the
        # limit yet. Real 201s here confirm the limit hasn't engaged.
        assert r.status_code != 429, f"enroll {i + 1}/10 hit rate limit unexpectedly: {r.text}"

    # 11th hit on the same IP should be 429.
    r = client.post(
        "/api/v0/workers/enroll",
        json=_enroll_payload(),
        headers={"CF-Connecting-IP": "203.0.113.10"},
    )
    assert r.status_code == 429
    # slowapi's default body shape:
    assert "Rate limit exceeded" in r.text or "10 per" in r.text


def test_enroll_limit_is_per_ip(client: TestClient) -> None:
    """A different IP gets its own bucket."""
    # IP A exhausts its 10 enrollments
    for _ in range(10):
        client.post(
            "/api/v0/workers/enroll",
            json=_enroll_payload(),
            headers={"CF-Connecting-IP": "203.0.113.20"},
        )
    # 11th from IP A → 429
    r_blocked = client.post(
        "/api/v0/workers/enroll",
        json=_enroll_payload(),
        headers={"CF-Connecting-IP": "203.0.113.20"},
    )
    assert r_blocked.status_code == 429
    # But IP B can still enroll
    r_ok = client.post(
        "/api/v0/workers/enroll",
        json=_enroll_payload(),
        headers={"CF-Connecting-IP": "198.51.100.30"},
    )
    assert r_ok.status_code != 429


def test_oauth_exchange_429_after_30_in_one_hour(client: TestClient) -> None:
    # Exhaust the 30/hour bucket. Each call carries an invalid token; the
    # endpoint returns 401, not 429, until the bucket fills. The
    # rate-limit decorator fires BEFORE the auth path, so once the bucket
    # is exhausted we get 429 even on the same invalid token.
    payload = {"idp": "github", "access_token": "not-a-real-token"}
    for i in range(30):
        r = client.post(
            "/api/v0/accounts/oauth/exchange",
            json=payload,
            headers={"CF-Connecting-IP": "203.0.113.40"},
        )
        assert r.status_code != 429, f"oauth exchange {i + 1}/30 hit rate limit unexpectedly"

    r = client.post(
        "/api/v0/accounts/oauth/exchange",
        json=payload,
        headers={"CF-Connecting-IP": "203.0.113.40"},
    )
    assert r.status_code == 429


def test_receipts_verify_429_after_60_in_one_minute(client: TestClient) -> None:
    # 60/minute is the limit. Each call carries a malformed base64 body;
    # the endpoint returns 400, not 429, until the bucket fills.
    payload = {"receipt_cose_b64": "not-real-base64-!!"}
    for i in range(60):
        r = client.post(
            "/api/v0/receipts/verify",
            json=payload,
            headers={"CF-Connecting-IP": "203.0.113.50"},
        )
        assert r.status_code != 429, f"receipts/verify {i + 1}/60 hit rate limit unexpectedly"

    r = client.post(
        "/api/v0/receipts/verify",
        json=payload,
        headers={"CF-Connecting-IP": "203.0.113.50"},
    )
    assert r.status_code == 429


def test_health_endpoint_is_not_rate_limited(client: TestClient) -> None:
    """The catch-all default limit (600/min) shouldn't bite legit polling
    of health from a single IP at reasonable cadence. 100 requests in
    quick succession should all succeed."""
    for _ in range(100):
        r = client.get(
            "/api/v0/health/public",
            headers={"CF-Connecting-IP": "203.0.113.60"},
        )
        assert r.status_code == 200
