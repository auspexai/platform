"""BodyLimitAndSecurityHeaders — the origin body-size cap + security headers
added for the open-beta public exposure (main.py). Asserted on responses that
don't depend on DB schema, so the bare-app fixture stays simple."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _has_security_headers(headers) -> bool:
    return (
        headers.get("x-content-type-options") == "nosniff"
        and headers.get("x-frame-options") == "DENY"
        and headers.get("referrer-policy") == "no-referrer"
        and "strict-transport-security" in headers
    )


def test_security_headers_on_routed_response() -> None:
    # A 404 still flows out through the middleware → carries the headers.
    r = _client().get("/api/v0/__definitely_not_a_route__")
    assert r.status_code == 404
    assert _has_security_headers(r.headers)


def test_oversized_body_rejected_before_routing_with_headers() -> None:
    # A >2 MiB body is rejected 413 by the middleware before the route's auth
    # dependency can buffer it (closes the buffer-before-auth DoS), and the
    # middleware-built 413 carries the security headers too.
    r = _client().post(
        "/api/v0/experiments",
        headers={"signature-input": "x"},  # would force await request.body() pre-auth
        content=b"x" * (3 * 1024 * 1024),
    )
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"
    assert _has_security_headers(r.headers)


def test_packages_upload_exempt_from_default_cap() -> None:
    # /packages owns its own (larger, hardened) size check — the 2 MiB default
    # must NOT clip it, so a 3 MiB body is not the middleware's 413.
    r = _client().post(
        "/api/v0/packages",
        headers={"signature-input": "x"},
        content=b"x" * (3 * 1024 * 1024),
    )
    assert not (r.status_code == 413 and r.json().get("error") == "payload_too_large")
