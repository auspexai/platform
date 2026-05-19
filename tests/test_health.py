"""Tests for the M1+M3 health endpoints.

M1 verified status + version + server_time presence.
M3 keeps all three fields visible to every credential class (all three are
tagged `public`), so the behavior is unchanged but the filter is exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from auspexai_platform import __version__


def test_health_returns_ok_for_anonymous(client: TestClient) -> None:
    response = client.get("/api/v0/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_health_returns_ok_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    response = client.get(
        "/api/v0/health",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_health_includes_server_time(client: TestClient) -> None:
    response = client.get("/api/v0/health")
    body = response.json()
    parsed = datetime.fromisoformat(body["server_time"])
    assert parsed.tzinfo is not None
    delta = (datetime.now(UTC) - parsed).total_seconds()
    assert abs(delta) < 5, f"server_time more than 5s skewed: {body['server_time']}"


def test_public_health_endpoint_anonymous(client: TestClient) -> None:
    response = client.get("/api/v0/health/public")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_unknown_endpoint_returns_404(client: TestClient) -> None:
    response = client.get("/api/v0/does-not-exist")
    assert response.status_code == 404
