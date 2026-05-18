"""Tests for the M1 health endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from auspexai_platform import __version__
from auspexai_platform.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v0/health")
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


def test_public_health_endpoint_exists(client: TestClient) -> None:
    response = client.get("/api/v0/health/public")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_unknown_endpoint_returns_404(client: TestClient) -> None:
    response = client.get("/api/v0/does-not-exist")
    assert response.status_code == 404
