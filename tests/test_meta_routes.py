"""Tests for the public root-discovery + API-docs routes.

Bare `/` returns a friendly discovery doc (HTML to browsers, JSON to programs)
and is public. `/docs`, `/redoc`, and `/openapi.json` are **maintainer-only**
(2026-06-19, defense-in-depth): the OpenAPI document maps the full 83-path API
surface incl. maintainer actions (promote/demote/quarantine/…), so it is not
published to the public even though tenant data is row-scoped + field-filtered
server-side regardless. This reverses the `3cf45fa` public-schema decision in
favor of not advertising the attack surface; the maintainer reaches the docs
through the operator console's authed same-origin proxy.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform import __version__


def test_root_returns_json_for_program_clients(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "AuspexAI Coordinator"
    assert body["version"] == __version__
    assert "health" in body["public_endpoints"]
    assert body["github_org"] == "https://github.com/auspexai"
    assert "authorized_signers" in body
    assert "worker_releases" in body


def test_root_returns_html_when_browser_requests_html(client: TestClient) -> None:
    response = client.get("/", headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "AuspexAI Coordinator" in response.text
    assert "<!doctype html>" in response.text.lower() or "<html" in response.text.lower()


def test_root_returns_html_for_browser_accept_with_quality(client: TestClient) -> None:
    # Real browsers send a complex Accept like `text/html,application/xhtml+xml,*/*;q=0.8`.
    response = client.get(
        "/",
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")


def test_openapi_requires_maintainer(client: TestClient) -> None:
    """The OpenAPI schema is maintainer-only (2026-06-19): an unauthenticated
    request is rejected (403, the coordinator's auth-failure status) — the
    schema isn't published publicly."""
    response = client.get("/openapi.json")
    assert response.status_code == 403


def test_docs_requires_maintainer(client: TestClient) -> None:
    assert client.get("/docs").status_code == 403


def test_redoc_requires_maintainer(client: TestClient) -> None:
    assert client.get("/redoc").status_code == 403


def test_openapi_returns_schema_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    response = client.get(
        "/openapi.json",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "/api/v0/health/public" in schema["paths"]


def test_docs_returns_swagger_ui_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    response = client.get(
        "/docs",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    assert "swagger" in response.text.lower()


def test_redoc_returns_redoc_for_maintainer(client: TestClient, maintainer_token: str) -> None:
    response = client.get(
        "/redoc",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    assert "redoc" in response.text.lower()
