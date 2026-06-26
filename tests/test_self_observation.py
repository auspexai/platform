"""AUD-1 (A9 audit): the firewall-#5 self-observation endpoint.

`signals.compute_self_observation` existed but had no production caller, so the
equal-trust flip could not be observed live. `GET /api/v0/self-observation` is
that caller — maintainer-only, read-only, returns the five A5 signals.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_self_observation_requires_maintainer(client: TestClient) -> None:
    """Unauthenticated request is rejected (403, the coordinator's auth-failure status)."""
    assert client.get("/api/v0/self-observation").status_code == 403


def test_self_observation_returns_signals_for_maintainer(
    client: TestClient, maintainer_token: str
) -> None:
    response = client.get(
        "/api/v0/self-observation",
        headers={"Authorization": f"Bearer {maintainer_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["firewall"] == 5
    signals = body["signals"]
    # All five A5 signals are present (the snapshot is honest-empty at single-maintainer scale).
    assert set(signals) == {
        "autonomy",
        "fleet_diversity",
        "trust_flow",
        "vouch_topology",
        "divergence_health",
    }
