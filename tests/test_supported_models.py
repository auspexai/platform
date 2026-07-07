"""GET /api/v0/models/supported — the top-down curated catalog overlaid with
the live fleet (served / runnable / too_big / unknown). RAM-null-safe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.supported_models import SUPPORTED_MODELS


def _mh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _by_id(body: dict) -> dict[str, dict]:
    return {m["model_id"]: m for m in body["models"]}


def test_lists_every_supported_model_even_with_no_workers(
    client: TestClient, maintainer_token: str
) -> None:
    r = client.get("/api/v0/models/supported", headers=_mh(maintainer_token))
    assert r.status_code == 200, r.text
    body = r.json()
    got = {m["model_id"] for m in body["models"]}
    assert got == {m.model_id for m in SUPPORTED_MODELS}  # full menu regardless of fleet
    # No active workers → nothing served, capacity unjudgeable → all 'unknown'.
    assert all(m["status"] == "unknown" for m in body["models"])
    assert body["fleet_can_auto_acquire"] is False


def test_served_model_is_green_and_counted(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    caps = {"models": ["gemma-3-1b-it-q4"], "ram_total_gb": 16.0, "auto_acquire": True}
    worker_repository.enroll(worker_id="wkr-s1", pubkey_hex="b1" * 32, capabilities=caps)
    worker_repository.record_heartbeat("wkr-s1", capabilities=caps)
    body = client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json()
    m = _by_id(body)["gemma-3-1b-it-q4"]
    assert m["status"] == "served"
    assert m["served_worker_count"] == 1
    assert body["fleet_can_auto_acquire"] is True


def test_ram_null_is_safe_auto_acquire_makes_unserved_runnable(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # A real-world heartbeat: RAM unreported (null) but auto_acquire on.
    caps = {"models": ["gemma-3-1b-it-q4"], "ram_total_gb": None, "auto_acquire": True}
    worker_repository.enroll(worker_id="wkr-n1", pubkey_hex="c1" * 32, capabilities=caps)
    worker_repository.record_heartbeat("wkr-n1", capabilities=caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert by["gemma-3-1b-it-q4"]["status"] == "served"
    # Every OTHER supported model: not served, RAM unknown, fleet auto-acquires →
    # 'runnable' (benefit of the doubt), never 'too_big'.
    others = [v for k, v in by.items() if k != "gemma-3-1b-it-q4"]
    assert others and all(v["status"] == "runnable" for v in others)
    assert all(v["status"] != "too_big" for v in by.values())


def test_ram_reported_gates_too_big(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # Only a tiny worker (1 GB) online → the big models can't fit anywhere.
    caps = {"models": [], "ram_total_gb": 1.0, "auto_acquire": True}
    worker_repository.enroll(worker_id="wkr-tiny", pubkey_hex="d1" * 32, capabilities=caps)
    worker_repository.record_heartbeat("wkr-tiny", capabilities=caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    # A 4.2 GB model can't fit a 1 GB worker → too_big (RAM known, fits 0).
    assert by["phi-3.5-mini-instruct-q4"]["status"] == "too_big"
    assert by["phi-3.5-mini-instruct-q4"]["fits_worker_count"] == 0
    # A sub-1GB model fits → runnable (auto-acquire).
    assert by["smollm2-360m-instruct-q4"]["status"] == "runnable"
    assert by["smollm2-360m-instruct-q4"]["fits_worker_count"] == 1


def test_requires_auth(client: TestClient) -> None:
    assert client.get("/api/v0/models/supported").status_code in (401, 403)
