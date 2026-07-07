"""GET /api/v0/models/supported — the fleet's real inventory PLUS the curated
provisionable set (available / runnable / too_big / unknown). RAM-null-safe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.supported_models import SUPPORTED_MODELS


def _mh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _by_id(body: dict) -> dict[str, dict]:
    return {m["model_id"]: m for m in body["models"]}


def _heartbeat(worker_repository, wid: str, caps: dict) -> None:
    worker_repository.enroll(worker_id=wid, pubkey_hex=(wid[-2:] * 32)[:64], capabilities=caps)
    worker_repository.record_heartbeat(wid, capabilities=caps)


def test_no_workers_shows_curated_set_as_unknown(client: TestClient, maintainer_token: str) -> None:
    body = client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json()
    got = {m["model_id"] for m in body["models"]}
    # With no fleet, the list is exactly the curated set, capacity unjudgeable.
    assert got == {m.model_id for m in SUPPORTED_MODELS}
    assert all(m["status"] == "unknown" and m["in_catalog"] for m in body["models"])
    assert body["fleet_can_auto_acquire"] is False


def test_present_model_is_available_and_counted(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    caps = {"models": ["gemma-3-1b-it-q4"], "ram_total_gb": 16.0, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-aa", caps)
    m = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())[
        "gemma-3-1b-it-q4"
    ]
    assert m["status"] == "available"
    assert m["on_worker_count"] == 1
    assert m["in_catalog"] is True


def test_non_curated_fleet_model_appears(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # A model the worker HAS that isn't in the curated catalog must still show —
    # this is the bug the maintainer caught (deepseek-v4 on the fleet, missing).
    caps = {"models": ["deepseek-v4-gguf-q4"], "ram_total_gb": 8.0, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-bb", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert "deepseek-v4-gguf-q4" in by
    m = by["deepseek-v4-gguf-q4"]
    assert m["status"] == "available"
    assert m["on_worker_count"] == 1
    assert m["in_catalog"] is False  # present on the fleet, not in the vetted set
    assert m["param_b"] is None and m["approx_ram_gb"] is None  # no curated metadata


def test_ram_null_safe_unserved_curated_is_runnable(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    caps = {"models": ["gemma-3-1b-it-q4"], "ram_total_gb": None, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-cc", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert by["gemma-3-1b-it-q4"]["status"] == "available"
    # Curated-but-not-present, RAM unknown, auto-acquire → runnable, never too_big.
    assert by["phi-3.5-mini-instruct-q4"]["status"] == "runnable"
    assert all(v["status"] != "too_big" for v in by.values())


def test_ram_reported_gates_too_big(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # A 7.44 GB fleet (like the real mayhems): the large curated tier can't fit.
    caps = {"models": [], "ram_total_gb": 7.44, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-dd", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert by["llama-3.3-70b-instruct-q4"]["status"] == "too_big"  # 42 GB > 7.44
    assert by["qwen2.5-14b-instruct-q4"]["status"] == "too_big"  # 9 GB > 7.44
    assert by["mistral-7b-instruct-q4"]["status"] == "runnable"  # 5 GB fits
    assert by["gemma-3-1b-it-q4"]["status"] == "runnable"  # small, fits


def test_requires_auth(client: TestClient) -> None:
    assert client.get("/api/v0/models/supported").status_code in (401, 403)
