"""GET /api/v0/models/supported — the fleet's real inventory PLUS the curated
provisionable set (available / runnable / too_big / unknown). RAM-null-safe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from auspexai_platform.config import Config
from auspexai_platform.hf_catalog import CatalogModel, write_catalog
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
    assert body["catalog_source"] == "curated"  # no HF cache written → seed fallback


def test_uses_hf_cache_when_present(
    client: TestClient, config: Config, maintainer_token: str
) -> None:
    # A warm HF cache supersedes the curated seed as the provisionable set.
    write_catalog(
        config.hf_catalog_path,
        [
            CatalogModel(
                "meta-llama-3.1-8b-instruct-q4",
                "Meta Llama 3.1 8B Instruct",
                "Meta",
                8.0,
                "Q4_K_M",
                5.5,
                "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
            )
        ],
        fetched_at="2026-07-07T12:00:00+00:00",
    )
    body = client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json()
    assert body["catalog_source"] == "hf"
    assert body["catalog_fetched_at"] == "2026-07-07T12:00:00+00:00"
    by = _by_id(body)
    assert by["meta-llama-3.1-8b-instruct-q4"]["hf_repo"].startswith("bartowski/")
    # The curated-seed models are NOT the provisionable set when HF is warm.
    assert "phi-3.5-mini-instruct-q4" not in by


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
    # A model the worker HAS that isn't in the sized catalog must still SHOW (so the
    # maintainer sees what's on the fleet), but its runnability is UNKNOWN — presence
    # on disk is not runnability (you can download anything; loading it needs RAM we
    # can't verify for an unsized model). This is the deepseek-v4 case: a 156 GB file
    # stranded on a 7.4 GB mayhem must NOT read as "available".
    caps = {"models": ["deepseek-v4-gguf-q4"], "ram_total_gb": 8.0, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-bb", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert "deepseek-v4-gguf-q4" in by
    m = by["deepseek-v4-gguf-q4"]
    assert m["status"] == "unknown"  # unsized presence ⇒ runnability unconfirmed, NOT "available"
    assert m["on_worker_count"] == 1  # still visible: it's downloaded on the fleet
    assert m["in_catalog"] is False  # present on the fleet, not in the vetted set
    assert m["param_b"] is None and m["approx_ram_gb"] is None  # no curated metadata


def test_ram_blind_fleet_is_unknown_never_false_positive(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # A fleet where NO worker reports RAM can't confirm ANY model fits — so every
    # model is honestly `unknown` (never a false-positive "available/runnable" and
    # never a false "too_big"). Presence on disk doesn't upgrade that.
    caps = {"models": ["gemma-3-1b-it-q4"], "ram_total_gb": None, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-cc", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    assert by["gemma-3-1b-it-q4"]["status"] == "unknown"  # present but RAM unverifiable
    assert by["phi-3.5-mini-instruct-q4"]["status"] == "unknown"  # curated but RAM unverifiable
    assert all(v["status"] != "too_big" for v in by.values())  # can't over-claim too_big either


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


def test_present_but_too_big_is_too_big_not_available(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # THE core fix: a SIZED model sitting on a worker's disk whose RAM can't load it
    # must be `too_big`, never "available". gemma-2-27b-it-q4 (~16 GB) on a 7.4 GB
    # worker — exactly the deepseek/gemma-4 stranded-on-a-mayhem pattern.
    caps = {"models": ["gemma-2-27b-it-q4"], "ram_total_gb": 7.4, "auto_acquire": True}
    _heartbeat(worker_repository, "wkr-small", caps)
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    m = by["gemma-2-27b-it-q4"]
    assert m["status"] == "too_big"  # NOT "available", despite being on disk
    assert m["on_worker_count"] == 1  # it IS present — informational only
    assert m["fits_worker_count"] == 0  # but fits no worker's RAM


def test_runnable_reports_repl_capacity_fits_1_of_2(
    client: TestClient, maintainer_token: str, worker_repository
) -> None:
    # A model that fits only SOME workers is runnable, and fits_worker_count makes
    # the repl-capacity explicit (fits 1 ⇒ repl-1 only, not the whole fleet).
    _heartbeat(worker_repository, "wkr-s", {"ram_total_gb": 7.4, "auto_acquire": True})
    _heartbeat(worker_repository, "wkr-l", {"ram_total_gb": 24.0, "auto_acquire": True})
    by = _by_id(client.get("/api/v0/models/supported", headers=_mh(maintainer_token)).json())
    m = by["qwen2.5-14b-instruct-q4"]  # ~9 GB: fits the 24 GB worker, not the 7.4 GB one
    assert m["status"] == "runnable"
    assert m["fits_worker_count"] == 1  # repl-1 only
    assert m["ram_known_workers"] == 2
