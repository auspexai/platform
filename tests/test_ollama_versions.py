"""The coordinator's proactive stale-Ollama signal (ollama_versions +
_worker_to_response surfacing)."""

from __future__ import annotations

from types import SimpleNamespace

from auspexai_platform.api.workers import _worker_to_response
from auspexai_platform.ollama_versions import (
    RECOMMENDED_MIN_OLLAMA,
    ollama_update_recommended,
)


def test_below_floor_is_flagged() -> None:
    # The Jetson versions that stranded phi/qwen3.
    assert ollama_update_recommended("0.17.7") is True
    assert ollama_update_recommended("0.18.2") is True
    assert ollama_update_recommended("0.9.0") is True


def test_at_or_above_floor_is_not_flagged() -> None:
    assert ollama_update_recommended("0.30.11") is False  # the Mac
    assert ollama_update_recommended(RECOMMENDED_MIN_OLLAMA) is False
    assert ollama_update_recommended("1.0.0") is False


def test_unknown_never_flags() -> None:
    assert ollama_update_recommended(None) is False
    assert ollama_update_recommended("") is False
    assert ollama_update_recommended("weird") is False


def _worker(caps: dict | None):
    return SimpleNamespace(
        worker_id="wkr-x",
        trust_tier=2,
        registered_at=None,
        last_heartbeat_at=None,
        retired_at=None,
        quarantined_at=None,
        quarantine_reason=None,
        paused_at=None,
        pause_reason=None,
        pubkey_hex="ab" * 32,
        account_id=None,
        capabilities=caps,
    )


def test_worker_response_surfaces_stale_flag() -> None:
    stale = _worker_to_response(_worker({"ollama_version": "0.17.7"}))
    assert stale.ollama_version == "0.17.7"
    assert stale.ollama_update_recommended is True

    current = _worker_to_response(_worker({"ollama_version": "0.30.11"}))
    assert current.ollama_version == "0.30.11"
    assert current.ollama_update_recommended is False


def test_worker_response_no_version_leaves_flag_none() -> None:
    # A non-serving worker (no ollama_version) is not flagged — nothing to update.
    resp = _worker_to_response(_worker({"os": "linux"}))
    assert resp.ollama_version is None
    assert resp.ollama_update_recommended is None
