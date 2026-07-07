"""hf_catalog — the recurring HF poll: publisher/noise filtering, size sanity,
quant pick, id normalization, and the cache round-trip."""

from __future__ import annotations

from pathlib import Path

from auspexai_platform.hf_catalog import (
    catalog_fetched_at,
    fetch_catalog,
    read_catalog,
    write_catalog,
)

GB = 1_000_000_000


class FakeBrowser:
    def __init__(self, repos: list[str], sizes: dict[str, dict[str, int]]) -> None:
        self._repos = repos
        self._sizes = sizes

    def search(self, *, limit: int) -> list[str]:
        return self._repos[:limit]

    def quant_sizes(self, repo: str) -> dict[str, int]:
        return self._sizes.get(repo, {})


def test_filters_publisher_and_noise() -> None:
    repos = [
        "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",  # keep
        "Qwen/Qwen2.5-7B-Instruct-GGUF",  # keep
        "randomdude/Qwythos-9B-Mythos-GGUF",  # drop: not a reputable publisher
        "bartowski/nomic-embed-text-v1.5-GGUF",  # drop: embedding
        "unsloth/Llama-3.2-1B-Instruct-uncensored-GGUF",  # drop: uncensored long tail
    ]
    sizes = {r: {"Q4_K_M": 5 * GB} for r in repos}
    cat = fetch_catalog(FakeBrowser(repos, sizes), limit=10)
    ids = {c.model_id for c in cat}
    assert ids == {"meta-llama-3.1-8b-instruct-q4", "qwen2.5-7b-instruct-q4"}


def test_size_sanity_drops_partial_file() -> None:
    # A 26B repo whose only GGUF sighting is a 0.3 GB stray shard is not the
    # weights — drop it rather than publish a bogus size (the real-world bug).
    repos = ["unsloth/gemma-4-26B-A4B-it-qat-GGUF"]
    sizes = {repos[0]: {"Q4_0": int(0.3 * GB)}}
    assert fetch_catalog(FakeBrowser(repos, sizes), limit=5) == []


def test_quant_preference_ram_and_id() -> None:
    repos = ["bartowski/Mistral-7B-Instruct-v0.3-GGUF"]
    sizes = {repos[0]: {"Q8_0": 8 * GB, "Q4_K_M": 5 * GB, "Q2_K": 3 * GB}}
    (m,) = fetch_catalog(FakeBrowser(repos, sizes), limit=5)
    assert m.quant == "Q4_K_M"  # preferred over Q8/Q2
    assert m.approx_ram_gb == round(5 * GB / 1e9 * 1.2, 2)  # sized from the real file
    assert m.param_b == 7.0
    assert m.model_id == "mistral-7b-instruct-v0.3-q4"
    assert m.hf_repo == repos[0]  # provenance retained


def test_moe_param_and_baked_quant_suffix() -> None:
    # Repo name already carries the quant (…-Q4_K_M) — must not double-suffix.
    repos = ["bartowski/Mixtral-8x7B-Instruct-v0.1-Q4_K_M-GGUF"]
    sizes = {repos[0]: {"Q4_K_M": 26 * GB}}
    (m,) = fetch_catalog(FakeBrowser(repos, sizes), limit=5)
    assert m.model_id == "mixtral-8x7b-instruct-v0.1-q4"  # single -q4
    assert m.param_b == 56.0  # 8 x 7


def test_cache_roundtrip(tmp_path: Path) -> None:
    repos = ["Qwen/Qwen2.5-7B-Instruct-GGUF"]
    cat = fetch_catalog(FakeBrowser(repos, {repos[0]: {"Q4_K_M": 5 * GB}}), limit=5)
    path = tmp_path / "hf_catalog.json"
    write_catalog(path, cat, fetched_at="2026-07-07T12:00:00+00:00")
    assert catalog_fetched_at(path) == "2026-07-07T12:00:00+00:00"
    back = read_catalog(path)
    assert [m.model_id for m in back] == [m.model_id for m in cat]
    assert back[0].approx_ram_gb == cat[0].approx_ram_gb


def test_read_missing_is_empty(tmp_path: Path) -> None:
    assert read_catalog(tmp_path / "nope.json") == []
    assert catalog_fetched_at(tmp_path / "nope.json") is None
