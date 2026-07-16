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
    def __init__(
        self,
        repos: list[str],
        sizes: dict[str, dict[str, int]],
        archs: dict[str, dict] | None = None,
    ) -> None:
        self._repos = repos
        self._sizes = sizes
        self._archs = archs or {}

    def search(self, *, limit: int) -> list[str]:
        return self._repos[:limit]

    def quant_sizes(self, repo: str) -> dict[str, int]:
        return self._sizes.get(repo, {})

    def arch(self, repo: str) -> dict | None:
        return self._archs.get(repo)


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


def test_serve_estimate_computed_from_arch_and_survives_roundtrip(tmp_path: Path) -> None:
    # #2: with the arch (config.json), the footprint is the KV-aware serve estimate,
    # NOT the flat file x 1.2. Phi-3.5-mini (MHA, big KV) → serve estimate well above
    # its 2.39 GB weights, so the catalog stops under-sizing it.
    repo = "bartowski/Phi-3.5-mini-instruct-GGUF"
    sizes = {repo: {"Q4_K_M": 2_390_000_000}}
    archs = {repo: {"num_hidden_layers": 32, "num_attention_heads": 32, "hidden_size": 3072}}
    (m,) = fetch_catalog(FakeBrowser([repo], sizes, archs), limit=5)
    assert m.serve_ram_gb is not None
    assert m.serve_ram_gb > m.approx_ram_gb  # KV-aware > file x 1.2 (2.87)
    assert m.serve_ram_gb > 5.0  # ~5.5 GB — over a Jetson, as observed

    # Round-trips through the cache JSON.
    path = tmp_path / "catalog.json"
    write_catalog(path, [m], fetched_at="2026-07-16T00:00:00Z")
    (loaded,) = read_catalog(path)
    assert loaded.serve_ram_gb == m.serve_ram_gb


def test_no_arch_uses_conservative_serve_estimate() -> None:
    # A browser with no arch (or a fetch miss) → serve_ram_gb is a CONSERVATIVE estimate
    # (weights + KV proxy + overhead), never None and never the flat file x 1.2. So a
    # gated-base-model 7B still can't hide behind an optimistic footprint.
    repo = "bartowski/Mistral-7B-Instruct-v0.3-GGUF"
    (m,) = fetch_catalog(FakeBrowser([repo], {repo: {"Q4_K_M": 4_370_000_000}}), limit=5)
    assert m.serve_ram_gb is not None
    assert m.serve_ram_gb > m.approx_ram_gb  # conservative > file x 1.2
    assert m.serve_ram_gb > 5.44  # too_big on a Jetson
