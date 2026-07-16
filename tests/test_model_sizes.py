"""ModelSizer sizes the routing requirement by the KV-aware SERVE footprint, not a
flat file x 1.2 — the same estimate the catalog uses, so routing and the catalog
agree on what fits where. The flat multiplier let Phi-3.5-mini (MHA, ~1.6 GB KV)
size at 2.87 GB and route onto a 4.44 GB-usable Jetson, where it OOM'd."""

from __future__ import annotations

import auspexai_platform.model_sizes as ms
from auspexai_platform.model_sizes import ModelSizer


class _FakeArchBrowser:
    """Stands in for HfHttpBrowser; returns a fixed config.json (or None for a miss)."""

    def __init__(self, cfg: dict | None):
        self._cfg = cfg

    def arch(self, repo: str) -> dict | None:
        return self._cfg


def _fake_tree(size_bytes: int, filename: str):
    """Patch for httpx.get over the repo tree — one file with the given size."""

    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> list[dict]:
            return [{"path": filename, "size": size_bytes}]

    def _get(url: str, **kw):
        return _Resp()

    return _get


def test_footprint_uses_kv_aware_estimate_for_mha(monkeypatch):
    # Phi-3.5-mini: MHA (num_key_value_heads == num_attention_heads) → large KV cache.
    # 2.39 GB weights + ~1.6 GB KV + 1.5 overhead ~= 5.5 GB — over a 4.44 GB Jetson.
    monkeypatch.setattr(ms.httpx, "get", _fake_tree(2_390_000_000, "phi.gguf"))
    cfg = {"num_hidden_layers": 32, "num_key_value_heads": 32, "head_dim": 96}
    fp = ModelSizer(browser=_FakeArchBrowser(cfg)).footprint_gb("org/phi", "phi.gguf")
    assert fp is not None
    assert 5.4 < fp < 6.0  # NOT the old 2.87 (which "fit" the Jetson)


def test_footprint_small_for_gqa(monkeypatch):
    # Gemma-3-1B: GQA (1 KV head) → tiny KV → fits a Jetson with headroom.
    monkeypatch.setattr(ms.httpx, "get", _fake_tree(806_000_000, "gemma.gguf"))
    cfg = {"num_hidden_layers": 26, "num_key_value_heads": 1, "head_dim": 256}
    fp = ModelSizer(browser=_FakeArchBrowser(cfg)).footprint_gb("org/gemma", "gemma.gguf")
    assert fp is not None
    assert fp < 3.0


def test_footprint_arch_miss_uses_conservative_proxy_not_flat_multiplier(monkeypatch):
    # No arch (gated base model / network miss) → KV ~= weights * 0.2 PLUS overhead,
    # never the bare file x 1.2 (2.87) that under-sized phi onto a Jetson.
    monkeypatch.setattr(ms.httpx, "get", _fake_tree(2_390_000_000, "x.gguf"))
    fp = ModelSizer(browser=_FakeArchBrowser(None)).footprint_gb("org/x", "x.gguf")
    assert fp is not None
    assert 4.0 < fp < 4.7  # 2.39 + 0.2*2.39 + 1.5 = 4.37


def test_footprint_none_without_coords():
    s = ModelSizer(browser=_FakeArchBrowser(None))
    assert s.footprint_gb(None, "x.gguf") is None
    assert s.footprint_gb("org/x", None) is None


def test_footprint_none_when_file_absent(monkeypatch):
    # File not in the tree → None (unsized), the worker-side guard is the backstop.
    monkeypatch.setattr(ms.httpx, "get", _fake_tree(2_000_000_000, "other.gguf"))
    fp = ModelSizer(browser=_FakeArchBrowser({"num_hidden_layers": 1})).footprint_gb(
        "org/x", "wanted.gguf"
    )
    assert fp is None


def test_footprint_is_cached(monkeypatch):
    calls = {"n": 0}

    class _CountingBrowser(_FakeArchBrowser):
        def arch(self, repo: str) -> dict | None:
            calls["n"] += 1
            return None

    monkeypatch.setattr(ms.httpx, "get", _fake_tree(1_000_000_000, "m.gguf"))
    s = ModelSizer(browser=_CountingBrowser(None))
    a = s.footprint_gb("org/m", "m.gguf")
    b = s.footprint_gb("org/m", "m.gguf")
    assert a == b
    assert calls["n"] == 1  # second call served from cache, no re-fetch
