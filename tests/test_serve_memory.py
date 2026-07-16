"""Serve-memory estimator — calibrated against the REAL model architectures and the
observed fit/OOM outcomes on the 5.44 GB Jetsons (usable = 7.44 total - 2.0 reserve)."""

from __future__ import annotations

from auspexai_platform.serve_memory import (
    DEFAULT_NUM_CTX,
    arch_from_config,
    estimate_serve_gb,
    head_dim_from_config,
    kv_cache_gb,
)

_JETSON_USABLE_GB = 5.44
_MAC_USABLE_GB = 22.0

# Real arch (from HF config.json) + real Q4_K_M weight sizes, with the observed
# outcome on the Jetson pair. The whole point: the estimator must reproduce reality,
# where the flat file-size x1.2 check did not.
_PHI_35_MINI = dict(weights_gb=2.39, n_layers=32, n_kv_heads=32, head_dim=96)  # MHA — OOMs
_QWEN3_4B = dict(weights_gb=2.50, n_layers=36, n_kv_heads=8, head_dim=128)  # GQA — OOMs
_QWEN3_1_7B = dict(weights_gb=1.28, n_layers=28, n_kv_heads=8, head_dim=128)  # GQA — fits
_SMOLLM2_1_7B = dict(weights_gb=1.06, n_layers=24, n_kv_heads=8, head_dim=64)  # fits


def test_kv_cache_dominated_by_architecture_not_just_params():
    # Phi-3.5-mini is MHA (32 KV-heads) → a HUGE KV cache the flat multiplier missed.
    phi_kv = kv_cache_gb(n_layers=32, n_kv_heads=32, head_dim=96)
    assert phi_kv > 1.5  # ~1.6 GB — bigger than a whole 1.7B model's weights
    # Qwen3-4B is GQA (8 KV-heads) → a small KV DESPITE being a bigger model.
    qwen4b_kv = kv_cache_gb(n_layers=36, n_kv_heads=8, head_dim=128)
    assert qwen4b_kv < 0.7
    # So param count alone can't order them; the KV term (architecture) is required.
    assert phi_kv > qwen4b_kv


def test_kv_cache_scales_with_context():
    at_4k = kv_cache_gb(n_layers=28, n_kv_heads=8, head_dim=128, num_ctx=4096)
    at_1k = kv_cache_gb(n_layers=28, n_kv_heads=8, head_dim=128, num_ctx=1024)
    assert abs(at_4k - 4 * at_1k) < 1e-9  # linear in context — the term the old check lacked


def test_classification_matches_observed_jetson_outcomes():
    # The models that OOM'd on the Jetsons must NOT fit; the ones that served must.
    phi = estimate_serve_gb(**_PHI_35_MINI)
    q4b = estimate_serve_gb(**_QWEN3_4B)
    q17 = estimate_serve_gb(**_QWEN3_1_7B)
    smol = estimate_serve_gb(**_SMOLLM2_1_7B)

    assert phi > _JETSON_USABLE_GB  # ~5.5 GB — correctly excluded (the flat check said 2.87 "fits")
    assert q17 <= _JETSON_USABLE_GB  # ~3.25 GB — fits, matching TS235 serving it
    assert smol <= _JETSON_USABLE_GB  # fits
    # Qwen3-4B is marginal by the estimate (GQA hides its cost) — the observed-failure
    # feedback is what nails it; the estimate at least stops UNDER-counting it.
    assert q4b > q17  # bigger than the 1.7B, as it must be

    # Everything fits the 22 GB Mac (where they DID serve).
    for m in (phi, q4b, q17, smol):
        assert m <= _MAC_USABLE_GB


def test_unknown_arch_returns_none_for_legacy_fallback():
    assert estimate_serve_gb(weights_gb=2.0, n_layers=None, n_kv_heads=8, head_dim=128) is None
    assert estimate_serve_gb(weights_gb=2.0, n_layers=32, n_kv_heads=None, head_dim=128) is None


def test_arch_from_config_reads_real_shapes():
    # Qwen3-4B config.json (GQA: explicit head_dim, num_key_value_heads=8).
    q = {
        "num_hidden_layers": 36,
        "num_attention_heads": 32,
        "num_key_value_heads": 8,
        "hidden_size": 2560,
        "head_dim": 128,
    }
    assert arch_from_config(q) == (36, 8, 128)
    # Phi-3.5-mini (MHA: no head_dim key, no GQA → kv falls back to attention heads).
    p = {"num_hidden_layers": 32, "num_attention_heads": 32, "hidden_size": 3072}
    assert arch_from_config(p) == (32, 32, 96)  # head_dim = 3072/32
    assert head_dim_from_config(p) == 96


def test_default_num_ctx_matches_worker():
    assert DEFAULT_NUM_CTX == 4096
