"""Serve-memory model — what a model ACTUALLY needs to serve, not just its weights.

The old fit check was `file_size_gb * 1.2 <= usable` (a flat 20% fudge). It ignored
the dependencies that actually decide whether a model loads:

  1. **KV cache** — scales with context length AND architecture. It's the term that
     bit us: Phi-3.5-mini (32 layers, 32 KV-heads, no GQA) needs ~1.6 GB of KV at
     4096 ctx ON TOP of its 2.4 GB weights, so the flat 1.2x (→ 2.87 GB "fits" on a
     5.44 GB Jetson) was off by more than a gigabyte and it OOM'd. Qwen3-4B (GQA,
     8 KV-heads) has a small KV but 2.5 GB weights — also over the line. Qwen3-1.7B
     (GQA, 1.28 GB weights, ~0.47 GB KV) fits. The KV term separates them; a
     file-size multiplier cannot.
  2. **Runtime overhead** — CUDA context + the model-server process + the compute
     graph. Roughly fixed per serve, folded into SERVE_OVERHEAD_GB.

This is an a-priori ESTIMATE. It's paired with an observed-failure ground truth
(a model that demonstrably OOMs on a worker is marked unservable there regardless
of the estimate — see the catalog's serve-outcome feedback), so the estimate only
has to be good enough to catch the obvious cases; reality corrects the rest.

Kept deliberately in sync with the worker (auspexai_worker serve guard): the two
must agree on the fit math the way _LOAD_OVERHEAD did before.
"""

from __future__ import annotations

# Ollama defaults to an fp16 KV cache (2 bytes per element, for K and V each).
_KV_BYTES = 2
# CUDA context + model-server runtime + compute graph — the fixed, non-weight,
# non-KV cost of having a model loaded and generating. Calibrated so Phi-3.5-mini
# (2.39 GB weights + 1.6 GB KV @4096) lands just over a 5.44 GB Jetson while the
# ~1.7B-class models (Qwen3-1.7B, SmolLM2) land comfortably under. The
# observed-failure feedback is the backstop for anything marginal (e.g. Qwen3-4B).
SERVE_OVERHEAD_GB = 1.5
# When the architecture is UNKNOWN (a gated base model whose config.json we can't
# fetch, or a present-but-unmenued model sized only from its file), estimate the KV
# cache as this fraction of the weights — a deliberately CONSERVATIVE GQA-ish proxy at
# 4096 ctx, so an arch-unknown model errs toward too_big rather than the old flat
# file x 1.2 that let mistral-7b (never served on a Jetson) read "fits" there.
_KV_PROXY_FRACTION = 0.2
# The context length the worker serves at (matches the worker's DEFAULT_NUM_CTX).
# The KV cache is linear in this, so it's a first-class input to the fit decision —
# the whole point is that a bigger context needs more memory, which the old check
# never saw.
DEFAULT_NUM_CTX = 4096


def kv_cache_gb(
    *, n_layers: int, n_kv_heads: int, head_dim: int, num_ctx: int = DEFAULT_NUM_CTX
) -> float:
    """The KV-cache footprint (GB) at `num_ctx` tokens: 2 (K+V) x tokens x layers x
    KV-heads x head-dim x fp16-bytes. GQA (few KV-heads) shrinks this dramatically vs
    MHA (KV-heads == attention-heads) — the exact difference the flat multiplier
    missed between Qwen3 (GQA) and Phi-3.5 (MHA)."""
    return 2 * num_ctx * n_layers * n_kv_heads * head_dim * _KV_BYTES / 1e9


def estimate_serve_gb(
    *,
    weights_gb: float,
    n_layers: int | None,
    n_kv_heads: int | None,
    head_dim: int | None,
    num_ctx: int = DEFAULT_NUM_CTX,
) -> float:
    """Estimated memory (GB) to SERVE a model: weights + KV cache + runtime overhead.
    When the architecture is known → the precise KV term. When it's UNKNOWN (a gated
    base model, or a present-but-unmenued model sized only from its file) → a
    CONSERVATIVE proxy (KV ~= weights x _KV_PROXY_FRACTION) so it errs toward too_big,
    never the old flat file x 1.2 that let a 7B model read 'fits' on a 5.44 GB Jetson.
    Always returns an estimate (weights are always known)."""
    if n_layers and n_kv_heads and head_dim:
        kv = kv_cache_gb(
            n_layers=n_layers, n_kv_heads=n_kv_heads, head_dim=head_dim, num_ctx=num_ctx
        )
    else:
        kv = weights_gb * _KV_PROXY_FRACTION
    return round(weights_gb + kv + SERVE_OVERHEAD_GB, 2)


def head_dim_from_config(cfg: dict) -> int | None:
    """A model's attention head dimension from its HF config.json: the explicit
    `head_dim`, else `hidden_size / num_attention_heads`."""
    hd = cfg.get("head_dim")
    if isinstance(hd, int) and hd > 0:
        return hd
    hidden = cfg.get("hidden_size")
    heads = cfg.get("num_attention_heads")
    if isinstance(hidden, int) and isinstance(heads, int) and heads > 0:
        return hidden // heads
    return None


def arch_from_config(cfg: dict) -> tuple[int | None, int | None, int | None]:
    """(n_layers, n_kv_heads, head_dim) from an HF config.json. `num_key_value_heads`
    falls back to `num_attention_heads` (a model with no GQA reports only the latter,
    which is the MHA case — the worst case for KV size, correctly)."""
    n_layers = cfg.get("num_hidden_layers")
    n_kv = cfg.get("num_key_value_heads") or cfg.get("num_attention_heads")
    head_dim = head_dim_from_config(cfg)
    return (
        n_layers if isinstance(n_layers, int) else None,
        n_kv if isinstance(n_kv, int) else None,
        head_dim,
    )
