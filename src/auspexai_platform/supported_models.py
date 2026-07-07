"""The curated top-down catalog of models the AuspexAI network SUPPORTS.

The `/models/catalog` route is BOTTOM-UP — a live aggregate of what active
workers are actually serving right now (`capabilities["models"]`). It answers
"what can I run this instant" but not "what could I conceivably run here." This
module is the TOP-DOWN half: a curated set of notable instruct GGUF models
across the full size range (0.36B-671B, HF-grounded), so a researcher sees the
provisionable menu. `GET /api/v0/models/supported` returns the UNION of this
list and the fleet's real inventory, labelling each available / runnable /
too_big / unknown.

Curated + STATIC (for now): "all of Hugging Face" is ~500k repos, most
unservable or junk, so this is a vetted spread, not a firehose. It does NOT poll
HF — new HF uploads are caught only by editing this list (or, future, by wiring
the worker's `models/hf_browse.runnable_models` on a periodic refresh). The
fleet-inventory half IS live (every heartbeat). A model a researcher wants that
isn't here routes to the existing request flow (GitHub Discussions).

`model_id` MUST equal the worker store id (`<family>-<size>-<variant>-<quant>`)
— the exact-match space the M1 scheduler routes on AND the string workers report
in `capabilities["models"]`. Get it wrong and the served-overlay silently won't
light up for that model. The three the fleet runs today are copied verbatim from
live worker heartbeats; the expansion follows the same convention and becomes the
canonical id when someone first runs it.

`approx_ram_gb` is a rough serve-footprint for the quant (weights + KV/runtime
overhead) — enough for the fleet-capacity hint, not a hard admission gate.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SupportedModel:
    model_id: str  # worker store id + M1 routing key + capabilities["models"] string
    display_name: str  # human label, e.g. "Qwen2.5 · 0.5B"
    family: str
    param_b: float  # billions of parameters
    quant: str  # e.g. "Q4_K_M"
    approx_ram_gb: float  # rough serve footprint for this quant


# Ordered smallest→largest within family groupings. The first three are LIVE on
# the fleet (ids verbatim from heartbeats 2026-07-07); the rest are the vetted
# expansion across size tiers. Everything here is an instruct model, GGUF-quantised,
# and CPU-servable on modest volunteer hardware.
SUPPORTED_MODELS: tuple[SupportedModel, ...] = (
    # ── currently served on the fleet ──
    SupportedModel("qwen2.5-0.5b-instruct-q4", "Qwen2.5 · 0.5B", "Qwen", 0.5, "Q4_K_M", 1.0),
    SupportedModel("gemma-3-1b-it-q4", "Gemma 3 · 1B", "Gemma", 1.0, "Q4_K_M", 2.0),
    SupportedModel("smollm2-1.7b-instruct-q4", "SmolLM2 · 1.7B", "SmolLM", 1.7, "Q4_K_M", 2.0),
    # ── vetted expansion (runnable, not-yet-served) ──
    SupportedModel("smollm2-360m-instruct-q4", "SmolLM2 · 360M", "SmolLM", 0.36, "Q4_K_M", 0.7),
    SupportedModel("tinyllama-1.1b-chat-q4", "TinyLlama · 1.1B", "TinyLlama", 1.1, "Q4_K_M", 1.4),
    SupportedModel("llama-3.2-1b-instruct-q4", "Llama 3.2 · 1B", "Llama", 1.0, "Q4_K_M", 1.6),
    SupportedModel("qwen2.5-1.5b-instruct-q4", "Qwen2.5 · 1.5B", "Qwen", 1.5, "Q4_K_M", 1.8),
    SupportedModel("gemma-2-2b-it-q4", "Gemma 2 · 2B", "Gemma", 2.0, "Q4_K_M", 2.4),
    SupportedModel("llama-3.2-3b-instruct-q4", "Llama 3.2 · 3B", "Llama", 3.0, "Q4_K_M", 3.6),
    SupportedModel("qwen2.5-3b-instruct-q4", "Qwen2.5 · 3B", "Qwen", 3.0, "Q4_K_M", 3.6),
    SupportedModel("phi-3.5-mini-instruct-q4", "Phi-3.5 mini · 3.8B", "Phi", 3.8, "Q4_K_M", 4.2),
    # ── mid tier (~5-9 GB) ──
    SupportedModel("mistral-7b-instruct-q4", "Mistral · 7B", "Mistral", 7.0, "Q4_K_M", 5.0),
    SupportedModel("qwen2.5-7b-instruct-q4", "Qwen2.5 · 7B", "Qwen", 7.0, "Q4_K_M", 5.0),
    SupportedModel(
        "qwen2.5-coder-7b-instruct-q4", "Qwen2.5 Coder · 7B", "Qwen", 7.0, "Q4_K_M", 5.0
    ),
    SupportedModel("llama-3.1-8b-instruct-q4", "Llama 3.1 · 8B", "Llama", 8.0, "Q4_K_M", 5.6),
    SupportedModel(
        "mistral-nemo-12b-instruct-q4", "Mistral Nemo · 12B", "Mistral", 12.0, "Q4_K_M", 7.5
    ),
    SupportedModel("qwen2.5-14b-instruct-q4", "Qwen2.5 · 14B", "Qwen", 14.0, "Q4_K_M", 9.0),
    # ── big tier (fits a ~24 GB worker) ──
    SupportedModel("gemma-2-27b-it-q4", "Gemma 2 · 27B", "Gemma", 27.0, "Q4_K_M", 16.0),
    SupportedModel(
        "mistral-small-24b-instruct-q4", "Mistral Small · 24B", "Mistral", 24.0, "Q4_K_M", 14.5
    ),
    SupportedModel(
        "qwen3-30b-a3b-instruct-q4", "Qwen3 · 30B-A3B (MoE)", "Qwen", 30.0, "Q4_K_M", 18.0
    ),
    SupportedModel("qwen2.5-32b-instruct-q4", "Qwen2.5 · 32B", "Qwen", 32.0, "Q4_K_M", 20.0),
    SupportedModel(
        "qwen2.5-coder-32b-instruct-q4", "Qwen2.5 Coder · 32B", "Qwen", 32.0, "Q4_K_M", 20.0
    ),
    # ── large tier (needs a worker bigger than a 24 GB fleet) ──
    SupportedModel(
        "mixtral-8x7b-instruct-q4", "Mixtral · 8x7B (MoE)", "Mistral", 47.0, "Q4_K_M", 26.0
    ),
    SupportedModel("llama-3.3-70b-instruct-q4", "Llama 3.3 · 70B", "Llama", 70.0, "Q4_K_M", 42.0),
    SupportedModel("qwen2.5-72b-instruct-q4", "Qwen2.5 · 72B", "Qwen", 72.0, "Q4_K_M", 44.0),
    SupportedModel(
        "mistral-large-123b-instruct-q4", "Mistral Large · 123B", "Mistral", 123.0, "Q4_K_M", 73.0
    ),
    SupportedModel(
        "llama-3.1-405b-instruct-q4", "Llama 3.1 · 405B", "Llama", 405.0, "Q4_K_M", 230.0
    ),
    SupportedModel(
        "deepseek-v3-instruct-q4", "DeepSeek V3 · 671B (MoE)", "DeepSeek", 671.0, "Q4_K_M", 380.0
    ),
)


def supported_by_id() -> dict[str, SupportedModel]:
    """`{model_id: SupportedModel}` for O(1) overlay joins against the live fleet."""
    return {m.model_id: m for m in SUPPORTED_MODELS}
