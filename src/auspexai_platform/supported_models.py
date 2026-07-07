"""The curated top-down catalog of models the AuspexAI network SUPPORTS.

The `/models/catalog` route is BOTTOM-UP — a live aggregate of what active
workers are actually serving right now (`capabilities["models"]`). It answers
"what can I run this instant" but not "what could I conceivably run here." This
module is the TOP-DOWN half: a small, deliberately-curated set of instruct GGUF
models that fit volunteer hardware, so a researcher always sees their full menu
of possibilities — with the live fleet then overlaid (served / runnable / too
big) by `GET /api/v0/models/supported`.

Curated, NOT dynamic: "all of Hugging Face" is ~500k repos, most unservable or
junk. This is the vetted set the network is designed to run; growth is a
deliberate edit here (a research-standing-appropriate addition), not a firehose.
A model a researcher wants that ISN'T here routes to the existing request flow
(GitHub Discussions), same as before.

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
    # ── mid tier (fits a ~8 GB worker; may be too_big for smaller ones) ──
    SupportedModel("mistral-7b-instruct-q4", "Mistral · 7B", "Mistral", 7.0, "Q4_K_M", 5.0),
    SupportedModel("qwen2.5-7b-instruct-q4", "Qwen2.5 · 7B", "Qwen", 7.0, "Q4_K_M", 5.0),
    SupportedModel("llama-3.1-8b-instruct-q4", "Llama 3.1 · 8B", "Llama", 8.0, "Q4_K_M", 5.6),
    # ── large tier (needs a bigger worker than the current fleet) ──
    SupportedModel("qwen2.5-14b-instruct-q4", "Qwen2.5 · 14B", "Qwen", 14.0, "Q4_K_M", 9.0),
    SupportedModel("qwen2.5-32b-instruct-q4", "Qwen2.5 · 32B", "Qwen", 32.0, "Q4_K_M", 20.0),
    SupportedModel("llama-3.3-70b-instruct-q4", "Llama 3.3 · 70B", "Llama", 70.0, "Q4_K_M", 42.0),
)


def supported_by_id() -> dict[str, SupportedModel]:
    """`{model_id: SupportedModel}` for O(1) overlay joins against the live fleet."""
    return {m.model_id: m for m in SUPPORTED_MODELS}
