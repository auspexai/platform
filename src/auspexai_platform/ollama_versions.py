"""Recommended-minimum Ollama version — the coordinator's PROACTIVE stale-worker
signal.

Newer models (phi-3.5, qwen3-2507, gpt-oss) need a recent Ollama runtime; an
install-once-never-updated worker silently 500s on them (the worker's serve guard
now diagnoses that at runtime — auspexai_worker/inference/server.py). Every worker
reports its `ollama_version` in the heartbeat capabilities, so the coordinator can
flag a below-floor worker on the operator surface BEFORE a run is routed to it and
fails — the signal we lacked when the Jetsons (Ollama 0.17/0.18) stranded phi/qwen3.

This is a SOFT NUDGE floor, not a routing gate: a stale worker still serves the
models it can; it's flagged so the operator/volunteer can update. Keep
RECOMMENDED_MIN_OLLAMA in sync with the worker (auspexai_worker/updates.py) and the
installer (packaging/install.sh); bump when onboarding a model that needs a newer
runtime.
"""

from __future__ import annotations

import re

RECOMMENDED_MIN_OLLAMA = "0.30.0"

_NUMERIC_PREFIX = re.compile(r"^(\d+(?:\.\d+)*)")


def _parts(version: str) -> tuple[int, ...] | None:
    m = _NUMERIC_PREFIX.match(version.strip().lstrip("v"))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def ollama_update_recommended(version: str | None, floor: str = RECOMMENDED_MIN_OLLAMA) -> bool:
    """True when `version` is a parseable Ollama version strictly older than `floor`.
    None / unparseable ⇒ False (never flag when we can't tell — the worker may not be
    serving, or reports an odd version)."""
    if not version:
        return False
    cur = _parts(version)
    flo = _parts(floor)
    if cur is None or flo is None:
        return False
    width = max(len(cur), len(flo))
    cur += (0,) * (width - len(cur))
    flo += (0,) * (width - len(flo))
    return cur < flo
