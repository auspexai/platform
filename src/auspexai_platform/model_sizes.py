"""Coordinator-side model-size authority (top-down fleet-fit).

The coordinator polls HF and knows every worker's RAM, so IT decides — top-down —
whether a model can run where, and pushes that into routing. This is the size half:
given a model's HF coords (`hf_repo`/`hf_filename` from the manifest), return the
serve FOOTPRINT in GB from HF's published GGUF file size x a runtime overhead — no
download required (that would be circular for discovery). Results are cached in
memory (an experiment's models are sized once, at submit, then routing reads the
stored footprint).

HF publishes the file SIZE, not a separate "needs X GB" field; for GGUF that file
size (x overhead for KV-cache/context) IS the memory footprint. The overhead
matches `hf_catalog._LOAD_OVERHEAD` and the worker's `hf_browse`, so the fit math
agrees everywhere.
"""

from __future__ import annotations

import logging

import httpx

from auspexai_platform.hf_catalog import _HF_API, _LOAD_OVERHEAD

logger = logging.getLogger(__name__)


class ModelSizer:
    """Cache-backed `(hf_repo, hf_filename) -> footprint_gb | None`. A failed/absent
    lookup returns None (caller treats it as 'unsized' — never a false fit or
    false too_big; the worker-side guard is the backstop)."""

    def __init__(self, *, timeout: float = 20.0) -> None:
        self._timeout = timeout
        self._cache: dict[tuple[str, str], float | None] = {}

    def footprint_gb(self, hf_repo: str | None, hf_filename: str | None) -> float | None:
        if not hf_repo or not hf_filename:
            return None
        key = (hf_repo, hf_filename)
        if key in self._cache:
            return self._cache[key]
        fp = self._query(hf_repo, hf_filename)
        self._cache[key] = fp
        return fp

    def _query(self, hf_repo: str, hf_filename: str) -> float | None:
        try:
            r = httpx.get(
                f"{_HF_API}/api/models/{hf_repo}/tree/main",
                params={"recursive": "true"},
                timeout=self._timeout,
                headers={"User-Agent": "auspexai-coordinator"},
            )
            r.raise_for_status()
            for item in r.json():
                path = item.get("path", "")
                if path.split("/")[-1] == hf_filename:
                    size = item.get("size")
                    if isinstance(size, int) and size > 0:
                        return round(size / 1e9 * _LOAD_OVERHEAD, 2)
        except Exception:
            logger.debug("model_sizes: HF size lookup failed for %s/%s", hf_repo, hf_filename)
        return None
