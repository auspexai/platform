"""Coordinator-side model-size authority (top-down fleet-fit).

The coordinator polls HF and knows every worker's RAM, so IT decides — top-down —
whether a model can run where, and pushes that into routing. This is the size half:
given a model's HF coords (`hf_repo`/`hf_filename` from the manifest), return the
serve FOOTPRINT in GB — no download required (that would be circular for discovery).
Results are cached in memory (an experiment's models are sized once, at submit, then
routing reads the stored footprint).

The footprint is the SAME KV-aware estimate the catalog uses (`estimate_serve_gb`):
weights (HF's published GGUF file size) + KV cache (from the model's architecture)
+ runtime overhead. A flat `file x 1.2` ignored the KV term and let Phi-3.5-mini
(MHA, ~1.6 GB KV → ~5.5 GB to serve) size at 2.87 GB and route onto a 5.44 GB Jetson,
where it OOM'd. Sizing here through the same estimator closes that gap so routing and
the catalog agree on what fits where. The arch (config.json) is best-effort: a miss
falls back to `estimate_serve_gb`'s conservative KV proxy, never the old flat 1.2x.
"""

from __future__ import annotations

import logging

import httpx

from auspexai_platform.hf_catalog import _HF_API, HfHttpBrowser
from auspexai_platform.serve_memory import arch_from_config, estimate_serve_gb

logger = logging.getLogger(__name__)


class ModelSizer:
    """Cache-backed `(hf_repo, hf_filename) -> footprint_gb | None`. A failed/absent
    lookup returns None (caller treats it as 'unsized' — never a false fit or
    false too_big; the worker-side guard is the backstop)."""

    def __init__(self, *, timeout: float = 20.0, browser: HfHttpBrowser | None = None) -> None:
        self._timeout = timeout
        self._cache: dict[tuple[str, str], float | None] = {}
        # Reused for the KV-aware arch fetch (config.json), same path as the catalog.
        self._browser = browser or HfHttpBrowser(timeout=timeout)

    def footprint_gb(self, hf_repo: str | None, hf_filename: str | None) -> float | None:
        if not hf_repo or not hf_filename:
            return None
        key = (hf_repo, hf_filename)
        if key in self._cache:
            return self._cache[key]
        fp = self._query(hf_repo, hf_filename)
        self._cache[key] = fp
        return fp

    def _file_size_bytes(self, hf_repo: str, hf_filename: str) -> int | None:
        """The GGUF file's published size on HF (the weights term), or None."""
        try:
            r = httpx.get(
                f"{_HF_API}/api/models/{hf_repo}/tree/main",
                params={"recursive": "true"},
                timeout=self._timeout,
                headers={"User-Agent": "auspexai-coordinator"},
            )
            r.raise_for_status()
            for item in r.json():
                if item.get("path", "").split("/")[-1] == hf_filename:
                    size = item.get("size")
                    if isinstance(size, int) and size > 0:
                        return size
        except Exception:
            logger.debug("model_sizes: HF size lookup failed for %s/%s", hf_repo, hf_filename)
        return None

    def _query(self, hf_repo: str, hf_filename: str) -> float | None:
        size_bytes = self._file_size_bytes(hf_repo, hf_filename)
        if size_bytes is None:
            return None
        # KV-aware serve estimate: fetch the arch (config.json) for the precise KV
        # term; a miss yields None arch and estimate_serve_gb's conservative proxy —
        # never the flat file x 1.2 that let an MHA model under-size onto a Jetson.
        n_layers = n_kv = head_dim = None
        try:
            cfg = self._browser.arch(hf_repo)
        except Exception:
            cfg = None
        if isinstance(cfg, dict):
            n_layers, n_kv, head_dim = arch_from_config(cfg)
        return estimate_serve_gb(
            weights_gb=size_bytes / 1e9,
            n_layers=n_layers,
            n_kv_heads=n_kv,
            head_dim=head_dim,
        )
