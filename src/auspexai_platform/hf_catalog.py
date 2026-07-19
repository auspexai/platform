"""Recurring HuggingFace catalog poll — the network's fresh top-down menu.

`supported_models.py` is a hand-curated STATIC seed. This module is the DYNAMIC
half: a coordinator-side poll that queries HuggingFace for popular GGUF instruct
models across the full size range, sizes each by its REAL quant file size (RAM ≈
file size + overhead — measured, not guessed, the same lever the worker's
`models/hf_browse.py` uses), and caches the result. A systemd timer refreshes it
(`auspexai-coordinator refresh-hf-catalog`) so new HF uploads are picked up
without a code edit.

`GET /api/v0/models/supported` serves the cached catalog (falling back to the
static curated seed when the cache is absent) as the provisionable set, then
classifies each model against the live fleet (available / runnable / too_big).
Because the poll is size-DIVERSE (not RAM-filtered), models bigger than any
worker correctly surface as `too_big` — the thing a per-worker `hf_browse` poll
can never show.

HF access is behind the `HfBrowser` protocol so the fetch logic is unit-tested
with a fake; `HfHttpBrowser` is the real one, over plain httpx (no
`huggingface_hub` dependency on the coordinator).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

import httpx

from auspexai_platform.serve_memory import arch_from_config, estimate_serve_gb

logger = logging.getLogger(__name__)

# RAM to serve a GGUF is approx the file size x this (KV cache + runtime).
# Matches the worker's hf_browse _LOAD_OVERHEAD so the fit math agrees with it.
_LOAD_OVERHEAD = 1.2
_QUANT_RE = re.compile(r"(MXFP\d+|I?Q\d+(?:_[A-Za-z0-9]+)*|F16|BF16|F32)", re.IGNORECASE)
# Which representative quant to catalog per repo (best quality that's still a
# sensible default), most-preferred first.
_QUANT_PREFERENCE = ("Q4_K_M", "Q4_K_S", "Q4_0", "Q5_K_M", "Q3_K_M", "Q8_0")
_HF_API = "https://huggingface.co"
# Non-instruct / non-text-gen / non-research noise the download-sorted GGUF feed
# drags in (multimodal, embeddings, and the roleplay/uncensored/base long tail).
_EXCLUDE_RE = re.compile(
    r"embed|rerank|vlm|-vl\b|-vl-|vision|whisper|clip|bge-|sd[-.]|flux|diffusion|tts|stt"
    r"|image|-edit|ltx|-video|uncensored|abliterated|heretic|roleplay|-rp\b|erp\b|nsfw|-base\b",
    re.IGNORECASE,
)
# The download-sorted GGUF firehose is dominated by hobbyist merges. Restrict to
# reputable quantizers + first-party model authors — the strongest quality lever
# (a fresh model from any of these is legit; the curated seed backfills the rest).
_REPUTABLE_AUTHORS = frozenset(
    {
        "bartowski",
        "unsloth",
        "lmstudio-community",
        "ggml-org",
        "maziyarpanahi",
        "mradermacher",
        "thebloke",
        "hugging-quants",
        "quantfactory",
        "second-state",
        "qwen",
        "google",
        "meta-llama",
        "mistralai",
        "microsoft",
        "huggingfacetb",
        "ibm-granite",
        "deepseek-ai",
        "allenai",
        "cohereforai",
        "nvidia",
        "openai",
        "tiiuae",
    }
)


@dataclass(frozen=True)
class CatalogModel:
    """One cached provisionable model (a representative GGUF quant on HF)."""

    model_id: str  # normalized store-style id (<repo-slug>-q4) for the fleet overlay
    display_name: str
    family: str
    param_b: float | None
    quant: str
    approx_ram_gb: float  # LEGACY footprint: file size x flat 1.2 overhead
    hf_repo: str  # provenance: the source HF repo
    # KV-aware serve estimate (weights + KV cache + runtime overhead), from the
    # model's real architecture (config.json). The footprint the fit verdict PREFERS;
    # None when the arch couldn't be fetched → falls back to approx_ram_gb.
    serve_ram_gb: float | None = None


def _parse_quant(filename: str) -> str:
    m = _QUANT_RE.search(filename)
    return m.group(0).upper() if m else filename.rsplit(".", 1)[0]


def _repo_slug(repo: str) -> str:
    """`bartowski/Meta-Llama-3.1-8B-Instruct-GGUF` -> `meta-llama-3.1-8b-instruct`
    (lowercased; trailing -gguf and any trailing quant token stripped) so the id
    lines up with the worker store convention as closely as a repo name allows."""
    slug = repo.split("/")[-1].lower()
    slug = re.sub(r"[-_.]?gguf$", "", slug)
    # Drop a trailing quant the publisher baked into the repo name (…-Q4_K_M),
    # so we don't emit a double suffix when we append the normalized -q4.
    slug = re.sub(r"[-_.](i?q\d+(?:_[a-z0-9]+)*|f16|bf16|f32)$", "", slug)
    return slug


def _param_b(repo: str) -> float | None:
    """Parse a parameter count from the repo name for display/sort — MoE `AxB`
    reads as A*B, plain `NB` as N, `NNNM` as N/1000. Sizing uses the file, so
    this is best-effort (and drives the size sanity-check in fetch_catalog)."""
    name = repo.split("/")[-1]
    moe = re.search(r"(\d+(?:\.\d+)?)x(\d+(?:\.\d+)?)b", name, re.IGNORECASE)
    if moe:
        return round(float(moe.group(1)) * float(moe.group(2)), 1)
    m = re.search(r"(\d+(?:\.\d+)?)b\b", name, re.IGNORECASE)
    if m:
        return float(m.group(1))
    mm = re.search(r"(\d{2,4})m\b", name, re.IGNORECASE)  # e.g. 360M, 500M
    return round(float(mm.group(1)) / 1000, 3) if mm else None


def _display_name(repo: str) -> str:
    """A readable label from the repo name: drop the -GGUF suffix and the org."""
    name = repo.split("/")[-1]
    name = re.sub(r"[-_.]?GGUF$", "", name, flags=re.IGNORECASE)
    return name.replace("_", " ").replace("-", " ").strip()


class HfBrowser(Protocol):
    def search(self, *, limit: int) -> list[str]:
        """Candidate HF repo ids (GGUF, most-downloaded first)."""
        ...

    def quant_sizes(self, repo: str) -> dict[str, int]:
        """`{quant: size_bytes}` for the repo's GGUF files (one per quant)."""
        ...

    def arch(self, repo: str) -> dict | None:
        """The model's config.json (architecture) for the KV-aware serve estimate,
        or None. Optional — callers guard with getattr for fake browsers."""
        ...


class HfHttpBrowser:
    """Real browser over the public HuggingFace API (plain httpx, unauthenticated)."""

    def __init__(self, *, timeout: float = 20.0) -> None:
        self._timeout = timeout

    def search(self, *, limit: int) -> list[str]:
        r = httpx.get(
            f"{_HF_API}/api/models",
            params={"filter": "gguf", "sort": "downloads", "direction": "-1", "limit": limit},
            timeout=self._timeout,
            headers={"User-Agent": "auspexai-coordinator"},
        )
        r.raise_for_status()
        return [m["id"] for m in r.json() if isinstance(m, dict) and m.get("id")]

    def quant_sizes(self, repo: str) -> dict[str, int]:
        r = httpx.get(
            f"{_HF_API}/api/models/{repo}/tree/main",
            params={"recursive": "true"},
            timeout=self._timeout,
            headers={"User-Agent": "auspexai-coordinator"},
        )
        r.raise_for_status()
        out: dict[str, int] = {}
        for item in r.json():
            path = item.get("path", "")
            size = item.get("size")
            if not path.lower().endswith(".gguf") or not isinstance(size, int) or size <= 0:
                continue
            quant = _parse_quant(path.split("/")[-1])
            # A quant split across shards would repeat; keep the largest sighting.
            out[quant] = max(out.get(quant, 0), size)
        return out

    def arch(self, repo: str) -> dict | None:
        """The model's config.json (num_hidden_layers / num_key_value_heads /
        head_dim) for the KV-aware serve estimate. GGUF repos rarely ship config.json
        themselves, so resolve via the repo's `base_model`; fall back to the repo
        itself. Best-effort — any failure returns None and the catalog falls back to
        the file-size estimate rather than guess."""
        try:
            r = httpx.get(
                f"{_HF_API}/api/models/{repo}",
                timeout=self._timeout,
                headers={"User-Agent": "auspexai-coordinator"},
            )
            r.raise_for_status()
            base = (r.json().get("cardData") or {}).get("base_model")
            if isinstance(base, list):
                base = base[0] if base else None
            for src in (base, repo):
                if not isinstance(src, str) or not src:
                    continue
                cr = httpx.get(
                    f"{_HF_API}/{src}/resolve/main/config.json",
                    timeout=self._timeout,
                    headers={"User-Agent": "auspexai-coordinator"},
                    follow_redirects=True,
                )
                if cr.status_code == 200:
                    cfg = cr.json()
                    if isinstance(cfg, dict):
                        return cfg
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return None


def _pick_quant(sizes: dict[str, int]) -> tuple[str, int] | None:
    """The representative (quant, size) for a repo — preferred order, then the
    smallest available as a floor."""
    if not sizes:
        return None
    for q in _QUANT_PREFERENCE:
        if q in sizes:
            return q, sizes[q]
    q = min(sizes, key=lambda k: sizes[k])
    return q, sizes[q]


def fetch_catalog(browser: HfBrowser, *, limit: int = 60) -> list[CatalogModel]:
    """Query HF and build the provisionable catalog — one representative quant
    per repo, sized by its real file. Repos with no usable GGUF are skipped;
    a per-repo failure is logged and skipped, never fatal."""
    out: list[CatalogModel] = []
    seen: set[str] = set()
    for repo in browser.search(limit=limit):
        if repo.split("/")[0].lower() not in _REPUTABLE_AUTHORS:
            continue  # keep the feed to trusted quantizers / first-party authors
        if _EXCLUDE_RE.search(repo):
            continue  # embedding / vision / rerank / roleplay / base noise
        try:
            sizes = browser.quant_sizes(repo)
        except Exception:
            logger.debug("hf_catalog: quant sizes failed for %s; skipping", repo)
            continue
        pick = _pick_quant(sizes)
        if pick is None:
            continue
        quant, size_bytes = pick
        ram = round(size_bytes / 1e9 * _LOAD_OVERHEAD, 2)
        param_b = _param_b(repo)
        # Size sanity: a real Q4 of an N-billion model is ~0.5N GB. A pick far
        # under that is a partial/side file (e.g. a stray Q4_0 shard), not the
        # weights — drop it rather than publish a bogus 0.3 GB for a 26B model.
        if param_b is not None and ram < param_b * 0.35:
            continue
        model_id = f"{_repo_slug(repo)}-q4"  # normalized quant tag for the fleet overlay
        if model_id in seen:
            continue
        seen.add(model_id)
        # KV-aware serve estimate: fetch the arch (config.json) for the precise KV
        # term; a miss (gated base model, network error) yields None arch and a
        # CONSERVATIVE proxy — never the flat file x 1.2 that let a 7B "fit" a Jetson.
        n_layers = n_kv = head_dim = None
        _arch = getattr(browser, "arch", None)
        if callable(_arch):
            try:
                cfg = _arch(repo)
            except Exception:
                cfg = None
            if isinstance(cfg, dict):
                n_layers, n_kv, head_dim = arch_from_config(cfg)
        serve_ram_gb = estimate_serve_gb(
            weights_gb=size_bytes / 1e9,
            n_layers=n_layers,
            n_kv_heads=n_kv,
            head_dim=head_dim,
        )
        out.append(
            CatalogModel(
                model_id=model_id,
                display_name=_display_name(repo),
                family=repo.split("/")[-1].split("-")[0],
                param_b=param_b,
                quant=quant,
                approx_ram_gb=ram,
                hf_repo=repo,
                serve_ram_gb=serve_ram_gb,
            )
        )
    return out


def write_catalog(path: Path, models: list[CatalogModel], *, fetched_at: str) -> None:
    """Atomically persist the catalog cache (temp-write + replace)."""
    payload = {"fetched_at": fetched_at, "models": [asdict(m) for m in models]}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def catalog_fetched_at(path: Path) -> str | None:
    """The cache's `fetched_at` stamp (for a 'menu refreshed X' surface), or None."""
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("fetched_at")
    except (FileNotFoundError, ValueError, OSError):
        return None


# The provisionable HF menu is refreshed by a DAILY systemd timer. If the last good fetch
# is older than this, the timer likely stopped (the enable≠start trap) or HF has been
# unreachable — the menu is aging silently. Two missed cycles = the alert line, so a
# single skipped run doesn't cry wolf.
CATALOG_STALE_AFTER = timedelta(hours=48)


def catalog_is_stale(source: str, fetched_at: str | None, *, now: datetime | None = None) -> bool:
    """True when the provisionable menu is NOT fresh — either the static curated fallback is
    in use (the HF poll never ran / HF unreachable → source != 'hf'), or the HF cache is older
    than CATALOG_STALE_AFTER. Lets a maintainer CATCH a silently-stopped refresh instead of
    only self-reporting `catalog_fetched_at`. The live 'what's-served-now' half of the catalog
    response is unaffected — this flags only the offerable-but-unserved menu."""
    if source != "hf" or not fetched_at:
        return True
    now = now or datetime.now(UTC)
    try:
        ts = datetime.fromisoformat(fetched_at)
    except ValueError:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return (now - ts) > CATALOG_STALE_AFTER


def read_catalog(path: Path) -> list[CatalogModel]:
    """Load the cached catalog, or [] if absent/unreadable (the endpoint then
    falls back to the static curated seed — never an error)."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return []
    out: list[CatalogModel] = []
    for m in payload.get("models", []):
        try:
            out.append(
                CatalogModel(
                    model_id=m["model_id"],
                    display_name=m["display_name"],
                    family=m.get("family", ""),
                    param_b=m.get("param_b"),
                    quant=m.get("quant", ""),
                    approx_ram_gb=float(m["approx_ram_gb"]),
                    hf_repo=m.get("hf_repo", ""),
                    serve_ram_gb=(
                        float(m["serve_ram_gb"]) if m.get("serve_ram_gb") is not None else None
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out
