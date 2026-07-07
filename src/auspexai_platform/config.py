"""Coordinator runtime configuration.

The coordinator reads two pieces of state from disk:

  - `<state_dir>/maintainer.token` — the maintainer bearer token store.
  - `<state_dir>/coordinator.db` — the SQLite control DB (M4+).

State directory resolution order:

  1. CLI `--state-dir <path>` argument (highest priority)
  2. `AUSPEXAI_STATE_DIR` environment variable
  3. Default: `./state/` (cwd-relative — fine for dev; production deployments
     pass an explicit path).

The config object is built once per app start and threaded through DI. Tests
build their own config pointing at a temp dir.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_DIR = Path("./state")
DEFAULT_RECEIPTS_MODE = "dev"
VALID_RECEIPTS_MODES = ("dev", "operational")
# Mirrors receipts.rekor.DEFAULT_REKOR_URL (kept inline so config stays
# dependency-light). The A2 backfill sweep submits attestations here.
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

# M7f tier-eligibility thresholds. Per §6.2 these are the receipt-history
# preconditions that the eligibility readout reports on. They do NOT
# auto-promote — per §6.1, T1→T2 also requires a real-identity check OR
# vouching by an existing T2+, plus human review. The eligibility surface
# only reports "thresholds met / not met"; the §6.1 identity gate and the
# tier-bump endpoint itself ship with the vouching / identity-verification
# milestone(s).
DEFAULT_TIER_T2_RECEIPT_THRESHOLD = 50
# Firewall #3 (inc-2): breadth is now distinct TENANTS, not distinct experiments —
# an account earns T2 by corroborating *diverse* tenants' work (independence),
# not by one tenant running many experiments (which a single operator can farm).
DEFAULT_TIER_T2_DISTINCT_TENANTS = 3
# Anti-burst (inc-2): minimum account age before T2 is reachable, so an account
# cannot spin up and farm trust in a single sprint. 0 disables the gate.
DEFAULT_TIER_T2_MIN_ACCOUNT_AGE_DAYS = 7
# §6.2.2 anti-Sybil vouching bars (inc-2 — moved from hardcoded to config): a
# voucher must already hold this many receipts across this many distinct tenants.
DEFAULT_VOUCH_MIN_RECEIPTS = 20
DEFAULT_VOUCH_MIN_DISTINCT_TENANTS = 2
# §41 containment floor: a tenant whose trust tier is BELOW this requires its
# code to run under STRICT host isolation (the scheduler routes such units only
# to strict-sandbox workers). 0 = disabled (Phase-1 default: vetted tenants +
# operator-owned fleet → permissive acceptable). Raise (e.g. 2) when untrusted
# tenants arrive so T0/T1 code is forced onto hardened workers.
DEFAULT_CONTAINMENT_STRICT_BELOW_TIER = 0


@dataclass(frozen=True)
class Config:
    """Coordinator runtime configuration. Immutable; replace by re-constructing."""

    state_dir: Path
    receipts_mode: str = DEFAULT_RECEIPTS_MODE
    tier_t2_receipt_threshold: int = DEFAULT_TIER_T2_RECEIPT_THRESHOLD
    tier_t2_distinct_tenants: int = DEFAULT_TIER_T2_DISTINCT_TENANTS
    tier_t2_min_account_age_days: int = DEFAULT_TIER_T2_MIN_ACCOUNT_AGE_DAYS
    vouch_min_receipts: int = DEFAULT_VOUCH_MIN_RECEIPTS
    vouch_min_distinct_tenants: int = DEFAULT_VOUCH_MIN_DISTINCT_TENANTS
    containment_strict_below_tier: int = DEFAULT_CONTAINMENT_STRICT_BELOW_TIER
    rekor_url: str = DEFAULT_REKOR_URL

    def __post_init__(self) -> None:
        if self.receipts_mode not in VALID_RECEIPTS_MODES:
            raise ValueError(
                f"receipts_mode must be one of {VALID_RECEIPTS_MODES}, got {self.receipts_mode!r}"
            )
        if self.tier_t2_receipt_threshold < 1:
            raise ValueError(
                f"tier_t2_receipt_threshold must be >=1, got {self.tier_t2_receipt_threshold}"
            )
        if self.tier_t2_distinct_tenants < 1:
            raise ValueError(
                f"tier_t2_distinct_tenants must be >=1, got {self.tier_t2_distinct_tenants}"
            )
        if self.tier_t2_min_account_age_days < 0:
            raise ValueError(
                f"tier_t2_min_account_age_days must be >=0, got {self.tier_t2_min_account_age_days}"
            )

    @property
    def maintainer_token_path(self) -> Path:
        return self.state_dir / "maintainer.token"

    @property
    def control_db_path(self) -> Path:
        """SQLite control DB path. Used from M4 onwards."""
        return self.state_dir / "coordinator.db"

    @property
    def hf_catalog_path(self) -> Path:
        """Cached HuggingFace provisionable catalog (D23), refreshed by the
        `refresh-hf-catalog` timer and read by `GET /models/supported`."""
        return self.state_dir / "hf_catalog.json"

    @property
    def jobs_dir(self) -> Path:
        """Directory holding per-experiment SQLite DBs (M6c+). Each
        experiment's work_units + assignments + results live in their own
        `<jobs_dir>/<experiment_id>.db` file — control DB stays small and
        per-job DBs are independent units (per §5.7)."""
        return self.state_dir / "jobs"

    @property
    def packages_dir(self) -> Path:
        """Content-addressed executor-package blobs (§9 #40a courier). One
        ``<package_digest>.tar.gz`` per uploaded tenant executor package;
        the digest is `compute_package_digest` over the extracted tree
        (verified on upload, re-derived by workers after fetch)."""
        return self.state_dir / "packages"

    @property
    def cors_allowed_origins(self) -> list[str]:
        """CORS allowed origins. Read from ``CORS_ALLOWED_ORIGINS`` env var
        (comma-separated). Defaults to ``["https://auspexai.network"]``."""
        raw = os.environ.get("CORS_ALLOWED_ORIGINS", "")
        if raw.strip():
            return [o.strip() for o in raw.split(",") if o.strip()]
        return ["https://auspexai.network"]

    @property
    def receipt_signing_key_path(self) -> Path:
        """Persistent Ed25519 receipt-signing key (M7b).

        Created on first startup at file mode `0600`. In `dev` mode, this
        is the placeholder key whose pubkey will not appear in
        `AUTHORIZED_SIGNERS.md`. In `operational` mode, the same file
        holds the §5.16-attested key (Path A) or its post-rotation
        replacement (Path B).
        """
        return self.state_dir / "coordinator_receipt_signing_key.pem"

    @classmethod
    def from_env(cls, *, state_dir: Path | None = None) -> Config:
        """Build a config. Explicit `state_dir` wins over env wins over default.
        `AUSPEXAI_RECEIPTS_MODE` controls receipts_mode."""
        resolved_state_dir: Path
        if state_dir is not None:
            resolved_state_dir = state_dir
        elif env_value := os.environ.get("AUSPEXAI_STATE_DIR"):
            resolved_state_dir = Path(env_value)
        else:
            resolved_state_dir = DEFAULT_STATE_DIR
        receipts_mode = os.environ.get("AUSPEXAI_RECEIPTS_MODE", DEFAULT_RECEIPTS_MODE)
        t2_receipts = int(
            os.environ.get(
                "AUSPEXAI_TIER_T2_RECEIPT_THRESHOLD",
                DEFAULT_TIER_T2_RECEIPT_THRESHOLD,
            )
        )
        t2_tenants = int(
            os.environ.get(
                "AUSPEXAI_TIER_T2_DISTINCT_TENANTS",
                DEFAULT_TIER_T2_DISTINCT_TENANTS,
            )
        )
        t2_min_age = int(
            os.environ.get(
                "AUSPEXAI_TIER_T2_MIN_ACCOUNT_AGE_DAYS",
                DEFAULT_TIER_T2_MIN_ACCOUNT_AGE_DAYS,
            )
        )
        vouch_min_receipts = int(
            os.environ.get("AUSPEXAI_VOUCH_MIN_RECEIPTS", DEFAULT_VOUCH_MIN_RECEIPTS)
        )
        vouch_min_tenants = int(
            os.environ.get(
                "AUSPEXAI_VOUCH_MIN_DISTINCT_TENANTS", DEFAULT_VOUCH_MIN_DISTINCT_TENANTS
            )
        )
        containment_strict_below_tier = int(
            os.environ.get(
                "AUSPEXAI_CONTAINMENT_STRICT_BELOW_TIER", DEFAULT_CONTAINMENT_STRICT_BELOW_TIER
            )
        )
        rekor_url = os.environ.get("AUSPEXAI_REKOR_URL", DEFAULT_REKOR_URL)
        return cls(
            state_dir=resolved_state_dir,
            receipts_mode=receipts_mode,
            tier_t2_receipt_threshold=t2_receipts,
            tier_t2_distinct_tenants=t2_tenants,
            tier_t2_min_account_age_days=t2_min_age,
            vouch_min_receipts=vouch_min_receipts,
            vouch_min_distinct_tenants=vouch_min_tenants,
            containment_strict_below_tier=containment_strict_below_tier,
            rekor_url=rekor_url,
        )
