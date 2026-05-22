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


@dataclass(frozen=True)
class Config:
    """Coordinator runtime configuration. Immutable; replace by re-constructing."""

    state_dir: Path
    receipts_mode: str = DEFAULT_RECEIPTS_MODE

    def __post_init__(self) -> None:
        if self.receipts_mode not in VALID_RECEIPTS_MODES:
            raise ValueError(
                f"receipts_mode must be one of {VALID_RECEIPTS_MODES}, got {self.receipts_mode!r}"
            )

    @property
    def maintainer_token_path(self) -> Path:
        return self.state_dir / "maintainer.token"

    @property
    def control_db_path(self) -> Path:
        """SQLite control DB path. Used from M4 onwards."""
        return self.state_dir / "coordinator.db"

    @property
    def jobs_dir(self) -> Path:
        """Directory holding per-experiment SQLite DBs (M6c+). Each
        experiment's work_units + assignments + results live in their own
        `<jobs_dir>/<experiment_id>.db` file — control DB stays small and
        per-job DBs are independent units (per §5.7)."""
        return self.state_dir / "jobs"

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
        return cls(state_dir=resolved_state_dir, receipts_mode=receipts_mode)
