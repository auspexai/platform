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


@dataclass(frozen=True)
class Config:
    """Coordinator runtime configuration. Immutable; replace by re-constructing."""

    state_dir: Path

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

    @classmethod
    def from_env(cls, *, state_dir: Path | None = None) -> Config:
        """Build a config. Explicit `state_dir` wins over env wins over default."""
        if state_dir is not None:
            return cls(state_dir=state_dir)
        env_value = os.environ.get("AUSPEXAI_STATE_DIR")
        if env_value:
            return cls(state_dir=Path(env_value))
        return cls(state_dir=DEFAULT_STATE_DIR)
