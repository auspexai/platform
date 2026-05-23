"""auspexai-coordinator CLI entrypoint.

M2 adds the `token` subgroup for maintainer-token management:
    auspexai-coordinator serve
    auspexai-coordinator token init       # first-run; writes <state>/maintainer.token
    auspexai-coordinator token rotate     # generate new; old expires after 5min overlap
    auspexai-coordinator token show       # list active tokens (and any in overlap window)

Future M-milestones add:
    auspexai-coordinator tenant register  # M5: register a tenant pubkey
    auspexai-coordinator db migrate       # M4: run pending DB migrations
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import click
import uvicorn

from auspexai_platform import __version__
from auspexai_platform.auth.bearer import DEFAULT_OVERLAP, TokenStore, TokenStoreError
from auspexai_platform.config import Config


def _resolve_config(state_dir: Path | None) -> Config:
    return Config.from_env(state_dir=state_dir)


_state_dir_option = click.option(
    "--state-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Coordinator state directory. Overrides AUSPEXAI_STATE_DIR; default ./state/.",
)


@click.group()
@click.version_option(version=__version__, prog_name="auspexai-coordinator")
def main() -> None:
    """AuspexAI coordinator daemon control surface."""


# ----------------------------------------------------------------------------
# serve
# ----------------------------------------------------------------------------


@main.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Interface to bind. Default localhost; pass 0.0.0.0 to expose externally.",
)
@click.option(
    "--port",
    default=8080,
    show_default=True,
    type=int,
    help="Port to bind.",
)
@click.option(
    "--reload",
    is_flag=True,
    help="Reload on source changes (dev only).",
)
def serve(host: str, port: int, reload: bool) -> None:
    """Run the coordinator HTTP server.

    Uses uvicorn's factory pattern (`factory=True`) — uvicorn calls
    `create_app()` exactly once to build the app. The alternative
    (`auspexai_platform.main:app` as a module-level instance) double-
    registers slowapi rate-limit decorators whenever tests also call
    `create_app()` themselves, since the decorators have no idempotency
    and append to the limiter's per-route list on each invocation.
    """
    uvicorn.run(
        "auspexai_platform.main:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ----------------------------------------------------------------------------
# token group
# ----------------------------------------------------------------------------


@main.group()
def token() -> None:
    """Maintainer-token management."""


@token.command("init")
@_state_dir_option
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing maintainer.token file.",
)
def token_init(state_dir: Path | None, force: bool) -> None:
    """Generate the first maintainer token. Idempotent only with --force."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    try:
        new_token = store.initialize(force=force)
    except TokenStoreError as e:
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1) from e
    click.echo(f"Maintainer token initialized at {config.maintainer_token_path}")
    click.echo(f"Token: {new_token}")
    click.echo("Pass this token via `Authorization: Bearer <token>` on operator-console requests.")
    click.echo("Re-run with --force to rotate via re-initialization, or use `token rotate` for an")
    click.echo("overlap-window rotation.")


@token.command("rotate")
@_state_dir_option
@click.option(
    "--overlap-minutes",
    type=int,
    default=int(DEFAULT_OVERLAP.total_seconds() // 60),
    show_default=True,
    help="How long the previous active token remains valid after rotation (minutes).",
)
def token_rotate(state_dir: Path | None, overlap_minutes: int) -> None:
    """Rotate the maintainer token. Previous token valid for the overlap window."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(
            f"ERROR: no maintainer token at {config.maintainer_token_path}. Run `token init` first.",
            err=True,
        )
        raise SystemExit(1)
    new_token = store.rotate(overlap=timedelta(minutes=overlap_minutes))
    click.echo(f"Rotated maintainer token at {config.maintainer_token_path}")
    click.echo(f"New token: {new_token}")
    click.echo(f"Previous token remains valid for {overlap_minutes} minute(s).")


@token.command("show")
@_state_dir_option
def token_show(state_dir: Path | None) -> None:
    """List all currently-valid maintainer tokens (steady state: 1; during rotation overlap: 2)."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(f"No maintainer.token at {config.maintainer_token_path}.", err=True)
        raise SystemExit(1)
    tokens = store.active_tokens()
    if not tokens:
        click.echo(
            "No active tokens — all have expired. Run `token rotate` or `token init --force`."
        )
        raise SystemExit(1)
    for i, t in enumerate(tokens, 1):
        click.echo(f"[{i}] {t}")


if __name__ == "__main__":
    main()
