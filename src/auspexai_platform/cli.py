"""auspexai-coordinator CLI entrypoint.

M1 ships `serve`. Future subcommands (M2+):
    auspexai-coordinator serve              # this milestone
    auspexai-coordinator token init         # first-run maintainer-token setup (M2)
    auspexai-coordinator token rotate       # rotate with 5-minute overlap (M2)
    auspexai-coordinator tenant register    # register a tenant pubkey (M5)
    auspexai-coordinator db migrate         # run pending migrations (M4)
"""

from __future__ import annotations

import click
import uvicorn

from auspexai_platform import __version__


@click.group()
@click.version_option(version=__version__, prog_name="auspexai-coordinator")
def main() -> None:
    """AuspexAI coordinator daemon control surface."""


@main.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Interface to bind. Defaults to localhost; pass --host 0.0.0.0 to expose externally (warning printed in M2+).",
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
    """Run the coordinator HTTP server."""
    uvicorn.run(
        "auspexai_platform.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
