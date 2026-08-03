"""Command-line interface for the crawler bootstrap."""

from typing import Annotated

import typer

from crawler import __version__

PROGRAM_NAME = "urllib3-knowledge-crawler"
PROGRAM_PURPOSE = "Build version-aware urllib3 security knowledge for AI-assisted SAST."


def _version_callback(value: bool) -> None:
    """Print the installed application version and exit."""
    if value:
        typer.echo(f"{PROGRAM_NAME} {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="urllib3-kb",
    help=PROGRAM_PURPOSE,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)


@app.callback(invoke_without_command=True)
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the application version and exit.",
        ),
    ] = False,
) -> None:
    """Expose the Phase 0 help and version command seam."""
