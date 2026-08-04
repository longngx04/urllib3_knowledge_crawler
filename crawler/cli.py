"""Command-line interface for the urllib3 knowledge crawler pipeline."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer

from crawler import __version__
from crawler.config import ConfigurationError, CrawlerConfig, load_crawler_config
from crawler.pipeline import (
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILURE,
    PipelineError,
    build_pipeline_state,
    format_query_rows,
    query_security_knowledge,
    resolve_pipeline_paths,
    run_pipeline,
    stage_build_kb,
    stage_crawl,
    stage_enrich,
    stage_normalize,
    stage_stats,
    stage_validate,
)
from crawler.utils.envfile import load_default_env_files
from crawler.validators.findings import PipelineValidationError

# Load ignored local `.env` before any command reads credentials.
load_default_env_files()

PROGRAM_NAME = "urllib3-knowledge-crawler"
PROGRAM_PURPOSE = "Build version-aware urllib3 security knowledge for AI-assisted SAST."

app = typer.Typer(
    name="urllib3-kb",
    help=PROGRAM_PURPOSE,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _version_callback(value: bool) -> None:
    """Print the installed application version and exit."""
    if value:
        typer.echo(f"{PROGRAM_NAME} {__version__}")
        raise typer.Exit()


def _load_config(config: Path) -> CrawlerConfig:
    try:
        return load_crawler_config(config)
    except ConfigurationError as error:
        typer.echo(f"configuration error: {error}", err=True)
        raise typer.Exit(code=2) from error


@app.callback(invoke_without_command=True)
def cli(
    ctx: typer.Context,
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
    """Build version-aware security knowledge for configured Python packages."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command("crawl")
def crawl_command(
    config: Annotated[
        Path,
        typer.Option(
            "--config", help="Path to the YAML configuration file.", exists=True
        ),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use fixtures instead of the network.")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Fetch authoritative raw sources into the configured raw store."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        stage_crawl(state)
    except (PipelineError, AssertionError) as error:
        typer.echo(f"crawl failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    typer.echo(f"crawl complete: raw store at {state.paths.raw}")


@app.command("normalize")
def normalize_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use fixtures instead of the network.")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Normalize raw sources into versions.jsonl and advisories.jsonl."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        stage_normalize(state)
    except (PipelineError, AssertionError) as error:
        typer.echo(f"normalize failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    version_count = (
        len(state.version_inventory.records) if state.version_inventory else 0
    )
    typer.echo(
        f"normalize complete: {version_count} versions, "
        f"{len(state.advisories)} advisories -> {state.paths.normalized}"
    )


@app.command("enrich")
def enrich_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use fixtures instead of the network.")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Enrich advisories with patch evidence and security patterns."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        stage_enrich(state)
    except (PipelineError, AssertionError) as error:
        typer.echo(f"enrich failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    patch_count = state.patches.record_count if state.patches else 0
    pattern_count = state.patterns.record_count if state.patterns else 0
    typer.echo(
        f"enrich complete: {patch_count} patches, {pattern_count} patterns -> "
        f"{state.paths.normalized}"
    )


@app.command("validate")
def validate_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Offline mode (no network).")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit with code 1 when findings exist.")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Validate normalized inventories and export validation_errors.json when needed."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        result = stage_validate(state, strict=strict)
    except PipelineValidationError as error:
        typer.echo(f"validation failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    except PipelineError as error:
        typer.echo(f"validate failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error

    if result.passed:
        typer.echo("validation passed")
        raise typer.Exit(EXIT_SUCCESS)
    typer.echo(f"validation completed with {result.error_count} finding(s)")
    raise typer.Exit(EXIT_VALIDATION_FAILURE if strict else EXIT_SUCCESS)


@app.command("build-kb")
def build_kb_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Offline mode (no network).")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Generate retrieval-oriented KB documents from security patterns."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        stage_build_kb(state)
    except PipelineError as error:
        typer.echo(f"build-kb failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    doc_count = state.kb_documents.record_count if state.kb_documents else 0
    typer.echo(f"build-kb complete: {doc_count} documents -> {state.paths.kb}")


@app.command("stats")
def stats_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Offline mode (no network).")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Compute quality metrics and write stats.json plus manifest.json."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        stage_stats(state)
    except PipelineError as error:
        typer.echo(f"stats failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    typer.echo(f"stats complete: {state.paths.root / 'stats.json'}")


@app.command("run")
def run_command(
    config: Annotated[
        Path,
        typer.Option("--config", help="Path to the YAML configuration.", exists=True),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", help="Override output directory.")
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use fixtures instead of the network.")
    ] = False,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
    skip_crawl: Annotated[
        bool,
        typer.Option("--skip-crawl", help="Skip the crawl stage and reuse raw cache."),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug logging.")
    ] = False,
) -> None:
    """Run the full crawl, normalize, enrich, validate, build-kb, and stats pipeline."""
    _configure_logging(verbose)
    crawler_config = _load_config(config)
    state = build_pipeline_state(
        crawler_config,
        output_override=output,
        offline=offline,
        fixture_dir=fixture_dir,
    )
    try:
        run_pipeline(state, skip_crawl=skip_crawl)
    except (
        PipelineError,
        PipelineValidationError,
        AssertionError,
        ValueError,
        OSError,
    ) as error:
        typer.echo(f"run failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error
    version_count = (
        len(state.version_inventory.records) if state.version_inventory else 0
    )
    pattern_count = state.patterns.record_count if state.patterns else 0
    typer.echo(
        f"run complete: {version_count} versions, {len(state.advisories)} advisories, "
        f"{pattern_count} patterns -> {state.paths.root}"
    )


@app.command("query")
def query_command(
    package: Annotated[str, typer.Option("--package", help="Package name to query.")],
    version: Annotated[
        str, typer.Option("--version", help="Installed package version to evaluate.")
    ],
    symbol: Annotated[
        str | None,
        typer.Option("--symbol", help="Optional vulnerable symbol filter."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", help="Optional config for output.directory resolution."
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Override normalized output directory."),
    ] = None,
    fixture_dir: Annotated[
        Path | None,
        typer.Option(
            "--fixture-dir",
            help="Offline fixture directory.",
            exists=True,
            file_okay=False,
        ),
    ] = None,
) -> None:
    """Query normalized security patterns for one package version."""
    normalized_directory: Path
    if output is not None:
        normalized_directory = output / "normalized"
    elif config is not None:
        crawler_config = _load_config(config)
        paths = resolve_pipeline_paths(crawler_config, None)
        normalized_directory = paths.normalized
    else:
        normalized_directory = Path("data/normalized")

    try:
        rows = query_security_knowledge(
            package_name=package,
            version=version,
            symbol=symbol,
            normalized_directory=normalized_directory,
            fixture_dir=fixture_dir,
        )
    except PipelineError as error:
        typer.echo(f"query failed: {error}", err=True)
        raise typer.Exit(EXIT_VALIDATION_FAILURE) from error

    typer.echo(format_query_rows(rows))
