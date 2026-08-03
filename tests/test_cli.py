"""Offline tests for the Phase 0 command contract."""

import subprocess
import sys

from typer.testing import CliRunner

from crawler import __version__
from crawler.cli import PROGRAM_NAME, PROGRAM_PURPOSE, app

runner = CliRunner()


def test_package_version_matches_contract() -> None:
    assert __version__ == "0.1.0"


def test_cli_help_describes_purpose_and_options() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert PROGRAM_PURPOSE in result.stdout
    assert "--help" in result.stdout
    assert "--version" in result.stdout


def test_cli_version_matches_contract_exactly() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"{PROGRAM_NAME} 0.1.0\n"


def test_cli_invalid_option_returns_usage_error() -> None:
    result = runner.invoke(app, ["--not-an-option"])

    assert result.exit_code == 2


def test_module_entry_point_exposes_help_contract() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "crawler", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert PROGRAM_PURPOSE in result.stdout
    assert "--help" in result.stdout
    assert "--version" in result.stdout


def test_module_entry_point_exposes_exact_version_contract() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "crawler", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == f"{PROGRAM_NAME} 0.1.0\n"
    assert result.stderr == ""
