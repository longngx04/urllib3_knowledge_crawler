"""Offline tests for Phase 11 pipeline CLI commands."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crawler.cli import app
from crawler.config import load_crawler_config
from crawler.pipeline import build_pipeline_state, run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "configs" / "urllib3.yaml"
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "pipeline"

runner = CliRunner()

PIPELINE_COMMANDS = (
    "crawl",
    "normalize",
    "enrich",
    "validate",
    "build-kb",
    "stats",
    "run",
    "query",
)


@pytest.mark.parametrize("command", PIPELINE_COMMANDS)
def test_pipeline_command_help_includes_description(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0
    assert "--help" in result.stdout
    assert (
        command.replace("-", " ") in result.stdout.lower() or command in result.stdout
    )


def test_offline_run_produces_deterministic_outputs(tmp_path: Path) -> None:
    config = load_crawler_config(CONFIG_PATH)
    output_dir = tmp_path / "data"

    def _execute() -> dict[str, str]:
        state = build_pipeline_state(
            config,
            output_override=output_dir,
            offline=True,
            fixture_dir=FIXTURE_DIR,
        )
        run_pipeline(state)
        digests: dict[str, str] = {}
        for relative in (
            "normalized/versions.jsonl",
            "normalized/advisories.jsonl",
            "normalized/patches.jsonl",
            "normalized/security_patterns.jsonl",
            "kb/documents.jsonl",
            "stats.json",
            "manifest.json",
        ):
            path = output_dir / relative
            assert path.is_file(), relative
            digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        return digests

    first = _execute()
    second = _execute()
    assert first == second
    assert first["normalized/versions.jsonl"]
    assert first["normalized/advisories.jsonl"]
    assert first["normalized/security_patterns.jsonl"]


def test_offline_run_via_cli(tmp_path: Path) -> None:
    output_dir = tmp_path / "cli-data"
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(CONFIG_PATH),
            "--output",
            str(output_dir),
            "--offline",
            "--fixture-dir",
            str(FIXTURE_DIR),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (output_dir / "normalized" / "security_patterns.jsonl").is_file()
    assert "run complete" in result.stdout


def test_query_command_returns_evidence_backed_fields(tmp_path: Path) -> None:
    output_dir = tmp_path / "query-data"
    runner.invoke(
        app,
        [
            "run",
            "--config",
            str(CONFIG_PATH),
            "--output",
            str(output_dir),
            "--offline",
            "--fixture-dir",
            str(FIXTURE_DIR),
        ],
    )

    result = runner.invoke(
        app,
        [
            "query",
            "--package",
            "urllib3",
            "--version",
            "2.6.0",
            "--output",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Package: urllib3" in result.stdout
    assert "Version: 2.6.0" in result.stdout
    assert "Affected: yes" in result.stdout
    assert "Canonical advisory:" in result.stdout
    assert "Detection type:" in result.stdout
    assert "Evidence:" in result.stdout
    assert "Confidence:" in result.stdout


def test_validate_strict_exits_one_on_findings(tmp_path: Path) -> None:
    output_dir = tmp_path / "validate-data"
    runner.invoke(
        app,
        [
            "run",
            "--config",
            str(CONFIG_PATH),
            "--output",
            str(output_dir),
            "--offline",
            "--fixture-dir",
            str(FIXTURE_DIR),
            "--skip-crawl",
        ],
    )
    # Remove provenance from one record to force a validation finding.
    versions_path = output_dir / "normalized" / "versions.jsonl"
    lines = versions_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["provenance"] = []
    lines[0] = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    versions_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "validate",
            "--config",
            str(CONFIG_PATH),
            "--output",
            str(output_dir),
            "--offline",
            "--strict",
        ],
    )
    assert result.exit_code == 1


def test_module_entry_point_lists_pipeline_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "crawler", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    for command in PIPELINE_COMMANDS:
        assert command in result.stdout
