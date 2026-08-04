"""Phase 12 installation and package-metadata smoke checks."""

from __future__ import annotations

import importlib
import importlib.metadata
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"


def test_pyproject_declares_complete_package_metadata() -> None:
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    project = data["project"]

    assert project["name"] == "urllib3-knowledge-crawler"
    assert project["version"] == "0.1.0"
    assert project["requires-python"] == ">=3.11"
    assert project["dependencies"]
    assert project["optional-dependencies"]["dev"]
    assert data["project"]["scripts"]["urllib3-kb"] == "crawler.cli:app"
    assert "crawler*" in data["tool"]["setuptools"]["packages"]["find"]["include"]


def test_crawler_package_import_smoke() -> None:
    importlib.import_module("crawler")
    importlib.import_module("crawler.cli")
    importlib.import_module("crawler.pipeline")
    importlib.import_module("crawler.config")


def test_installed_distribution_matches_pyproject() -> None:
    metadata = importlib.metadata.metadata("urllib3-knowledge-crawler")
    assert metadata["Name"] == "urllib3-knowledge-crawler"
    assert metadata["Version"] == "0.1.0"
    assert metadata["Requires-Python"] == ">=3.11"


@pytest.mark.slow
def test_editable_install_imports_without_network(tmp_path: Path) -> None:
    """Verify package layout via a no-deps editable install in an isolated venv."""
    venv_dir = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    venv_python = venv_dir / "bin" / "python"
    subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "-e",
            str(PROJECT_ROOT),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        [
            str(venv_python),
            "-c",
            "import crawler; print(crawler.__version__)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "0.1.0"
