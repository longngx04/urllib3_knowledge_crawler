"""Tests for safe local .env loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from crawler.utils.envfile import load_default_env_files, load_env_file


def test_load_env_file_sets_allowlisted_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "# comment",
                "GITHUB_TOKEN=ghp_test_token",
                "NVD_API_KEY='nvd-secret'",
                "export CRAWLER_OFFLINE=1",
                "EVIL_KEY=should-not-load",
                "",
            ]
        ),
        encoding="utf-8",
    )

    applied = load_env_file(env_path)

    assert set(applied) == {"GITHUB_TOKEN", "NVD_API_KEY", "CRAWLER_OFFLINE"}
    assert os.environ["GITHUB_TOKEN"] == "ghp_test_token"
    assert os.environ["NVD_API_KEY"] == "nvd-secret"
    assert os.environ["CRAWLER_OFFLINE"] == "1"
    assert "EVIL_KEY" not in os.environ


def test_load_env_file_preserves_existing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "already-set")
    env_path = tmp_path / ".env"
    env_path.write_text("GITHUB_TOKEN=from-file\n", encoding="utf-8")

    applied = load_env_file(env_path)

    assert applied == ()
    assert os.environ["GITHUB_TOKEN"] == "already-set"


def test_load_default_env_files_finds_parent_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    (tmp_path / ".env").write_text("GITHUB_TOKEN=parent-token\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()

    applied = load_default_env_files(start=nested)

    assert applied == ("GITHUB_TOKEN",)
    assert os.environ["GITHUB_TOKEN"] == "parent-token"


def test_load_env_file_rejects_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_bytes(b"GITHUB_TOKEN=" + (b"x" * 70_000))

    with pytest.raises(ValueError, match="exceeds"):
        load_env_file(env_path)
