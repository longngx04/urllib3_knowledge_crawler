"""Tests for bounded Phase 2 retrieval configuration."""

from pathlib import Path

import pytest

from crawler.config import ConfigurationError, load_http_client_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_http_config_loads_committed_crawl_settings() -> None:
    config = load_http_client_config(PROJECT_ROOT / "configs" / "urllib3.yaml")

    assert config.timeout_seconds == 30
    assert config.max_retries == 4
    assert config.cache_enabled is True
    assert config.respect_rate_limits is True
    assert config.max_response_bytes == 10_485_760
    assert config.initial_backoff_seconds == 1.0
    assert config.max_retry_delay_seconds == 60.0


@pytest.mark.parametrize(
    "content",
    [
        "[]",
        "package: urllib3\n",
        "crawl:\n  timeout_seconds: -1\n",
        "crawl:\n  timeout_seconds: 1\n  unknown_setting: true\n",
    ],
)
def test_http_config_rejects_invalid_shapes(tmp_path: Path, content: str) -> None:
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_http_client_config(config_path)


def test_http_config_rejects_oversized_file(tmp_path: Path) -> None:
    config_path = tmp_path / "large.yaml"
    config_path.write_bytes(b"x" * 1_048_577)

    with pytest.raises(ConfigurationError, match="1 MiB"):
        load_http_client_config(config_path)


def test_http_config_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text("crawl: {}\n", encoding="utf-8")
    link = tmp_path / "config.yaml"
    link.symlink_to(target)

    with pytest.raises(ConfigurationError, match="symlink"):
        load_http_client_config(link)
