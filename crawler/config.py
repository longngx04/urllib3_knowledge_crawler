"""Typed local configuration for crawler infrastructure."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, ValidationError

_MAX_CONFIG_BYTES = 1_048_576


class ConfigurationError(ValueError):
    """Raised when a local project configuration is unsafe or invalid."""


class HttpClientConfig(BaseModel):
    """Bounded retrieval settings shared by all source adapters."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    timeout_seconds: float = Field(gt=0, le=300)
    max_retries: int = Field(ge=0, le=10)
    cache_enabled: bool
    respect_rate_limits: bool
    max_response_bytes: int = Field(gt=0, le=104_857_600)
    initial_backoff_seconds: float = Field(ge=0, le=60)
    max_retry_delay_seconds: float = Field(gt=0, le=3_600)


def load_http_client_config(path: Path) -> HttpClientConfig:
    """Load and validate the ``crawl`` section of a bounded UTF-8 YAML file."""
    if path.is_symlink():
        raise ConfigurationError("configuration path must not be a symlink")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ConfigurationError(f"cannot read configuration: {path}") from error
    if size > _MAX_CONFIG_BYTES:
        raise ConfigurationError("configuration exceeds the 1 MiB size limit")

    try:
        parsed: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ConfigurationError(f"invalid configuration: {path}") from error
    if not isinstance(parsed, Mapping):
        raise ConfigurationError("configuration root must be a mapping")

    crawl = parsed.get("crawl")
    if not isinstance(crawl, Mapping):
        raise ConfigurationError("configuration must contain a crawl mapping")
    try:
        return HttpClientConfig.model_validate(dict(crawl))
    except ValidationError as error:
        raise ConfigurationError("invalid crawl configuration") from error


__all__ = ["ConfigurationError", "HttpClientConfig", "load_http_client_config"]
