"""Typed local configuration for crawler infrastructure."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

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


class PackageConfig(BaseModel):
    """Target package identity for one crawl configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str
    ecosystem: str
    purl: str
    repository: str
    version_scheme: Literal["pep440"]


class SourcesConfig(BaseModel):
    """Authoritative source toggles for one package crawl."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    pypi: bool
    github_releases: bool
    github_tags: bool
    changelog: bool
    github_advisories: bool
    osv: bool
    nvd: bool | Literal["optional"]
    patches: bool
    regression_tests: bool


class RepositoryConfig(BaseModel):
    """Repository metadata used for release and changelog correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    default_branch: str
    changelog_candidates: tuple[str, ...]
    security_policy_candidates: tuple[str, ...]


class OutputConfig(BaseModel):
    """Deterministic export settings for one pipeline run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    directory: str
    deterministic: bool
    include_raw: bool
    include_kb_documents: bool


class CrawlerConfig(BaseModel):
    """Full package-specific crawler configuration contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    package: PackageConfig
    sources: SourcesConfig
    repository: RepositoryConfig
    output: OutputConfig
    crawl: HttpClientConfig


def _load_yaml_mapping(path: Path) -> Mapping[str, Any]:
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
    return parsed


def load_http_client_config(path: Path) -> HttpClientConfig:
    """Load and validate the ``crawl`` section of a bounded UTF-8 YAML file."""
    parsed = _load_yaml_mapping(path)
    crawl = parsed.get("crawl")
    if not isinstance(crawl, Mapping):
        raise ConfigurationError("configuration must contain a crawl mapping")
    try:
        return HttpClientConfig.model_validate(dict(crawl))
    except ValidationError as error:
        raise ConfigurationError("invalid crawl configuration") from error


def load_crawler_config(path: Path) -> CrawlerConfig:
    """Load and validate the full crawler configuration from one YAML file."""
    parsed = _load_yaml_mapping(path)
    repository = parsed.get("repository")
    if isinstance(repository, Mapping):
        repository_payload = dict(repository)
        if isinstance(repository_payload.get("changelog_candidates"), list):
            repository_payload["changelog_candidates"] = tuple(
                repository_payload["changelog_candidates"]
            )
        if isinstance(repository_payload.get("security_policy_candidates"), list):
            repository_payload["security_policy_candidates"] = tuple(
                repository_payload["security_policy_candidates"]
            )
        parsed = {**parsed, "repository": repository_payload}
    try:
        return CrawlerConfig.model_validate(parsed)
    except ValidationError as error:
        raise ConfigurationError("invalid crawler configuration") from error


__all__ = [
    "ConfigurationError",
    "CrawlerConfig",
    "HttpClientConfig",
    "OutputConfig",
    "PackageConfig",
    "RepositoryConfig",
    "SourcesConfig",
    "load_crawler_config",
    "load_http_client_config",
]
