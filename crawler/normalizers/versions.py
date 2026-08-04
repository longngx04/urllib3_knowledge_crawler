"""Normalize preserved PyPI project JSON into authoritative version records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from crawler.models import (
    DistributionArtifact,
    PackageRecord,
    ProvenanceRecord,
    VersionRecord,
)
from crawler.utils.hashing import stable_record_id
from crawler.utils.http import RetrievedResponse
from crawler.validators.versions import (
    VersionInventoryValidationError,
    validate_version_inventory,
)

_MAX_RELEASES = 10_000
_MAX_ARTIFACTS_PER_RELEASE = 1_000
_MAX_TEXT_LENGTH = 4_096


class PyPIDataError(ValueError):
    """Raised when preserved PyPI JSON violates the expected source contract."""


class VersionNormalizationConflictError(PyPIDataError):
    """Raised when distinct release keys normalize to the same PEP 440 version."""


@dataclass(frozen=True, slots=True)
class VersionInventoryStats:
    """Deterministic summary of one normalized PyPI inventory."""

    total_versions: int
    total_prereleases: int
    total_yanked_versions: int
    total_artifacts: int
    total_unparsable_versions: int


@dataclass(frozen=True, slots=True)
class VersionInventory:
    """Validated records plus release keys that are not valid PEP 440."""

    package: PackageRecord
    records: tuple[VersionRecord, ...]
    unparsable_versions: tuple[str, ...]

    @property
    def stats(self) -> VersionInventoryStats:
        return VersionInventoryStats(
            total_versions=len(self.records),
            total_prereleases=sum(record.is_prerelease for record in self.records),
            total_yanked_versions=sum(record.is_yanked for record in self.records),
            total_artifacts=sum(len(record.artifacts) for record in self.records),
            total_unparsable_versions=len(self.unparsable_versions),
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise PyPIDataError(f"duplicate JSON object key: {key}")
        parsed[key] = value
    return parsed


def _required_mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PyPIDataError(f"{field} must be an object")
    return value


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PyPIDataError(f"{field} must be a string or null")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > _MAX_TEXT_LENGTH:
        raise PyPIDataError(f"{field} exceeds {_MAX_TEXT_LENGTH} characters")
    return normalized


def _required_text(value: object, field: str) -> str:
    parsed = _optional_text(value, field)
    if parsed is None:
        raise PyPIDataError(f"{field} must be a non-empty string")
    return parsed


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PyPIDataError(f"{field} must be a non-negative integer or null")
    return value


def _required_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise PyPIDataError(f"{field} must be a boolean")
    return value


def _optional_datetime(value: object, field: str) -> datetime | None:
    text = _optional_text(value, field)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise PyPIDataError(f"{field} must be a valid ISO-8601 datetime") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PyPIDataError(f"{field} must include a timezone")
    return parsed


def _artifact_from_json(raw: object, release: str) -> DistributionArtifact:
    artifact = _required_mapping(raw, f"releases[{release}] artifact")
    filename = _required_text(artifact.get("filename"), "artifact.filename")
    digests = _required_mapping(artifact.get("digests"), "artifact.digests")
    sha256 = _optional_text(digests.get("sha256"), "artifact.digests.sha256")
    is_yanked = _required_bool(artifact.get("yanked"), "artifact.yanked")
    yanked_reason = _optional_text(
        artifact.get("yanked_reason"), "artifact.yanked_reason"
    )
    try:
        return DistributionArtifact(
            filename=filename,
            url=_optional_text(artifact.get("url"), "artifact.url"),
            size=_optional_int(artifact.get("size"), "artifact.size"),
            sha256=sha256,
            package_type=_optional_text(
                artifact.get("packagetype"), "artifact.packagetype"
            ),
            python_version=_optional_text(
                artifact.get("python_version"), "artifact.python_version"
            ),
            requires_python=_optional_text(
                artifact.get("requires_python"), "artifact.requires_python"
            ),
            upload_time=_optional_datetime(
                artifact.get("upload_time_iso_8601"),
                "artifact.upload_time_iso_8601",
            ),
            is_yanked=is_yanked,
            yanked_reason=yanked_reason,
        )
    except ValidationError as error:
        raise PyPIDataError(f"invalid artifact metadata: {filename}") from error


def _release_record(
    *,
    raw_version: str,
    parsed_version: Version,
    raw_artifacts: object,
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> VersionRecord:
    if not isinstance(raw_artifacts, list):
        raise PyPIDataError(f"releases[{raw_version}] must be an array")
    if len(raw_artifacts) > _MAX_ARTIFACTS_PER_RELEASE:
        raise PyPIDataError(f"releases[{raw_version}] has too many artifacts")
    artifacts = [_artifact_from_json(item, raw_version) for item in raw_artifacts]
    upload_times = [
        artifact.upload_time
        for artifact in artifacts
        if artifact.upload_time is not None
    ]
    requirements = {
        artifact.requires_python
        for artifact in artifacts
        if artifact.requires_python is not None
    }
    release_is_yanked = bool(artifacts) and all(
        artifact.is_yanked for artifact in artifacts
    )
    reasons = {
        artifact.yanked_reason
        for artifact in artifacts
        if artifact.yanked_reason is not None
    }
    normalized_version = str(parsed_version)
    return VersionRecord(
        schema_version="1.0",
        record_type="version",
        record_id=stable_record_id(
            "version",
            {"package": package.purl, "version": normalized_version},
        ),
        package=package,
        provenance=[provenance],
        raw_version=raw_version,
        normalized_version=normalized_version,
        release_date=min(upload_times) if upload_times else None,
        is_prerelease=parsed_version.is_prerelease,
        is_yanked=release_is_yanked,
        yanked_reason=(
            next(iter(reasons)) if release_is_yanked and len(reasons) == 1 else None
        ),
        requires_python=(next(iter(requirements)) if len(requirements) == 1 else None),
        git_tag=None,
        commit_sha=None,
        support_branch=None,
        support_status=None,
        artifacts=artifacts,
    )


def normalize_pypi_versions(
    response: RetrievedResponse, expected_package: PackageRecord
) -> VersionInventory:
    """Normalize exact PyPI project bytes without contacting the network."""
    if response.status_code != 200:
        raise PyPIDataError(f"cannot normalize PyPI HTTP {response.status_code}")
    try:
        payload: Any = json.loads(
            response.content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PyPIDataError("PyPI response must be valid UTF-8 JSON") from error
    root = _required_mapping(payload, "PyPI response")
    info = _required_mapping(root.get("info"), "info")
    actual_name = _required_text(info.get("name"), "info.name")
    expected_name = canonicalize_name(expected_package.name)
    if canonicalize_name(actual_name) != expected_name:
        raise PyPIDataError(
            f"PyPI project mismatch: expected {expected_name}, got {actual_name}"
        )
    releases = _required_mapping(root.get("releases"), "releases")
    if len(releases) > _MAX_RELEASES:
        raise PyPIDataError(f"PyPI response exceeds {_MAX_RELEASES} releases")

    provenance = ProvenanceRecord(
        source_type="pypi",
        source_id=response.url,
        retrieved_at=response.retrieved_at,
        raw_sha256=response.body_sha256,
        extractor_version="0.1.0",
    )
    parsed_releases: list[tuple[Version, str, object]] = []
    unparsable: list[str] = []
    normalized_to_raw: dict[Version, str] = {}
    for raw_version, raw_artifacts in releases.items():
        if (
            not isinstance(raw_version, str)
            or not raw_version
            or len(raw_version) > 256
        ):
            raise PyPIDataError("release keys must be bounded non-empty strings")
        try:
            parsed_version = Version(raw_version)
        except InvalidVersion:
            unparsable.append(raw_version)
            continue
        normalized = str(parsed_version)
        previous = normalized_to_raw.get(parsed_version)
        if previous is not None:
            raise VersionNormalizationConflictError(
                f"release keys {previous!r} and {raw_version!r} both normalize to "
                f"{normalized!r}"
            )
        normalized_to_raw[parsed_version] = raw_version
        parsed_releases.append((parsed_version, raw_version, raw_artifacts))

    records = tuple(
        _release_record(
            raw_version=raw_version,
            parsed_version=parsed_version,
            raw_artifacts=raw_artifacts,
            package=expected_package,
            provenance=provenance,
        )
        for parsed_version, raw_version, raw_artifacts in sorted(
            parsed_releases, key=lambda item: item[0]
        )
    )
    try:
        validated = validate_version_inventory(records, expected_package)
    except VersionInventoryValidationError as error:
        raise PyPIDataError(str(error)) from error
    return VersionInventory(
        package=expected_package,
        records=validated,
        unparsable_versions=tuple(sorted(unparsable)),
    )


__all__ = [
    "PyPIDataError",
    "VersionInventory",
    "VersionInventoryStats",
    "VersionNormalizationConflictError",
    "normalize_pypi_versions",
]
