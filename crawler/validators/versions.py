"""Semantic validation for authoritative PyPI version inventories."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

from packaging.utils import canonicalize_name
from packaging.version import Version

from crawler.models import PackageRecord, VersionRecord

_PYPI_FILES_HOST = "files.pythonhosted.org"


class VersionInventoryValidationError(ValueError):
    """Raised when version records cannot form a safe, coherent inventory."""


def _validate_artifact_name(filename: str, expected_project: str) -> None:
    canonical_filename = canonicalize_name(filename)
    if not canonical_filename.startswith(f"{expected_project}-"):
        raise VersionInventoryValidationError(
            f"artifact does not belong to expected project: {filename}"
        )


def _validate_artifact_url(url: str, filename: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != _PYPI_FILES_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise VersionInventoryValidationError(f"unsafe PyPI artifact URL: {filename}")
    url_filename = unquote(parsed.path.rsplit("/", maxsplit=1)[-1])
    if url_filename != filename:
        raise VersionInventoryValidationError(
            f"artifact URL filename mismatch: {filename}"
        )


def validate_version_inventory(
    records: Iterable[VersionRecord], expected_package: PackageRecord
) -> tuple[VersionRecord, ...]:
    """Validate and return an already PEP 440-sorted version inventory."""
    materialized = tuple(records)
    expected_project = canonicalize_name(expected_package.name)
    expected_order = tuple(
        sorted(materialized, key=lambda record: Version(record.normalized_version))
    )
    if materialized != expected_order:
        raise VersionInventoryValidationError("version records are not PEP 440 sorted")

    normalized_versions: set[Version] = set()
    record_ids: set[str] = set()
    for record in materialized:
        if record.package != expected_package:
            raise VersionInventoryValidationError(
                f"package mismatch for version {record.raw_version}"
            )
        parsed_version = Version(record.normalized_version)
        if str(parsed_version) != record.normalized_version:
            raise VersionInventoryValidationError(
                f"version is not normalized: {record.normalized_version}"
            )
        if parsed_version.is_prerelease != record.is_prerelease:
            raise VersionInventoryValidationError(
                f"incorrect prerelease flag: {record.normalized_version}"
            )
        if parsed_version in normalized_versions:
            raise VersionInventoryValidationError(
                f"duplicate normalized version: {record.normalized_version}"
            )
        if record.record_id in record_ids:
            raise VersionInventoryValidationError(
                f"duplicate version record ID: {record.record_id}"
            )
        normalized_versions.add(parsed_version)
        record_ids.add(record.record_id)

        filenames: set[str] = set()
        for artifact in record.artifacts:
            if artifact.filename in filenames:
                raise VersionInventoryValidationError(
                    f"duplicate artifact filename: {artifact.filename}"
                )
            filenames.add(artifact.filename)
            _validate_artifact_name(artifact.filename, expected_project)
            if artifact.url is not None:
                _validate_artifact_url(artifact.url, artifact.filename)

        release_dates = [
            artifact.upload_time
            for artifact in record.artifacts
            if artifact.upload_time is not None
        ]
        expected_date = min(release_dates) if release_dates else None
        if record.release_date != expected_date:
            raise VersionInventoryValidationError(
                f"incorrect release date: {record.normalized_version}"
            )
        expected_yanked = bool(record.artifacts) and all(
            artifact.is_yanked for artifact in record.artifacts
        )
        if record.is_yanked != expected_yanked:
            raise VersionInventoryValidationError(
                f"incorrect yanked state: {record.normalized_version}"
            )
        requirements = {
            artifact.requires_python
            for artifact in record.artifacts
            if artifact.requires_python is not None
        }
        expected_requirement = (
            next(iter(requirements)) if len(requirements) == 1 else None
        )
        if record.requires_python != expected_requirement:
            raise VersionInventoryValidationError(
                f"incorrect Python requirement: {record.normalized_version}"
            )

    return materialized


__all__ = ["VersionInventoryValidationError", "validate_version_inventory"]
