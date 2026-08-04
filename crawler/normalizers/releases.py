"""Map GitHub tags and releases to normalized PEP 440 version inventory."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from crawler.extractors.changelog import ChangelogEntry, ParsedChangelog
from crawler.models import VersionRecord

_COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ReleaseNormalizationError(ValueError):
    """Raised when release normalization encounters invalid source data."""


@dataclass(frozen=True, slots=True)
class TagMapping:
    """One Git tag resolved to a PEP 440 version with commit provenance."""

    raw_tag: str
    normalized_version: str
    commit_sha: str
    match_type: str
    confidence: float


@dataclass(frozen=True, slots=True)
class ReleaseCorrelation:
    """One package version correlated with repository evidence."""

    version: str
    git_tag: str | None
    commit_sha: str | None
    release_url: str | None
    release_body: str | None
    changelog_entries: tuple[ChangelogEntry, ...] | None
    match_type: str | None
    is_resolved: bool


@dataclass(frozen=True, slots=True)
class ReleaseInventoryStats:
    """Deterministic summary of one release correlation pass."""

    total_versions: int
    resolved_versions: int
    unresolved_versions: int
    total_tags: int
    unmatched_tags: int
    total_releases: int
    total_changelog_entries: int


@dataclass(frozen=True, slots=True)
class ReleaseInventory:
    """Correlated version records with repository evidence and resolution gaps."""

    correlations: tuple[ReleaseCorrelation, ...]
    unresolved_versions: tuple[str, ...]
    stats: ReleaseInventoryStats


def _try_parse_tag(raw_tag: str) -> tuple[Version, str, float] | None:
    """Try to extract a PEP 440 version from a tag name.

    Returns (parsed_version, match_type, confidence) or None.
    """
    candidates: list[tuple[str, str, float]] = []
    if raw_tag.startswith("release-"):
        candidates.append((raw_tag[8:], "release_prefix", 0.8))
    if raw_tag.startswith("v"):
        candidates.append((raw_tag[1:], "v_prefix", 1.0))
    candidates.append((raw_tag, "exact", 1.0))

    for version_str, match_type, confidence in candidates:
        try:
            return Version(version_str), match_type, confidence
        except InvalidVersion:
            continue
    return None


def _tag_preference(mapping: TagMapping) -> tuple[float, int, str]:
    """Higher tuples win when two tags normalize to the same version."""

    match_rank = {
        "v_prefix": 3,
        "exact": 2,
        "release_prefix": 1,
    }.get(mapping.match_type, 0)
    return (mapping.confidence, match_rank, mapping.raw_tag)


def map_tags_to_versions(
    tags_json: list[dict[str, Any]], expected_repo: str
) -> tuple[TagMapping, ...]:
    """Parse GitHub tags API response and map to PEP 440 versions.

    Tags that cannot be parsed as PEP 440 are silently skipped.
    Commit SHAs must be exactly 40 lowercase hexadecimal characters.
    When multiple tags normalize to the same version (for example ``v2.0.5`` and
    ``2.0.5``), keep the preferred tag deterministically instead of failing the crawl.
    """
    del expected_repo  # reserved for future ownership checks
    chosen: dict[str, TagMapping] = {}

    for tag_data in tags_json:
        raw_tag = tag_data.get("name")
        commit_data = tag_data.get("commit", {})
        commit_sha = commit_data.get("sha")

        if not isinstance(raw_tag, str) or not raw_tag:
            continue
        if not isinstance(commit_sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(
            commit_sha
        ):
            raise ReleaseNormalizationError(
                f"invalid commit SHA for tag {raw_tag!r}: {commit_sha!r}"
            )

        result = _try_parse_tag(raw_tag)
        if result is None:
            continue

        parsed_version, match_type, confidence = result
        normalized = str(parsed_version)
        candidate = TagMapping(
            raw_tag=raw_tag,
            normalized_version=normalized,
            commit_sha=commit_sha,
            match_type=match_type,
            confidence=confidence,
        )
        previous = chosen.get(normalized)
        if previous is None or _tag_preference(candidate) > _tag_preference(previous):
            chosen[normalized] = candidate

    mappings = sorted(
        chosen.values(),
        key=lambda item: Version(item.normalized_version),
    )
    return tuple(mappings)


def correlate_releases(
    version_records: Iterable[VersionRecord],
    tag_mappings: tuple[TagMapping, ...],
    releases_json: list[dict[str, Any]] | None = None,
    changelog: ParsedChangelog | None = None,
) -> ReleaseInventory:
    """Match version records with tag mappings, releases, and changelog entries.

    Each VersionRecord is matched to a TagMapping by normalized version. GitHub
    releases and changelog entries are associated through the tag name and version
    string respectively. Unresolved versions (no tag match) are reported honestly.
    """
    tag_by_version: dict[str, TagMapping] = {
        m.normalized_version: m for m in tag_mappings
    }
    release_by_tag: dict[str, dict[str, Any]] = {
        r["tag_name"]: r
        for r in (releases_json or [])
        if isinstance(r.get("tag_name"), str)
    }

    changelog_by_version: dict[str, tuple[ChangelogEntry, ...]] = {}
    total_changelog_entries = 0
    if changelog is not None:
        for cl_release in changelog.releases:
            try:
                norm_ver = str(Version(cl_release.version))
                changelog_by_version[norm_ver] = cl_release.entries
                total_changelog_entries += len(cl_release.entries)
            except InvalidVersion:
                continue

    correlations: list[ReleaseCorrelation] = []
    unresolved: list[str] = []

    for record in version_records:
        normalized_version = record.normalized_version
        tag_match = tag_by_version.get(normalized_version)

        release_match: dict[str, Any] | None = None
        if tag_match is not None:
            release_match = release_by_tag.get(tag_match.raw_tag)

        cl_entries = changelog_by_version.get(normalized_version)

        if tag_match is not None:
            correlations.append(
                ReleaseCorrelation(
                    version=normalized_version,
                    git_tag=tag_match.raw_tag,
                    commit_sha=tag_match.commit_sha,
                    release_url=release_match.get("html_url")
                    if release_match
                    else None,
                    release_body=release_match.get("body") if release_match else None,
                    changelog_entries=cl_entries,
                    match_type=tag_match.match_type,
                    is_resolved=True,
                )
            )
        else:
            unresolved.append(normalized_version)
            correlations.append(
                ReleaseCorrelation(
                    version=normalized_version,
                    git_tag=None,
                    commit_sha=None,
                    release_url=None,
                    release_body=None,
                    changelog_entries=cl_entries,
                    match_type=None,
                    is_resolved=False,
                )
            )

    matched_tags = {c.git_tag for c in correlations if c.git_tag is not None}
    resolved_count = sum(1 for c in correlations if c.is_resolved)

    stats = ReleaseInventoryStats(
        total_versions=len(correlations),
        resolved_versions=resolved_count,
        unresolved_versions=len(unresolved),
        total_tags=len(tag_mappings),
        unmatched_tags=len(tag_mappings) - len(matched_tags),
        total_releases=len(release_by_tag),
        total_changelog_entries=total_changelog_entries,
    )

    return ReleaseInventory(
        correlations=tuple(correlations),
        unresolved_versions=tuple(sorted(unresolved)),
        stats=stats,
    )


__all__ = [
    "ReleaseCorrelation",
    "ReleaseInventory",
    "ReleaseInventoryStats",
    "ReleaseNormalizationError",
    "TagMapping",
    "correlate_releases",
    "map_tags_to_versions",
]
