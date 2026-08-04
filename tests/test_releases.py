"""Offline tests for the release normalizer."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crawler.extractors.changelog import parse_changelog
from crawler.models import (
    PackageRecord,
    ProvenanceRecord,
    VersionRecord,
)
from crawler.normalizers.releases import (
    ReleaseNormalizationError,
    correlate_releases,
    map_tags_to_versions,
)
from crawler.utils.hashing import stable_record_id

FIXTURES = Path(__file__).parent / "fixtures"


def _make_version_record(version: str) -> VersionRecord:
    """Build a minimal version record for testing."""
    package = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")
    provenance = ProvenanceRecord(
        source_type="pypi",
        source_id="https://pypi.org/pypi/urllib3/json",
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )
    return VersionRecord(
        schema_version="1.0",
        record_type="version",
        record_id=stable_record_id(
            "version", {"package": "pkg:pypi/urllib3", "version": version}
        ),
        package=package,
        provenance=[provenance],
        raw_version=version,
        normalized_version=version,
        release_date=None,
        is_prerelease=False,
        is_yanked=False,
        artifacts=[],
    )


class TestMapTagsToVersions:
    def test_fixture_tags(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        # 5 tags total, 1 is "not-a-version" which is skipped
        assert len(mappings) == 4
        versions = [m.normalized_version for m in mappings]
        assert "2.5.0" in versions
        assert "2.6.0" in versions
        assert "2.7.0" in versions
        assert "2.7.1a1" in versions

    def test_pep440_sorting(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        versions = [m.normalized_version for m in mappings]
        assert versions == ["2.5.0", "2.6.0", "2.7.0", "2.7.1a1"]

    def test_exact_match_type(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        m270 = next(m for m in mappings if m.normalized_version == "2.7.0")
        assert m270.match_type == "exact"
        assert m270.confidence == 1.0
        assert m270.raw_tag == "2.7.0"

    def test_commit_sha_stored(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        m270 = next(m for m in mappings if m.normalized_version == "2.7.0")
        assert m270.commit_sha == "aabbccddee00112233445566778899aabbccddee"

    def test_unparsable_tags_skipped(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        raw_tags = [m.raw_tag for m in mappings]
        assert "not-a-version" not in raw_tags

    def test_v_prefix_matching(self) -> None:
        tags = [
            {
                "name": "v1.0.0",
                "commit": {"sha": "a" * 40},
            }
        ]
        mappings = map_tags_to_versions(tags, "test/repo")
        assert len(mappings) == 1
        assert mappings[0].match_type == "v_prefix"
        assert mappings[0].normalized_version == "1.0.0"
        assert mappings[0].confidence == 1.0

    def test_release_prefix_matching(self) -> None:
        tags = [
            {
                "name": "release-1.0.0",
                "commit": {"sha": "b" * 40},
            }
        ]
        mappings = map_tags_to_versions(tags, "test/repo")
        assert len(mappings) == 1
        assert mappings[0].match_type == "release_prefix"
        assert mappings[0].confidence == 0.8

    def test_invalid_commit_sha_rejected(self) -> None:
        tags = [
            {
                "name": "1.0.0",
                "commit": {"sha": "not-a-sha"},
            }
        ]
        with pytest.raises(ReleaseNormalizationError, match="invalid commit SHA"):
            map_tags_to_versions(tags, "test/repo")

    def test_duplicate_normalized_tags_prefer_v_prefix(self) -> None:
        tags = [
            {
                "name": "2.0.5",
                "commit": {"sha": "a" * 40},
            },
            {
                "name": "v2.0.5",
                "commit": {"sha": "b" * 40},
            },
        ]
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        assert len(mappings) == 1
        assert mappings[0].raw_tag == "v2.0.5"
        assert mappings[0].commit_sha == "b" * 40
        assert mappings[0].match_type == "v_prefix"

    def test_empty_tags(self) -> None:
        mappings = map_tags_to_versions([], "test/repo")
        assert mappings == ()

    def test_missing_name_skipped(self) -> None:
        tags = [{"commit": {"sha": "a" * 40}}]
        mappings = map_tags_to_versions(tags, "test/repo")
        assert mappings == ()


class TestCorrelateReleases:
    def test_basic_correlation(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        releases = json.loads((FIXTURES / "github_releases.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")

        records = [
            _make_version_record("2.5.0"),
            _make_version_record("2.6.0"),
            _make_version_record("2.7.0"),
        ]
        inventory = correlate_releases(records, mappings, releases_json=releases)
        assert inventory.stats.total_versions == 3
        assert inventory.stats.resolved_versions == 3
        assert inventory.stats.unresolved_versions == 0
        assert len(inventory.unresolved_versions) == 0

    def test_unresolved_versions_reported(self) -> None:
        mappings = map_tags_to_versions(
            [{"name": "2.7.0", "commit": {"sha": "a" * 40}}],
            "urllib3/urllib3",
        )
        records = [
            _make_version_record("2.6.0"),
            _make_version_record("2.7.0"),
        ]
        inventory = correlate_releases(records, mappings)
        assert inventory.stats.resolved_versions == 1
        assert inventory.stats.unresolved_versions == 1
        assert "2.6.0" in inventory.unresolved_versions

    def test_release_url_associated(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        releases = json.loads((FIXTURES / "github_releases.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")

        records = [_make_version_record("2.7.0")]
        inventory = correlate_releases(records, mappings, releases_json=releases)
        c270 = next(c for c in inventory.correlations if c.version == "2.7.0")
        assert c270.is_resolved is True
        assert (
            c270.release_url == "https://github.com/urllib3/urllib3/releases/tag/2.7.0"
        )
        assert c270.release_body is not None

    def test_changelog_entries_associated(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        changelog_content = (FIXTURES / "changelog.rst").read_text("utf-8")
        changelog = parse_changelog(changelog_content, format="rst")

        records = [_make_version_record("2.7.0")]
        inventory = correlate_releases(records, mappings, changelog=changelog)
        c270 = next(c for c in inventory.correlations if c.version == "2.7.0")
        assert c270.changelog_entries is not None
        assert len(c270.changelog_entries) > 0

    def test_stats_accuracy(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        releases = json.loads((FIXTURES / "github_releases.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        changelog_content = (FIXTURES / "changelog.rst").read_text("utf-8")
        changelog = parse_changelog(changelog_content, format="rst")

        records = [
            _make_version_record("2.5.0"),
            _make_version_record("2.6.0"),
            _make_version_record("2.7.0"),
            _make_version_record("0.1"),
        ]
        inventory = correlate_releases(
            records, mappings, releases_json=releases, changelog=changelog
        )
        assert inventory.stats.total_versions == 4
        assert inventory.stats.resolved_versions == 3
        assert inventory.stats.unresolved_versions == 1
        assert inventory.stats.total_tags == 4
        assert inventory.stats.total_releases == 4
        assert inventory.stats.total_changelog_entries > 0

    def test_empty_inputs(self) -> None:
        inventory = correlate_releases([], ())
        assert inventory.stats.total_versions == 0
        assert inventory.stats.resolved_versions == 0
        assert len(inventory.correlations) == 0

    def test_deterministic_output(self) -> None:
        tags = json.loads((FIXTURES / "github_tags.json").read_text("utf-8"))
        mappings = map_tags_to_versions(tags, "urllib3/urllib3")
        records = [
            _make_version_record("2.5.0"),
            _make_version_record("2.7.0"),
        ]
        inv1 = correlate_releases(records, mappings)
        inv2 = correlate_releases(records, mappings)
        assert inv1 == inv2
