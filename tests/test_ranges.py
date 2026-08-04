"""Offline tests for Phase 6 version-range resolution."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from packaging.version import Version

from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    PackageRecord,
    ProvenanceRecord,
    SourcePriority,
    VersionEvent,
    VersionRange,
    VersionRecord,
)
from crawler.normalizers.versions import VersionInventory
from crawler.resolvers.ranges import (
    RangeIssueKind,
    resolve_advisory_ranges,
    resolve_version_range,
    version_matches_events,
    version_matches_specifier,
)


@pytest.fixture
def package() -> PackageRecord:
    return PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


@pytest.fixture
def provenance() -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id="GHSA-test",
        retrieved_at=datetime(2024, 1, 1, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


def _inventory(package: PackageRecord, versions: list[str]) -> VersionInventory:
    records: list[VersionRecord] = []
    for index, value in enumerate(versions):
        parsed = Version(value)
        digest = f"{index:064x}"
        records.append(
            VersionRecord(
                schema_version="1.0",
                record_id=f"version:{digest}",
                record_type="version",
                package=package,
                provenance=[
                    ProvenanceRecord(
                        source_type="pypi",
                        source_id=value,
                        retrieved_at=datetime(2024, 1, 1, tzinfo=UTC),
                        raw_sha256="b" * 64,
                        extractor_version="0.1.0",
                    )
                ],
                raw_version=value,
                normalized_version=str(parsed),
                is_prerelease=parsed.is_prerelease,
                is_yanked=False,
            )
        )
    records.sort(key=lambda item: Version(item.normalized_version))
    return VersionInventory(
        package=package,
        records=tuple(records),
        unparsable_versions=(),
    )


def _advisory(
    package: PackageRecord,
    provenance: ProvenanceRecord,
    *,
    ranges: list[VersionRange] | None = None,
    affected: list[str] | None = None,
    fixed: list[str] | None = None,
    canonical: str = "GHSA-test-0000-0000",
) -> AdvisoryRecord:
    return AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "1" * 64,
        record_type="advisory",
        package=package,
        provenance=[provenance],
        identifiers=AdvisoryIdentifiers(canonical=canonical),
        affected_ranges=ranges or [],
        affected_versions=affected or [],
        fixed_versions=fixed or [],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["fixture"]),
    )


def test_specifier_range_inclusion_and_exclusion() -> None:
    assert version_matches_specifier(Version("2.6.0"), ">=2.6.0,<2.7.0")
    assert version_matches_specifier(Version("2.6.3"), ">=2.6.0,<2.7.0")
    assert not version_matches_specifier(Version("2.7.0"), ">=2.6.0,<2.7.0")
    assert Version("2.0.0a1") < Version("2.0.0")


def test_events_open_ended_lower_bound() -> None:
    events = [
        VersionEvent(introduced="0"),
        VersionEvent(fixed="1.26.5"),
    ]
    assert version_matches_events(Version("1.26.4"), events)
    assert not version_matches_events(Version("1.26.5"), events)


def test_events_missing_upper_bound() -> None:
    events = [VersionEvent(introduced="2.0.0")]
    assert version_matches_events(Version("2.0.0"), events)
    assert version_matches_events(Version("99.0.0"), events)
    assert not version_matches_events(Version("1.26.0"), events)


def test_events_last_affected_and_limit() -> None:
    last_affected = [
        VersionEvent(introduced="1.0.0"),
        VersionEvent(last_affected="1.0.2"),
    ]
    assert version_matches_events(Version("1.0.2"), last_affected)
    assert not version_matches_events(Version("1.0.3"), last_affected)

    limited = [
        VersionEvent(introduced="1.0.0"),
        VersionEvent(limit="2.0.0"),
    ]
    assert version_matches_events(Version("1.9.0"), limited)
    assert not version_matches_events(Version("2.0.0"), limited)


def test_prerelease_ordering_against_introduced() -> None:
    events = [VersionEvent(introduced="2.0.0"), VersionEvent(fixed="2.0.7")]
    assert not version_matches_events(Version("2.0.0a1"), events)
    assert version_matches_events(Version("2.0.0"), events)
    assert not version_matches_events(Version("2.0.7"), events)


def test_resolve_version_range_with_yanked_inventory(
    package: PackageRecord,
) -> None:
    inventory = _inventory(package, ["1.26.4", "1.26.5", "2.0.0"])
    # Mark yanked by rebuilding one record.
    yanked = inventory.records[0].model_copy(update={"is_yanked": True})
    inventory = VersionInventory(
        package=package,
        records=(yanked, *inventory.records[1:]),
        unparsable_versions=(),
    )
    version_range = VersionRange(
        raw="ECOSYSTEM",
        events=[VersionEvent(introduced="0"), VersionEvent(fixed="1.26.5")],
    )
    resolved, error = resolve_version_range(
        version_range,
        tuple(Version(item.normalized_version) for item in inventory.records),
    )
    assert error is None
    assert resolved == ["1.26.4"]


def test_resolve_invalid_range_and_specifier() -> None:
    versions = (Version("1.0.0"), Version("2.0.0"))
    invalid_events, error = resolve_version_range(
        VersionRange(events=[VersionEvent(introduced="not-a-version")]),
        versions,
    )
    assert invalid_events == []
    assert error is not None
    assert "invalid introduced" in error

    invalid_spec, spec_error = resolve_version_range(
        VersionRange(raw=">=2.0.0<<<"),
        versions,
    )
    assert invalid_spec == []
    assert spec_error is not None


def test_multiple_disjoint_ranges(
    package: PackageRecord, provenance: ProvenanceRecord
) -> None:
    inventory = _inventory(
        package,
        ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "2.2.0", "3.0.0"],
    )
    advisory = _advisory(
        package,
        provenance,
        ranges=[
            VersionRange(
                raw="ECOSYSTEM",
                events=[
                    VersionEvent(introduced="1.0.0"),
                    VersionEvent(fixed="1.2.0"),
                ],
                fixed_versions=["1.2.0"],
            ),
            VersionRange(
                raw="ECOSYSTEM",
                events=[
                    VersionEvent(introduced="2.0.0"),
                    VersionEvent(fixed="2.2.0"),
                ],
                fixed_versions=["2.2.0"],
            ),
        ],
        fixed=["1.2.0", "2.2.0"],
    )
    result = resolve_advisory_ranges([advisory], inventory)
    assert result.stats.resolvable_advisories == 1
    assert result.advisories[0].affected_versions == [
        "1.0.0",
        "1.1.0",
        "2.0.0",
        "2.1.0",
    ]
    assert result.advisories[0].affected_ranges[0].resolved == ["1.0.0", "1.1.0"]
    assert result.advisories[0].affected_ranges[1].resolved == ["2.0.0", "2.1.0"]
    assert result.advisories[0].affected_ranges[0].raw == "ECOSYSTEM"


def test_preserves_raw_and_merges_explicit_versions(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    inventory = _inventory(package, ["1.0.0", "1.1.0", "1.2.0"])
    advisory = _advisory(
        package,
        provenance,
        ranges=[
            VersionRange(
                raw=">=1.0.0,<1.2.0",
                events=[],
            )
        ],
        affected=["1.1.0"],
    )
    result = resolve_advisory_ranges([advisory], inventory)
    resolved = result.advisories[0]
    assert resolved.affected_ranges[0].raw == ">=1.0.0,<1.2.0"
    assert resolved.affected_versions == ["1.0.0", "1.1.0"]


def test_missing_fixed_version_and_contradiction(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    inventory = _inventory(package, ["1.0.0", "1.1.0"])
    advisory = _advisory(
        package,
        provenance,
        ranges=[
            VersionRange(
                raw="ECOSYSTEM",
                events=[
                    VersionEvent(introduced="0"),
                    VersionEvent(last_affected="1.1.0"),
                ],
                fixed_versions=["1.1.0"],
            )
        ],
        fixed=["9.9.9", "1.1.0"],
    )
    result = resolve_advisory_ranges([advisory], inventory)
    kinds = {issue.kind for issue in result.issues}
    assert RangeIssueKind.MISSING_FIXED_VERSION in kinds
    assert RangeIssueKind.CONTRADICTORY_RANGES in kinds
    assert result.stats.missing_fixed_versions >= 1
    assert result.stats.contradictory_ranges >= 1


def test_unresolvable_advisory_and_coverage_metrics(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    inventory = _inventory(package, ["1.0.0"])
    bad = _advisory(
        package,
        provenance,
        ranges=[VersionRange(events=[VersionEvent(fixed="nope")])],
        canonical="GHSA-bad",
    )
    good = _advisory(
        package,
        provenance,
        ranges=[
            VersionRange(
                events=[VersionEvent(introduced="0"), VersionEvent(fixed="1.0.1")],
                fixed_versions=["1.0.1"],
            )
        ],
        canonical="GHSA-good",
        fixed=["1.0.1"],
    )
    result = resolve_advisory_ranges([bad, good], inventory)
    assert result.stats.total_advisories == 2
    assert result.stats.resolvable_advisories == 1
    assert result.stats.unresolvable_advisories == 1
    assert result.stats.coverage_ratio == 0.5
    assert any(issue.kind is RangeIssueKind.UNRESOLVABLE for issue in result.issues)


def test_resolution_is_deterministic(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    inventory = _inventory(package, ["2.0.0", "2.0.1", "2.1.0"])
    advisory = _advisory(
        package,
        provenance,
        ranges=[
            VersionRange(
                raw="ECOSYSTEM",
                events=[
                    VersionEvent(introduced="2.0.0"),
                    VersionEvent(fixed="2.1.0"),
                ],
            )
        ],
    )
    first = resolve_advisory_ranges([advisory], inventory)
    second = resolve_advisory_ranges([advisory], inventory)
    assert (
        first.advisories[0].affected_versions == second.advisories[0].affected_versions
    )
    assert first.stats == second.stats
    assert first.issues == second.issues
