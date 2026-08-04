"""Unit tests for the alias resolver module."""

from datetime import UTC, datetime

import pytest

from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    PackageRecord,
    ProvenanceRecord,
    SourcePriority,
)
from crawler.resolvers.aliases import AliasResolver


@pytest.fixture
def base_package() -> PackageRecord:
    return PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


@pytest.fixture
def prov1() -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id="GHSA-565x-2c8m-578w",
        retrieved_at=datetime(2023, 10, 18, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


@pytest.fixture
def prov2() -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id="CVE-2023-45803",
        retrieved_at=datetime(2023, 10, 18, 13, 0, tzinfo=UTC),
        raw_sha256="b" * 64,
        extractor_version="0.1.0",
    )


def test_alias_resolver_single_advisory(base_package, prov1):
    adv = AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "1" * 64,
        record_type="advisory",
        package=base_package,
        provenance=[prov1],
        identifiers=AdvisoryIdentifiers(
            canonical="GHSA-565x-2c8m-578w",
            aliases=["CVE-2023-45803"],
            cve="CVE-2023-45803",
            ghsa="GHSA-565x-2c8m-578w",
        ),
        summary="GHSA summary",
        cwe=["CWE-200"],
        affected_versions=["2.0.0"],
        fixed_versions=["2.0.7"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["Source: OSV"]),
    )

    resolver = AliasResolver()
    merged, conflicts = resolver.resolve_advisories([adv])
    assert len(merged) == 1
    assert len(conflicts) == 0
    assert merged[0].identifiers.canonical == "GHSA-565x-2c8m-578w"


def test_alias_resolver_merges_linked_cluster(base_package, prov1, prov2):
    adv1 = AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "1" * 64,
        record_type="advisory",
        package=base_package,
        provenance=[prov1],
        identifiers=AdvisoryIdentifiers(
            canonical="GHSA-565x-2c8m-578w",
            aliases=["CVE-2023-45803"],
            cve="CVE-2023-45803",
            ghsa="GHSA-565x-2c8m-578w",
        ),
        summary="Short GHSA summary",
        detailed_impact="Detailed description from GHSA advisory",
        cwe=["CWE-200"],
        affected_versions=["2.0.0", "2.0.1"],
        fixed_versions=["2.0.7"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["Source 1"]),
    )

    adv2 = AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "2" * 64,
        record_type="advisory",
        package=base_package,
        provenance=[prov2],
        identifiers=AdvisoryIdentifiers(
            canonical="CVE-2023-45803",
            aliases=["PYSEC-2023-999"],
            cve="CVE-2023-45803",
            osv="PYSEC-2023-999",
        ),
        summary="CVE summary",
        detailed_impact="Less detailed description",
        cwe=["CWE-200"],
        affected_versions=["2.0.2"],
        fixed_versions=["2.0.7"],
        references=["https://github.com/advisories/GHSA-565x-2c8m-578w"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["Source 2"]),
    )

    resolver = AliasResolver()
    merged, conflicts = resolver.resolve_advisories([adv1, adv2])

    assert len(merged) == 1
    m = merged[0]
    assert m.identifiers.canonical == "GHSA-565x-2c8m-578w"
    assert "CVE-2023-45803" in m.identifiers.aliases
    assert "PYSEC-2023-999" in m.identifiers.aliases
    assert m.identifiers.cve == "CVE-2023-45803"
    assert m.identifiers.ghsa == "GHSA-565x-2c8m-578w"
    assert m.identifiers.osv == "PYSEC-2023-999"

    assert sorted(m.affected_versions) == ["2.0.0", "2.0.1", "2.0.2"]
    assert len(m.provenance) == 2
    assert len(m.references) == 2


def test_alias_resolver_reports_source_conflict_for_multiple_ghsa_ids(
    base_package, prov1, prov2
):
    """Explicit source-conflict coverage for Phase 12 reproducibility contract."""
    adv1 = AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "1" * 64,
        record_type="advisory",
        package=base_package,
        provenance=[prov1],
        identifiers=AdvisoryIdentifiers(
            canonical="GHSA-aaaa-1111-2222",
            aliases=["CVE-2023-99999"],
            cve="CVE-2023-99999",
            ghsa="GHSA-aaaa-1111-2222",
        ),
        summary="First GHSA summary",
        cwe=["CWE-200"],
        affected_versions=["1.0.0"],
        fixed_versions=["1.0.1"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["Source 1"]),
    )
    adv2 = AdvisoryRecord(
        schema_version="1.0",
        record_id="advisory:" + "2" * 64,
        record_type="advisory",
        package=base_package,
        provenance=[prov2],
        identifiers=AdvisoryIdentifiers(
            canonical="GHSA-bbbb-3333-4444",
            aliases=["CVE-2023-99999"],
            cve="CVE-2023-99999",
            ghsa="GHSA-bbbb-3333-4444",
        ),
        summary="Second GHSA summary",
        cwe=["CWE-200"],
        affected_versions=["1.1.0"],
        fixed_versions=["1.1.1"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["Source 2"]),
    )

    resolver = AliasResolver()
    merged, conflicts = resolver.resolve_advisories([adv1, adv2])

    assert len(merged) == 1
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.canonical_id == "GHSA-aaaa-1111-2222"
    assert conflict.conflicting_ids == ["GHSA-aaaa-1111-2222", "GHSA-bbbb-3333-4444"]
    assert "multiple distinct GHSA" in conflict.reason
