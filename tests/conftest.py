"""Shared Phase 1 model examples."""

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel

from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    DetectionType,
    EvidenceRecord,
    ImpactRecord,
    KBDocumentMetadata,
    KBDocumentRecord,
    KBDocumentType,
    PackageRecord,
    PatchRecord,
    ProvenanceRecord,
    RemediationRecord,
    SecurityPatternRecord,
    SourcePriority,
    VersionEvent,
    VersionRange,
    VersionRecord,
    VulnerableUsage,
)
from crawler.utils.hashing import stable_record_id


@pytest.fixture
def example_records() -> dict[str, BaseModel]:
    """Return one representative instance for every checked-in schema."""
    package = PackageRecord(
        name="urllib3",
        ecosystem="PyPI",
        purl="pkg:pypi/urllib3",
    )
    provenance = ProvenanceRecord(
        source_type="github_advisory",
        source_id="GHSA-example",
        retrieved_at=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )
    identifiers = AdvisoryIdentifiers(
        canonical="GHSA-example",
        aliases=["CVE-2099-0001", "GHSA-example"],
        cve="CVE-2099-0001",
        ghsa="GHSA-example",
        osv=None,
    )
    confidence = Confidence(
        score=0.9,
        rationale=["maintainer advisory", "patch reference"],
    )
    version_range = VersionRange(
        raw=">=2.0,<2.1.1",
        events=[VersionEvent(introduced="2.0"), VersionEvent(fixed="2.1.1")],
        resolved=["2.1.0", "2.0.0"],
        fixed_versions=["2.1.1"],
    )

    version = VersionRecord(
        schema_version="1.0",
        record_type="version",
        record_id=stable_record_id("version", {"version": "2.1.1"}),
        package=package,
        provenance=[provenance],
        raw_version="2.1.1",
        normalized_version="2.1.1",
        release_date=datetime(2026, 8, 1, 8, 30, tzinfo=UTC),
        is_prerelease=False,
        is_yanked=False,
        yanked_reason=None,
        requires_python=">=3.9",
        git_tag="2.1.1",
        commit_sha="b" * 40,
        support_branch=None,
        support_status=None,
        artifacts=[],
    )
    advisory = AdvisoryRecord(
        schema_version="1.0",
        record_type="advisory",
        record_id=stable_record_id("advisory", {"canonical": "GHSA-example"}),
        package=package,
        provenance=[provenance],
        identifiers=identifiers,
        summary="Synthetic contract example",
        detailed_impact=None,
        cwe=["CWE-918"],
        severity="high",
        cvss=None,
        affected_ranges=[version_range],
        affected_versions=["2.1.0", "2.0.0"],
        fixed_versions=["2.1.1"],
        published_at=datetime(2026, 8, 1, 9, 0, tzinfo=UTC),
        modified_at=None,
        workarounds=[],
        references=["https://example.invalid/GHSA-example"],
        patch_commits=["b" * 40],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=confidence,
    )
    patch = PatchRecord(
        schema_version="1.0",
        record_type="patch",
        record_id=stable_record_id("patch", {"commit_sha": "b" * 40}),
        package=package,
        provenance=[provenance],
        advisory_ids=["GHSA-example"],
        commit_sha="b" * 40,
        parent_sha="c" * 40,
        repository_url="https://github.com/urllib3/urllib3",
        changed_files=["src/urllib3/example.py"],
        changed_symbols=["Example.request"],
        added_guards=["reject unsafe input"],
        behavioral_differences=["unsafe input now raises ValueError"],
        regression_tests=["test_rejects_unsafe_input"],
        fixed_versions=["2.1.1"],
        confidence=confidence,
    )
    security_pattern = SecurityPatternRecord(
        schema_version="1.0",
        record_type="security_pattern",
        record_id=stable_record_id("security_pattern", {"canonical": "GHSA-example"}),
        package=package,
        provenance=[provenance],
        identifiers=identifiers,
        version=version_range,
        cwe=["CWE-918"],
        severity="high",
        cvss=None,
        detection_type=DetectionType.VERSION_API_DATAFLOW,
        vulnerable_usage=VulnerableUsage(
            modules=["urllib3"],
            classes=["PoolManager"],
            symbols=["PoolManager.request"],
            arguments=["redirect=True"],
            api_sequence=["PoolManager", "request"],
            preconditions=["untrusted URL reaches request"],
            sources=["user_input"],
            sinks=["PoolManager.request"],
            required_dataflow=["user_input", "url", "PoolManager.request"],
        ),
        negative_conditions=["redirects disabled"],
        impact=ImpactRecord(
            confidentiality="source-reported exposure",
            ssrf=True,
        ),
        remediation=RemediationRecord(
            fixed_versions=["2.1.1"],
            upgrade_guidance="Upgrade to a fixed release.",
        ),
        patch_evidence=[
            EvidenceRecord(
                evidence_type="commit",
                source_id="b" * 40,
                reference="https://github.com/urllib3/urllib3/commit/example",
            )
        ],
        test_evidence=[
            EvidenceRecord(
                evidence_type="test",
                source_id="test_rejects_unsafe_input",
            )
        ],
        confidence=confidence,
    )
    kb_document = KBDocumentRecord(
        schema_version="1.0",
        record_type="kb_document",
        record_id=stable_record_id(
            "kb_document", {"source_record_id": security_pattern.record_id}
        ),
        package=package,
        provenance=[provenance],
        document_type=KBDocumentType.SECURITY_PATTERN,
        title="Synthetic security pattern",
        content="A contract-only example with no real vulnerability claim.",
        metadata=KBDocumentMetadata(
            package_name="urllib3",
            advisory_ids=["GHSA-example"],
            affected_versions=["2.0", "2.1.0"],
            fixed_versions=["2.1.1"],
            symbols=["PoolManager.request"],
            detection_type=DetectionType.VERSION_API_DATAFLOW,
            confidence=confidence,
        ),
        source_record_ids=[security_pattern.record_id],
    )

    return {
        "advisory.schema.json": advisory,
        "kb_document.schema.json": kb_document,
        "patch.schema.json": patch,
        "provenance.schema.json": provenance,
        "security_pattern.schema.json": security_pattern,
        "version.schema.json": version,
    }
