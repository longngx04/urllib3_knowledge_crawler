"""Offline tests for pipeline validation and reproducible statistics."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crawler.exporters.stats import (
    compute_pipeline_stats,
    export_manifest,
    export_stats,
    sha256_file,
)
from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    PackageRecord,
    ProvenanceRecord,
    SourcePriority,
    VersionRecord,
)
from crawler.resolvers.ranges import RangeIssueKind, RangeResolutionIssue
from crawler.utils.hashing import stable_record_id
from crawler.validators.findings import PipelineValidationError
from crawler.validators.pipeline import (
    InventoryBundle,
    ValidationOptions,
    export_validation_errors,
    validate_inventory_bundle,
)


@pytest.fixture
def package() -> PackageRecord:
    return PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


@pytest.fixture
def provenance() -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id="GHSA-example",
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


def _version(
    package: PackageRecord,
    provenance: ProvenanceRecord,
    normalized: str,
    *,
    git_tag: str | None = "2.1.1",
) -> VersionRecord:
    return VersionRecord(
        schema_version="1.0",
        record_type="version",
        record_id=stable_record_id("version", {"version": normalized}),
        package=package,
        provenance=[provenance],
        raw_version=normalized,
        normalized_version=normalized,
        release_date=None,
        is_prerelease=False,
        is_yanked=False,
        requires_python=None,
        git_tag=git_tag,
        commit_sha="b" * 40 if git_tag else None,
        artifacts=[],
    )


def _advisory(
    package: PackageRecord,
    provenance: ProvenanceRecord,
    *,
    canonical: str,
    record_suffix: str,
    fixed_versions: list[str] | None = None,
) -> AdvisoryRecord:
    return AdvisoryRecord(
        schema_version="1.0",
        record_type="advisory",
        record_id=f"advisory:{record_suffix}",
        package=package,
        provenance=[provenance],
        identifiers=AdvisoryIdentifiers(
            canonical=canonical,
            aliases=[canonical],
            ghsa=canonical if canonical.startswith("GHSA-") else None,
        ),
        summary="Example advisory",
        fixed_versions=fixed_versions or ["2.1.1"],
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=Confidence(score=1.0, rationale=["fixture"]),
    )


def test_validate_inventory_passes_for_coherent_bundle(
    example_records: dict[str, object],
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    bundle = InventoryBundle(
        package=package,
        versions=(
            _version(package, provenance, "2.0.0", git_tag="2.0.0"),
            _version(package, provenance, "2.1.1"),
        ),
        advisories=(example_records["advisory.schema.json"],),  # type: ignore[arg-type]
        patches=(example_records["patch.schema.json"],),  # type: ignore[arg-type]
        security_patterns=(
            example_records["security_pattern.schema.json"],  # type: ignore[arg-type]
        ),
        kb_documents=(example_records["kb_document.schema.json"],),  # type: ignore[arg-type]
    )

    result = validate_inventory_bundle(bundle)
    assert result.passed
    assert result.error_count == 0


def test_validate_inventory_reports_missing_provenance(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    version = VersionRecord.model_construct(
        schema_version="1.0",
        record_type="version",
        record_id=stable_record_id("version", {"version": "2.1.1"}),
        package=package,
        provenance=[],
        raw_version="2.1.1",
        normalized_version="2.1.1",
        release_date=None,
        is_prerelease=False,
        is_yanked=False,
        requires_python=None,
        git_tag="2.1.1",
        commit_sha="b" * 40,
        artifacts=[],
    )
    bundle = InventoryBundle(package=package, versions=(version,))
    result = validate_inventory_bundle(bundle)
    assert not result.passed
    assert any(finding.check == "provenance" for finding in result.findings)


def test_validate_inventory_detects_duplicate_canonical_advisories(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    bundle = InventoryBundle(
        package=package,
        advisories=(
            _advisory(
                package,
                provenance,
                canonical="GHSA-duplicate",
                record_suffix="1" * 64,
            ),
            _advisory(
                package,
                provenance,
                canonical="GHSA-duplicate",
                record_suffix="2" * 64,
            ),
        ),
    )
    result = validate_inventory_bundle(bundle)
    assert not result.passed
    duplicate_findings = [
        finding for finding in result.findings if finding.check == "duplicate"
    ]
    assert len(duplicate_findings) == 2


def test_validate_inventory_surfaces_range_issues_when_configured(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    advisory = _advisory(
        package,
        provenance,
        canonical="GHSA-range",
        record_suffix="3" * 64,
    )
    bundle = InventoryBundle(
        package=package,
        advisories=(advisory,),
        range_issues=(
            RangeResolutionIssue(
                advisory_id="GHSA-range",
                kind=RangeIssueKind.MISSING_FIXED_VERSION,
                message="fixed version not present in inventory: 9.9.9",
            ),
        ),
    )
    result = validate_inventory_bundle(bundle, options=ValidationOptions())
    range_findings = [
        finding for finding in result.findings if finding.check == "range"
    ]
    assert len(range_findings) == 1
    assert range_findings[0].record_id == advisory.record_id


def test_validate_inventory_strict_mode_raises(
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    bundle = InventoryBundle(
        package=package,
        advisories=(
            _advisory(
                package,
                provenance,
                canonical="GHSA-strict",
                record_suffix="4" * 64,
                fixed_versions=["99.0.0"],
            ),
        ),
        versions=(_version(package, provenance, "2.1.1"),),
    )
    with pytest.raises(PipelineValidationError) as error:
        validate_inventory_bundle(
            bundle,
            options=ValidationOptions(strict=True, include_patch_release_checks=True),
        )
    assert error.value.findings


def test_export_validation_errors_writes_machine_readable_json(
    tmp_path: Path,
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    bundle = InventoryBundle(
        package=package,
        versions=(_version(package, provenance, "2.1.1"),),
        advisories=(
            _advisory(
                package,
                provenance,
                canonical="GHSA-export",
                record_suffix="5" * 64,
                fixed_versions=["88.0.0"],
            ),
        ),
    )
    result = validate_inventory_bundle(bundle)
    output_path = export_validation_errors(result.findings, tmp_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["error_count"] >= 1
    assert payload["findings"][0]["record_id"]
    assert payload["findings"][0]["reason"]


def test_compute_and_export_stats_are_reproducible(
    tmp_path: Path,
    example_records: dict[str, object],
    package: PackageRecord,
    provenance: ProvenanceRecord,
) -> None:
    bundle = InventoryBundle(
        package=package,
        versions=(
            _version(package, provenance, "2.0.0", git_tag=None),
            _version(package, provenance, "2.1.1"),
        ),
        advisories=(example_records["advisory.schema.json"],),  # type: ignore[arg-type]
        patches=(example_records["patch.schema.json"],),  # type: ignore[arg-type]
        security_patterns=(
            example_records["security_pattern.schema.json"],  # type: ignore[arg-type]
        ),
        kb_documents=(example_records["kb_document.schema.json"],),  # type: ignore[arg-type]
    )
    validation = validate_inventory_bundle(bundle)
    stats = compute_pipeline_stats(bundle, validation=validation)
    assert stats.total_versions == 2
    assert stats.total_advisories == 1
    assert stats.provenance_coverage == 1.0
    assert stats.schema_validation_rate == 1.0
    assert stats.crawl_duration_seconds is None
    assert stats.cache_hit_rate is None
    assert stats.failed_request_count == 0
    assert 0.0 < stats.average_sast_usefulness_score <= 1.0

    first_stats_path = export_stats(stats, tmp_path / "first")
    second_stats_path = export_stats(stats, tmp_path / "second")
    assert first_stats_path.read_bytes() == second_stats_path.read_bytes()
    stats_payload = json.loads(first_stats_path.read_text(encoding="utf-8"))
    assert stats_payload["total_versions"] == 2

    manifest_path = export_manifest(
        {
            "normalized/versions.jsonl": sha256_file(first_stats_path),
            "stats.json": sha256_file(first_stats_path),
        },
        tmp_path / "manifest",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["files"]) == 2
    assert manifest["files"][0]["path"] < manifest["files"][1]["path"]
