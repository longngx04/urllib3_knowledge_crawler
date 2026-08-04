"""Normalize semantic extractions into provenance-backed security patterns."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from crawler.extractors.semantics import SemanticExtraction, extract_security_semantics
from crawler.models import (
    AdvisoryRecord,
    Confidence,
    ImpactRecord,
    PackageRecord,
    PatchRecord,
    ProvenanceRecord,
    RemediationRecord,
    SecurityPatternRecord,
    VulnerableUsage,
)
from crawler.utils.hashing import stable_record_id


class SecurityPatternNormalizationError(ValueError):
    """Raised when a security pattern cannot be normalized safely."""


@dataclass(frozen=True, slots=True)
class SecurityPatternInventory:
    """Deterministic collection of normalized security patterns."""

    package: PackageRecord
    records: tuple[SecurityPatternRecord, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)


def _merge_provenance(
    advisory: AdvisoryRecord,
    patch: PatchRecord | None,
) -> list[ProvenanceRecord]:
    merged: dict[tuple[str, str, str, str, str], ProvenanceRecord] = {}
    for item in advisory.provenance:
        key = (
            item.source_type,
            item.source_id,
            item.retrieved_at.isoformat(),
            item.raw_sha256,
            item.extractor_version,
        )
        merged[key] = item
    if patch is not None:
        for item in patch.provenance:
            key = (
                item.source_type,
                item.source_id,
                item.retrieved_at.isoformat(),
                item.raw_sha256,
                item.extractor_version,
            )
            merged[key] = item
    return sorted(
        merged.values(),
        key=lambda item: (
            item.source_type,
            item.source_id,
            item.retrieved_at.isoformat(),
            item.raw_sha256,
            item.extractor_version,
        ),
    )


def normalize_security_pattern(
    advisory: AdvisoryRecord,
    *,
    patch: PatchRecord | None = None,
    changelog_text: str | None = None,
    extractor_version: str = "0.1.0",
) -> SecurityPatternRecord:
    """Build one ``SecurityPatternRecord`` from advisory and optional patch evidence."""
    semantics = extract_security_semantics(
        advisory,
        patch=patch,
        changelog_text=changelog_text,
    )
    return _pattern_from_semantics(
        advisory,
        semantics,
        patch=patch,
        extractor_version=extractor_version,
    )


def _pattern_from_semantics(
    advisory: AdvisoryRecord,
    semantics: SemanticExtraction,
    *,
    patch: PatchRecord | None,
    extractor_version: str,
) -> SecurityPatternRecord:
    canonical = advisory.identifiers.canonical
    record_id = stable_record_id(
        "security_pattern",
        {
            "canonical": canonical,
            "package": advisory.package.name,
            "ecosystem": advisory.package.ecosystem,
        },
    )

    provenance = _merge_provenance(advisory, patch)
    if not provenance:
        raise SecurityPatternNormalizationError(
            f"security pattern for {canonical} requires provenance"
        )

    confidence = Confidence(
        score=semantics.confidence_score,
        rationale=[
            *semantics.confidence_rationale,
            f"sast_usefulness_score={semantics.sast_usefulness_score:.4f}",
        ],
    )

    fixed_versions = list(semantics.version.fixed_versions or advisory.fixed_versions)
    remediation = RemediationRecord(
        fixed_versions=fixed_versions,
        upgrade_guidance=semantics.remediation_upgrade,
        workarounds=list(semantics.remediation_workarounds),
        safe_alternatives=list(semantics.remediation_alternatives),
    )

    return SecurityPatternRecord(
        schema_version="1.0",
        record_type="security_pattern",
        record_id=record_id,
        package=advisory.package,
        provenance=provenance,
        identifiers=advisory.identifiers,
        version=semantics.version,
        cwe=list(advisory.cwe),
        severity=advisory.severity,
        cvss=advisory.cvss,
        detection_type=semantics.detection_type,
        vulnerable_usage=VulnerableUsage(
            modules=list(semantics.modules),
            classes=list(semantics.classes),
            symbols=list(semantics.symbols),
            arguments=list(semantics.arguments),
            api_sequence=list(semantics.api_sequence),
            preconditions=list(semantics.preconditions),
            sources=list(semantics.sources),
            sinks=list(semantics.sinks),
            required_dataflow=list(semantics.required_dataflow),
        ),
        negative_conditions=list(semantics.negative_conditions),
        impact=ImpactRecord(
            confidentiality=semantics.impact_confidentiality,
            integrity=semantics.impact_integrity,
            availability=semantics.impact_availability,
            ssrf=semantics.impact_ssrf,
            rce=semantics.impact_rce,
            data_exposure=semantics.impact_data_exposure,
            notes=list(semantics.impact_notes),
        ),
        remediation=remediation,
        patch_evidence=list(semantics.patch_evidence),
        test_evidence=list(semantics.test_evidence),
        confidence=confidence,
    )


def build_security_pattern_inventory(
    *,
    package: PackageRecord,
    records: Sequence[SecurityPatternRecord],
) -> SecurityPatternInventory:
    """Return a deterministic security-pattern inventory ordered by canonical ID."""
    sorted_records = tuple(
        sorted(
            records,
            key=lambda item: (
                item.identifiers.canonical,
                item.record_id,
            ),
        )
    )
    seen_ids: set[str] = set()
    for record in sorted_records:
        if record.record_id in seen_ids:
            raise SecurityPatternNormalizationError(
                f"duplicate security pattern record_id: {record.record_id}"
            )
        seen_ids.add(record.record_id)
    return SecurityPatternInventory(package=package, records=sorted_records)


__all__ = [
    "SecurityPatternInventory",
    "SecurityPatternNormalizationError",
    "build_security_pattern_inventory",
    "normalize_security_pattern",
]
