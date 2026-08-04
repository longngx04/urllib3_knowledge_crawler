"""Generate retrieval-oriented KB documents from security patterns."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from crawler.models import (
    AdvisoryRecord,
    KBDocumentMetadata,
    KBDocumentRecord,
    KBDocumentType,
    PackageRecord,
    PatchRecord,
    ProvenanceRecord,
    SecurityPatternRecord,
)
from crawler.utils.hashing import stable_record_id

MAX_CONTENT_BYTES = 32 * 1024


class KBDocumentTopic(StrEnum):
    """Retrieval topic encoded in title and record identity."""

    VULNERABILITY_OVERVIEW = "vulnerability_overview"
    DETECTION_GUIDANCE = "detection_guidance"
    NEGATIVE_CONDITIONS = "negative_conditions"
    REMEDIATION_GUIDANCE = "remediation_guidance"
    PATCH_EVIDENCE = "patch_evidence"


_TOPIC_DOCUMENT_TYPE: dict[KBDocumentTopic, KBDocumentType] = {
    KBDocumentTopic.VULNERABILITY_OVERVIEW: KBDocumentType.ADVISORY,
    KBDocumentTopic.DETECTION_GUIDANCE: KBDocumentType.SECURITY_PATTERN,
    KBDocumentTopic.NEGATIVE_CONDITIONS: KBDocumentType.SECURITY_PATTERN,
    KBDocumentTopic.REMEDIATION_GUIDANCE: KBDocumentType.SECURITY_PATTERN,
    KBDocumentTopic.PATCH_EVIDENCE: KBDocumentType.PATCH,
}

_TOPIC_SORT_ORDER: tuple[KBDocumentTopic, ...] = (
    KBDocumentTopic.VULNERABILITY_OVERVIEW,
    KBDocumentTopic.DETECTION_GUIDANCE,
    KBDocumentTopic.NEGATIVE_CONDITIONS,
    KBDocumentTopic.REMEDIATION_GUIDANCE,
    KBDocumentTopic.PATCH_EVIDENCE,
)


class KBDocumentNormalizationError(ValueError):
    """Raised when a KB document cannot be normalized safely."""


class KBDocumentContentTooLargeError(KBDocumentNormalizationError):
    """Raised when document content exceeds the configured byte limit."""


@dataclass(frozen=True, slots=True)
class KBDocumentInventory:
    """Deterministic collection of KB retrieval documents."""

    package: PackageRecord
    records: tuple[KBDocumentRecord, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)


@dataclass(frozen=True, slots=True)
class KBDocumentGenerationStats:
    """Counts produced while deduplicating KB document content."""

    documents_attempted: int
    documents_written: int
    duplicates_skipped: int

    @property
    def duplicate_rate(self) -> float:
        if self.documents_attempted == 0:
            return 0.0
        return self.duplicates_skipped / self.documents_attempted


@dataclass(frozen=True, slots=True)
class KBDocumentGenerationResult:
    """Inventory plus duplicate reporting from one generation pass."""

    inventory: KBDocumentInventory
    stats: KBDocumentGenerationStats


def _merge_provenance(
    pattern: SecurityPatternRecord,
    advisory: AdvisoryRecord | None,
    patch: PatchRecord | None,
) -> list[ProvenanceRecord]:
    merged: dict[tuple[str, str, str, str, str], ProvenanceRecord] = {}
    for source in (pattern, advisory, patch):
        if source is None:
            continue
        for item in source.provenance:
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


def _advisory_ids(pattern: SecurityPatternRecord) -> list[str]:
    identifiers = pattern.identifiers
    return sorted({identifiers.canonical, *identifiers.aliases})


def _metadata_from_pattern(pattern: SecurityPatternRecord) -> KBDocumentMetadata:
    fixed_versions = list(pattern.version.fixed_versions)
    if not fixed_versions:
        fixed_versions = list(pattern.remediation.fixed_versions)
    return KBDocumentMetadata(
        package_name=pattern.package.name,
        advisory_ids=_advisory_ids(pattern),
        affected_versions=list(pattern.version.resolved),
        fixed_versions=fixed_versions,
        symbols=list(pattern.vulnerable_usage.symbols),
        detection_type=pattern.detection_type,
        confidence=pattern.confidence,
    )


def _validate_content_size(content: str) -> str:
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_CONTENT_BYTES:
        raise KBDocumentContentTooLargeError(
            f"KB document content exceeds {MAX_CONTENT_BYTES} bytes "
            f"({len(encoded)} bytes)"
        )
    return content


def _format_list_section(title: str, items: Sequence[str]) -> str:
    if not items:
        return f"{title}\n\n(none documented in source evidence)"
    lines = [title, ""]
    lines.extend(f"- {item}" for item in items)
    return "\n".join(lines)


def _build_vulnerability_overview_content(
    pattern: SecurityPatternRecord,
    advisory: AdvisoryRecord | None,
) -> str:
    canonical = pattern.identifiers.canonical
    sections = [f"# Vulnerability overview: {canonical}", ""]
    if advisory is not None and advisory.summary:
        sections.extend(["## Summary", advisory.summary, ""])
    elif pattern.impact.notes:
        sections.extend(["## Summary", pattern.impact.notes[0], ""])
    if advisory is not None and advisory.detailed_impact:
        sections.extend(["## Impact", advisory.detailed_impact, ""])
    impact_lines: list[str] = []
    for label, value in (
        ("Confidentiality", pattern.impact.confidentiality),
        ("Integrity", pattern.impact.integrity),
        ("Availability", pattern.impact.availability),
    ):
        if value:
            impact_lines.append(f"- {label}: {value}")
    if pattern.impact.ssrf:
        impact_lines.append("- SSRF: reported")
    if pattern.impact.rce:
        impact_lines.append("- RCE: reported")
    if pattern.impact.data_exposure:
        impact_lines.append("- Data exposure: reported")
    if impact_lines:
        sections.extend(["## Structured impact", *impact_lines, ""])
    if pattern.cwe:
        sections.extend(["## CWE", ", ".join(pattern.cwe), ""])
    range_raw = pattern.version.raw
    if range_raw:
        sections.extend(["## Affected range (source)", range_raw, ""])
    if pattern.version.fixed_versions:
        fixed = ", ".join(pattern.version.fixed_versions)
        sections.extend(["## Fixed versions", fixed, ""])
    sections.append(
        "Evidence-backed overview derived from normalized advisory and pattern records."
    )
    return _validate_content_size("\n".join(sections).strip())


def _build_detection_guidance_content(pattern: SecurityPatternRecord) -> str:
    usage = pattern.vulnerable_usage
    sections = [
        f"# Detection guidance: {pattern.identifiers.canonical}",
        "",
        f"Detection type: {pattern.detection_type.value}",
        "",
    ]
    if usage.symbols:
        sections.append(_format_list_section("## Vulnerable symbols", usage.symbols))
        sections.append("")
    if usage.modules or usage.classes:
        modules = ", ".join(usage.modules) if usage.modules else "(none)"
        classes = ", ".join(usage.classes) if usage.classes else "(none)"
        sections.extend(
            [
                "## API surface",
                f"- Modules: {modules}",
                f"- Classes: {classes}",
                "",
            ]
        )
    if usage.arguments:
        sections.append(_format_list_section("## Dangerous arguments", usage.arguments))
        sections.append("")
    if usage.api_sequence:
        sections.append(
            _format_list_section("## Required API sequence", usage.api_sequence)
        )
        sections.append("")
    if usage.preconditions:
        sections.append(
            _format_list_section("## Required preconditions", usage.preconditions)
        )
        sections.append("")
    if usage.required_dataflow:
        sections.append(
            _format_list_section("## Required data-flow", usage.required_dataflow)
        )
        sections.append("")
    if usage.sources or usage.sinks:
        if usage.sources:
            sections.append(_format_list_section("## Data sources", usage.sources))
            sections.append("")
        if usage.sinks:
            sections.append(_format_list_section("## Data sinks", usage.sinks))
            sections.append("")
    sections.append(
        "Use version, symbol, and precondition filters together; do not flag on "
        "version exposure alone when detection type requires API usage."
    )
    return _validate_content_size("\n".join(sections).strip())


def _build_negative_conditions_content(pattern: SecurityPatternRecord) -> str:
    sections = [
        f"# Negative conditions: {pattern.identifiers.canonical}",
        "",
        _format_list_section(
            "## Safe or not-affected conditions",
            pattern.negative_conditions,
        ),
        "",
        "When a negative condition applies, downgrade or reject a vulnerable verdict "
        "even if the installed version is inside the affected range.",
    ]
    return _validate_content_size("\n".join(sections).strip())


def _build_remediation_guidance_content(pattern: SecurityPatternRecord) -> str:
    remediation = pattern.remediation
    sections = [f"# Remediation guidance: {pattern.identifiers.canonical}", ""]
    if remediation.fixed_versions:
        sections.extend(
            [
                "## Fixed versions",
                ", ".join(remediation.fixed_versions),
                "",
            ]
        )
    if remediation.upgrade_guidance:
        sections.extend(["## Upgrade guidance", remediation.upgrade_guidance, ""])
    if remediation.workarounds:
        sections.append(_format_list_section("## Workarounds", remediation.workarounds))
        sections.append("")
    if remediation.safe_alternatives:
        sections.append(
            _format_list_section("## Safe alternatives", remediation.safe_alternatives)
        )
        sections.append("")
    sections.append(
        "Prefer upgrading to a listed fixed release; workarounds are secondary and "
        "must be validated against project constraints."
    )
    return _validate_content_size("\n".join(sections).strip())


def _build_patch_evidence_content(
    pattern: SecurityPatternRecord,
    patch: PatchRecord | None,
) -> str:
    canonical = pattern.identifiers.canonical
    sections = [f"# Patch evidence: {canonical}", ""]
    if patch is not None:
        sections.extend(
            [
                "## Commit",
                f"- SHA: {patch.commit_sha}",
                f"- Repository: {patch.repository_url or '(not recorded)'}",
                "",
            ]
        )
        if patch.changed_files:
            sections.append(
                _format_list_section("## Changed files", patch.changed_files)
            )
            sections.append("")
        if patch.changed_symbols:
            sections.append(
                _format_list_section("## Changed symbols", patch.changed_symbols)
            )
            sections.append("")
        if patch.added_guards:
            sections.append(_format_list_section("## Added guards", patch.added_guards))
            sections.append("")
        if patch.behavioral_differences:
            sections.append(
                _format_list_section(
                    "## Behavioral differences", patch.behavioral_differences
                )
            )
            sections.append("")
        if patch.regression_tests:
            sections.append(
                _format_list_section("## Regression tests", patch.regression_tests)
            )
            sections.append("")
    if pattern.patch_evidence:
        lines = ["## Linked patch evidence"]
        for item in pattern.patch_evidence:
            ref = item.reference or "(no reference)"
            lines.append(f"- {item.evidence_type}: {item.source_id} ({ref})")
        sections.extend(["\n".join(lines), ""])
    if pattern.test_evidence:
        lines = ["## Linked test evidence"]
        for item in pattern.test_evidence:
            ref = item.reference or "(no reference)"
            lines.append(f"- {item.evidence_type}: {item.source_id} ({ref})")
        sections.extend(["\n".join(lines), ""])
    if len(sections) <= 2:
        raise KBDocumentNormalizationError(
            f"patch evidence document for {canonical} requires patch or evidence links"
        )
    sections.append("Patch and test pointers support implementation-level SAST checks.")
    return _validate_content_size("\n".join(sections).strip())


def _source_record_ids_for_topic(
    topic: KBDocumentTopic,
    pattern: SecurityPatternRecord,
    advisory: AdvisoryRecord | None,
    patch: PatchRecord | None,
) -> list[str]:
    ids = [pattern.record_id]
    if topic is KBDocumentTopic.VULNERABILITY_OVERVIEW and advisory is not None:
        ids.append(advisory.record_id)
    if topic is KBDocumentTopic.PATCH_EVIDENCE and patch is not None:
        ids.append(patch.record_id)
    return sorted(set(ids))


def _title_for_topic(topic: KBDocumentTopic, canonical: str) -> str:
    labels = {
        KBDocumentTopic.VULNERABILITY_OVERVIEW: "Vulnerability overview",
        KBDocumentTopic.DETECTION_GUIDANCE: "Detection guidance",
        KBDocumentTopic.NEGATIVE_CONDITIONS: "Negative conditions",
        KBDocumentTopic.REMEDIATION_GUIDANCE: "Remediation guidance",
        KBDocumentTopic.PATCH_EVIDENCE: "Patch evidence",
    }
    return f"{labels[topic]}: {canonical}"


def _content_for_topic(
    topic: KBDocumentTopic,
    pattern: SecurityPatternRecord,
    advisory: AdvisoryRecord | None,
    patch: PatchRecord | None,
) -> str:
    builders = {
        KBDocumentTopic.VULNERABILITY_OVERVIEW: (
            lambda: _build_vulnerability_overview_content(pattern, advisory)
        ),
        KBDocumentTopic.DETECTION_GUIDANCE: (
            lambda: _build_detection_guidance_content(pattern)
        ),
        KBDocumentTopic.NEGATIVE_CONDITIONS: (
            lambda: _build_negative_conditions_content(pattern)
        ),
        KBDocumentTopic.REMEDIATION_GUIDANCE: (
            lambda: _build_remediation_guidance_content(pattern)
        ),
        KBDocumentTopic.PATCH_EVIDENCE: (
            lambda: _build_patch_evidence_content(pattern, patch)
        ),
    }
    return builders[topic]()


def generate_kb_documents_for_pattern(
    pattern: SecurityPatternRecord,
    *,
    advisory: AdvisoryRecord | None = None,
    patch: PatchRecord | None = None,
    topics: Sequence[KBDocumentTopic] | None = None,
) -> tuple[KBDocumentRecord, ...]:
    """Build one retrieval document per topic for a security pattern."""
    selected_topics = tuple(topics) if topics is not None else _TOPIC_SORT_ORDER
    provenance = _merge_provenance(pattern, advisory, patch)
    if not provenance:
        raise KBDocumentNormalizationError(
            f"KB documents for {pattern.identifiers.canonical} require provenance"
        )
    metadata = _metadata_from_pattern(pattern)
    canonical = pattern.identifiers.canonical
    documents: list[KBDocumentRecord] = []
    for topic in selected_topics:
        try:
            content = _content_for_topic(topic, pattern, advisory, patch)
        except KBDocumentNormalizationError:
            if topic is KBDocumentTopic.PATCH_EVIDENCE:
                continue
            raise
        record_id = stable_record_id(
            "kb_document",
            {
                "source_record_id": pattern.record_id,
                "topic": topic.value,
            },
        )
        documents.append(
            KBDocumentRecord(
                schema_version="1.0",
                record_type="kb_document",
                record_id=record_id,
                package=pattern.package,
                provenance=provenance,
                document_type=_TOPIC_DOCUMENT_TYPE[topic],
                title=_title_for_topic(topic, canonical),
                content=content,
                metadata=metadata,
                source_record_ids=_source_record_ids_for_topic(
                    topic, pattern, advisory, patch
                ),
            )
        )
    return tuple(documents)


def build_kb_document_inventory(
    *,
    package: PackageRecord,
    records: Sequence[KBDocumentRecord],
    deduplicate_content: bool = True,
) -> KBDocumentGenerationResult:
    """Return a deterministic KB inventory with optional content deduplication."""
    sorted_input = sorted(
        records,
        key=lambda item: (
            item.metadata.advisory_ids[0] if item.metadata.advisory_ids else "",
            item.title,
            item.record_id,
        ),
    )
    seen_ids: set[str] = set()
    seen_content: set[str] = set()
    kept: list[KBDocumentRecord] = []
    attempted = len(sorted_input)
    duplicates_skipped = 0
    for record in sorted_input:
        if record.record_id in seen_ids:
            raise KBDocumentNormalizationError(
                f"duplicate KB document record_id: {record.record_id}"
            )
        seen_ids.add(record.record_id)
        if deduplicate_content and record.content in seen_content:
            duplicates_skipped += 1
            continue
        seen_content.add(record.content)
        kept.append(record)
    inventory = KBDocumentInventory(package=package, records=tuple(kept))
    stats = KBDocumentGenerationStats(
        documents_attempted=attempted,
        documents_written=inventory.record_count,
        duplicates_skipped=duplicates_skipped,
    )
    return KBDocumentGenerationResult(inventory=inventory, stats=stats)


def generate_kb_documents_from_patterns(
    *,
    package: PackageRecord,
    patterns: Sequence[SecurityPatternRecord],
    advisories: Sequence[AdvisoryRecord] | None = None,
    patches: Sequence[PatchRecord] | None = None,
) -> KBDocumentGenerationResult:
    """Generate and inventory KB documents for many security patterns."""
    advisory_by_canonical = {
        item.identifiers.canonical: item for item in (advisories or ())
    }
    patch_by_advisory: dict[str, PatchRecord] = {}
    for item in patches or ():
        for advisory_id in item.advisory_ids:
            patch_by_advisory.setdefault(advisory_id, item)
    all_records: list[KBDocumentRecord] = []
    for pattern in sorted(
        patterns,
        key=lambda item: (item.identifiers.canonical, item.record_id),
    ):
        canonical = pattern.identifiers.canonical
        docs = generate_kb_documents_for_pattern(
            pattern,
            advisory=advisory_by_canonical.get(canonical),
            patch=patch_by_advisory.get(canonical),
        )
        all_records.extend(docs)
    return build_kb_document_inventory(package=package, records=all_records)


__all__ = [
    "KBDocumentContentTooLargeError",
    "KBDocumentGenerationResult",
    "KBDocumentGenerationStats",
    "KBDocumentInventory",
    "KBDocumentNormalizationError",
    "KBDocumentTopic",
    "MAX_CONTENT_BYTES",
    "build_kb_document_inventory",
    "generate_kb_documents_for_pattern",
    "generate_kb_documents_from_patterns",
]
