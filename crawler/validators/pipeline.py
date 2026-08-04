"""Validate a normalized inventory bundle and surface actionable findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from crawler.models import (
    AdvisoryRecord,
    KBDocumentRecord,
    PackageRecord,
    PatchRecord,
    SecurityPatternRecord,
    VersionRecord,
)
from crawler.resolvers.ranges import RangeResolutionIssue
from crawler.validators.duplicates import (
    detect_duplicate_advisories,
    detect_duplicate_record_ids,
)
from crawler.validators.findings import (
    PipelineValidationError,
    ValidationFinding,
    ValidationResult,
)
from crawler.validators.schema import validate_record_schema
from crawler.validators.versions import (
    VersionInventoryValidationError,
    validate_version_inventory,
)


@dataclass(frozen=True, slots=True)
class InventoryBundle:
    """Normalized records present in one export bundle."""

    package: PackageRecord
    versions: tuple[VersionRecord, ...] = ()
    advisories: tuple[AdvisoryRecord, ...] = ()
    patches: tuple[PatchRecord, ...] = ()
    security_patterns: tuple[SecurityPatternRecord, ...] = ()
    kb_documents: tuple[KBDocumentRecord, ...] = ()
    range_issues: tuple[RangeResolutionIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class ValidationOptions:
    """Operator controls for inventory validation."""

    strict: bool = False
    include_range_issues: bool = True
    include_patch_release_checks: bool = True


def _serialize_record(record: BaseModel) -> dict[str, object]:
    return record.model_dump(mode="json")


def _advisory_record_id_for_canonical(
    advisories: Sequence[AdvisoryRecord], advisory_id: str
) -> str:
    for advisory in advisories:
        if advisory.identifiers.canonical == advisory_id:
            return advisory.record_id
    return f"advisory:{advisory_id}"


def _validate_provenance(payload: Mapping[str, Any]) -> list[ValidationFinding]:
    record_id = str(payload.get("record_id", "unknown"))
    provenance = payload.get("provenance")
    if not isinstance(provenance, list) or not provenance:
        return [
            ValidationFinding(
                record_id=record_id,
                check="provenance",
                reason="normalized record must include at least one provenance entry",
            )
        ]
    return []


def _validate_references(payload: Mapping[str, Any]) -> list[ValidationFinding]:
    record_id = str(payload.get("record_id", "unknown"))
    findings: list[ValidationFinding] = []
    for field in ("references",):
        values = payload.get(field)
        if not isinstance(values, list):
            continue
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value.startswith(
                ("http://", "https://")
            ):
                findings.append(
                    ValidationFinding(
                        record_id=record_id,
                        check="reference",
                        reason=(
                            f"reference[{index}] is not a syntactically valid URL: "
                            f"{value!r}"
                        ),
                    )
                )
    repository_url = payload.get("repository_url")
    if isinstance(repository_url, str) and not repository_url.startswith(
        ("http://", "https://")
    ):
        findings.append(
            ValidationFinding(
                record_id=record_id,
                check="reference",
                reason=(
                    "repository_url is not a syntactically valid URL: "
                    f"{repository_url!r}"
                ),
            )
        )
    return findings


def _inventory_version_set(versions: Sequence[VersionRecord]) -> set[str]:
    return {record.normalized_version for record in versions}


def _validate_patch_release_consistency(
    *,
    versions: Sequence[VersionRecord],
    advisories: Sequence[AdvisoryRecord],
    patches: Sequence[PatchRecord],
) -> list[ValidationFinding]:
    """Soft checks: claimed fixed versions should exist in the version inventory."""
    inventory = _inventory_version_set(versions)
    if not inventory:
        return []

    findings: list[ValidationFinding] = []
    for advisory in advisories:
        for fixed in advisory.fixed_versions:
            if fixed not in inventory:
                findings.append(
                    ValidationFinding(
                        record_id=advisory.record_id,
                        check="patch_release",
                        reason=(
                            "claimed fixed version is absent from version inventory: "
                            f"{fixed}"
                        ),
                    )
                )
    for patch in patches:
        for fixed in patch.fixed_versions:
            if fixed not in inventory:
                findings.append(
                    ValidationFinding(
                        record_id=patch.record_id,
                        check="patch_release",
                        reason=(
                            "patch fixed version is absent from version inventory: "
                            f"{fixed}"
                        ),
                    )
                )
    return findings


def _range_issue_findings(
    *,
    advisories: Sequence[AdvisoryRecord],
    range_issues: Sequence[RangeResolutionIssue],
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for issue in range_issues:
        record_id = _advisory_record_id_for_canonical(advisories, issue.advisory_id)
        suffix = (
            f" (range_index={issue.range_index})"
            if issue.range_index is not None
            else ""
        )
        findings.append(
            ValidationFinding(
                record_id=record_id,
                check="range",
                reason=f"{issue.kind.value}: {issue.message}{suffix}",
            )
        )
    return findings


def validate_inventory_bundle(
    bundle: InventoryBundle,
    *,
    options: ValidationOptions | None = None,
) -> ValidationResult:
    """Run schema, inventory, alias, duplicate, provenance, and consistency checks."""
    config = options or ValidationOptions()
    findings: list[ValidationFinding] = []

    all_records: list[BaseModel] = [
        *bundle.versions,
        *bundle.advisories,
        *bundle.patches,
        *bundle.security_patterns,
        *bundle.kb_documents,
    ]
    serialized = [_serialize_record(record) for record in all_records]

    for payload in serialized:
        findings.extend(validate_record_schema(payload))
        findings.extend(_validate_provenance(payload))
        findings.extend(_validate_references(payload))

    if bundle.versions:
        try:
            validate_version_inventory(bundle.versions, bundle.package)
        except VersionInventoryValidationError as error:
            findings.append(
                ValidationFinding(
                    record_id="inventory:versions",
                    check="version",
                    reason=str(error),
                )
            )

    findings.extend(detect_duplicate_advisories(bundle.advisories))
    record_ids = [str(payload["record_id"]) for payload in serialized]
    findings.extend(detect_duplicate_record_ids(record_ids))

    if config.include_range_issues and bundle.range_issues:
        findings.extend(
            _range_issue_findings(
                advisories=bundle.advisories,
                range_issues=bundle.range_issues,
            )
        )

    if config.include_patch_release_checks:
        findings.extend(
            _validate_patch_release_consistency(
                versions=bundle.versions,
                advisories=bundle.advisories,
                patches=bundle.patches,
            )
        )

    result = ValidationResult(findings=tuple(findings))
    if config.strict and not result.passed:
        raise PipelineValidationError(result.findings)
    return result


def export_validation_errors(
    findings: Sequence[ValidationFinding],
    output_directory: Path,
) -> Path:
    """Write machine-readable validation findings to ``validation_errors.json``."""
    from crawler.exporters.stats import atomic_write_json as _atomic_write_json

    payload = [
        {
            "record_id": finding.record_id,
            "check": finding.check,
            "reason": finding.reason,
        }
        for finding in findings
    ]
    return _atomic_write_json(
        {"findings": payload, "error_count": len(payload)},
        output_directory,
        "validation_errors.json",
        temporary_prefix=".validation_errors.",
    )


__all__ = [
    "InventoryBundle",
    "PipelineValidationError",
    "ValidationOptions",
    "ValidationResult",
    "export_validation_errors",
    "validate_inventory_bundle",
]
