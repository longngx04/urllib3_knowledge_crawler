"""Compute reproducible pipeline statistics and write manifest metadata."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crawler.extractors.semantics import compute_sast_usefulness_score
from crawler.models import (
    AdvisoryRecord,
    PatchRecord,
    SecurityPatternRecord,
    VersionRecord,
)
from crawler.resolvers.ranges import RangeResolutionIssue, RangeResolutionStats
from crawler.validators.findings import ValidationResult
from crawler.validators.pipeline import InventoryBundle


class StatsExportError(OSError):
    """Raised when stats or manifest output cannot be written safely."""


@dataclass(frozen=True, slots=True)
class PipelineStats:
    """Required Phase 10 quality metrics derived from inventory output."""

    total_versions: int
    total_prereleases: int
    total_yanked_versions: int
    total_advisories: int
    total_aliases: int
    total_patches: int
    total_security_patterns: int
    total_kb_documents: int
    version_coverage: float
    range_resolution_rate: float
    alias_resolution_rate: float
    patch_resolution_rate: float
    fixed_release_verification_rate: float
    provenance_coverage: float
    schema_validation_rate: float
    duplicate_rate: float
    average_sast_usefulness_score: float
    crawl_duration_seconds: float | None
    cache_hit_rate: float | None
    failed_request_count: int

    def to_json(self) -> dict[str, object]:
        return {
            "total_versions": self.total_versions,
            "total_prereleases": self.total_prereleases,
            "total_yanked_versions": self.total_yanked_versions,
            "total_advisories": self.total_advisories,
            "total_aliases": self.total_aliases,
            "total_patches": self.total_patches,
            "total_security_patterns": self.total_security_patterns,
            "total_kb_documents": self.total_kb_documents,
            "version_coverage": self.version_coverage,
            "range_resolution_rate": self.range_resolution_rate,
            "alias_resolution_rate": self.alias_resolution_rate,
            "patch_resolution_rate": self.patch_resolution_rate,
            "fixed_release_verification_rate": self.fixed_release_verification_rate,
            "provenance_coverage": self.provenance_coverage,
            "schema_validation_rate": self.schema_validation_rate,
            "duplicate_rate": self.duplicate_rate,
            "average_sast_usefulness_score": self.average_sast_usefulness_score,
            "crawl_duration_seconds": self.crawl_duration_seconds,
            "cache_hit_rate": self.cache_hit_rate,
            "failed_request_count": self.failed_request_count,
            "_notes": {
                "crawl_duration_seconds": (
                    "null when the stats pass is derived from exported files only"
                ),
                "cache_hit_rate": (
                    "null when retrieval cache metrics were not supplied "
                    "to the stats pass"
                ),
                "failed_request_count": (
                    "0 when retrieval failure metrics were not supplied "
                    "to the stats pass"
                ),
            },
        }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return round(numerator / denominator, 6)


def _count_aliases(advisories: Sequence[AdvisoryRecord]) -> int:
    aliases: set[str] = set()
    for advisory in advisories:
        aliases.update(advisory.identifiers.aliases)
        for typed_alias in (
            advisory.identifiers.cve,
            advisory.identifiers.ghsa,
            advisory.identifiers.osv,
        ):
            if typed_alias is not None:
                aliases.add(typed_alias)
    return len(aliases)


def _version_coverage(versions: Sequence[VersionRecord]) -> float:
    if not versions:
        return 1.0
    correlated = sum(
        1 for record in versions if record.git_tag is not None or record.commit_sha
    )
    return _ratio(correlated, len(versions))


def _range_resolution_rate(
    advisories: Sequence[AdvisoryRecord],
    range_issues: Sequence[RangeResolutionIssue],
    range_stats: RangeResolutionStats | None,
) -> float:
    if range_stats is not None:
        return round(range_stats.coverage_ratio, 6)
    if not advisories:
        return 1.0
    blocked = {issue.advisory_id for issue in range_issues}
    resolvable = len(advisories) - len(blocked)
    return _ratio(resolvable, len(advisories))


def _alias_resolution_rate(
    advisories: Sequence[AdvisoryRecord],
    validation: ValidationResult | None,
) -> float:
    if not advisories:
        return 1.0
    if validation is None:
        return 1.0
    alias_errors = {
        finding.record_id
        for finding in validation.findings
        if finding.check in {"alias", "duplicate"}
    }
    return _ratio(len(advisories) - len(alias_errors), len(advisories))


def _patch_resolution_rate(
    patches: Sequence[PatchRecord],
    inventory_versions: set[str],
) -> float:
    if not patches:
        return 1.0
    verified = 0
    for patch in patches:
        if not patch.fixed_versions:
            verified += 1
            continue
        if all(fixed in inventory_versions for fixed in patch.fixed_versions):
            verified += 1
    return _ratio(verified, len(patches))


def _fixed_release_verification_rate(
    *,
    advisories: Sequence[AdvisoryRecord],
    patches: Sequence[PatchRecord],
    inventory_versions: set[str],
) -> float:
    claims: list[bool] = []
    for advisory in advisories:
        for fixed in advisory.fixed_versions:
            claims.append(fixed in inventory_versions)
    for patch in patches:
        for fixed in patch.fixed_versions:
            claims.append(fixed in inventory_versions)
    if not claims:
        return 1.0
    return _ratio(sum(claims), len(claims))


def _provenance_coverage(
    total_records: int,
    validation: ValidationResult | None,
) -> float:
    if total_records == 0:
        return 1.0
    if validation is None:
        return 1.0
    missing = sum(1 for finding in validation.findings if finding.check == "provenance")
    return _ratio(total_records - missing, total_records)


def _schema_validation_rate(
    total_records: int, validation: ValidationResult | None
) -> float:
    if total_records == 0:
        return 1.0
    if validation is None:
        return 1.0
    schema_errors = {
        finding.record_id
        for finding in validation.findings
        if finding.check == "schema"
    }
    return _ratio(total_records - len(schema_errors), total_records)


def _duplicate_rate(total_records: int, validation: ValidationResult | None) -> float:
    if total_records == 0:
        return 0.0
    if validation is None:
        return 0.0
    duplicate_errors = sum(
        1 for finding in validation.findings if finding.check == "duplicate"
    )
    return round(duplicate_errors / total_records, 6)


def _average_sast_usefulness(patterns: Sequence[SecurityPatternRecord]) -> float:
    if not patterns:
        return 0.0
    scores = [
        compute_sast_usefulness_score(
            version=pattern.version,
            symbols=pattern.vulnerable_usage.symbols,
            preconditions=pattern.vulnerable_usage.preconditions,
            arguments=pattern.vulnerable_usage.arguments,
            negative_conditions=pattern.negative_conditions,
            remediation_upgrade=pattern.remediation.upgrade_guidance,
            remediation_workarounds=pattern.remediation.workarounds,
            patch_evidence=pattern.patch_evidence,
            test_evidence=pattern.test_evidence,
        )
        for pattern in patterns
    ]
    return round(sum(scores) / len(scores), 6)


def compute_pipeline_stats(
    bundle: InventoryBundle,
    *,
    validation: ValidationResult | None = None,
    range_stats: RangeResolutionStats | None = None,
    crawl_duration_seconds: float | None = None,
    cache_hit_rate: float | None = None,
    failed_request_count: int = 0,
) -> PipelineStats:
    """Compute required metrics from one inventory bundle and optional validation."""
    versions = bundle.versions
    advisories = bundle.advisories
    patches = bundle.patches
    patterns = bundle.security_patterns
    kb_documents = bundle.kb_documents
    inventory_versions = {record.normalized_version for record in versions}
    total_records = (
        len(versions)
        + len(advisories)
        + len(patches)
        + len(patterns)
        + len(kb_documents)
    )

    return PipelineStats(
        total_versions=len(versions),
        total_prereleases=sum(record.is_prerelease for record in versions),
        total_yanked_versions=sum(record.is_yanked for record in versions),
        total_advisories=len(advisories),
        total_aliases=_count_aliases(advisories),
        total_patches=len(patches),
        total_security_patterns=len(patterns),
        total_kb_documents=len(kb_documents),
        version_coverage=_version_coverage(versions),
        range_resolution_rate=_range_resolution_rate(
            advisories,
            bundle.range_issues,
            range_stats,
        ),
        alias_resolution_rate=_alias_resolution_rate(advisories, validation),
        patch_resolution_rate=_patch_resolution_rate(patches, inventory_versions),
        fixed_release_verification_rate=_fixed_release_verification_rate(
            advisories=advisories,
            patches=patches,
            inventory_versions=inventory_versions,
        ),
        provenance_coverage=_provenance_coverage(total_records, validation),
        schema_validation_rate=_schema_validation_rate(total_records, validation),
        duplicate_rate=_duplicate_rate(total_records, validation),
        average_sast_usefulness_score=_average_sast_usefulness(patterns),
        crawl_duration_seconds=crawl_duration_seconds,
        cache_hit_rate=cache_hit_rate,
        failed_request_count=failed_request_count,
    )


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    return encoded + b"\n"


def atomic_write_json(
    payload: Mapping[str, Any],
    output_directory: Path,
    filename: str,
    temporary_prefix: str,
) -> Path:
    """Atomically write one UTF-8 JSON document under ``output_directory``."""
    if output_directory.is_symlink():
        raise StatsExportError("output directory must not be a symlink")
    try:
        output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise StatsExportError("cannot create stats output directory") from error
    if not output_directory.is_dir():
        raise StatsExportError("stats output path must be a directory")

    output_path = output_directory / filename
    if output_path.is_symlink():
        raise StatsExportError(f"{filename} must not be a symlink")
    body = _canonical_json(payload)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output_directory,
            prefix=temporary_prefix,
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(body)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    except OSError as error:
        raise StatsExportError(f"cannot atomically write {filename}") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output_path


def export_stats(stats: PipelineStats, output_directory: Path) -> Path:
    """Write ``stats.json`` atomically."""
    return atomic_write_json(
        stats.to_json(),
        output_directory,
        "stats.json",
        temporary_prefix=".stats.",
    )


def export_manifest(
    files: Mapping[str, str],
    output_directory: Path,
) -> Path:
    """Write ``manifest.json`` listing exported files and their SHA-256 digests."""
    payload = {
        "files": [
            {"path": path, "sha256": digest}
            for path, digest in sorted(files.items(), key=lambda item: item[0])
        ]
    }
    return atomic_write_json(
        payload,
        output_directory,
        "manifest.json",
        temporary_prefix=".manifest.",
    )


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for one on-disk file."""
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "PipelineStats",
    "StatsExportError",
    "atomic_write_json",
    "compute_pipeline_stats",
    "export_manifest",
    "export_stats",
    "sha256_file",
]
