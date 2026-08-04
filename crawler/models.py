"""Strict Phase 1 data contracts for normalized urllib3 knowledge."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from packaging.version import InvalidVersion, Version
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CommitSha = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
RecordId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")]


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def _normalized_versions(values: list[str]) -> list[str]:
    parsed: set[Version] = set()
    for value in values:
        try:
            parsed.add(Version(value))
        except InvalidVersion as error:
            raise ValueError(f"invalid PEP 440 version: {value}") from error
    return [str(version) for version in sorted(parsed)]


class ContractModel(BaseModel):
    """Shared strict configuration for all wire-contract objects."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


class SourcePriority(StrEnum):
    """Trust tier assigned to a source-backed claim."""

    TIER_1_AUTHORITATIVE = "tier_1_authoritative"
    TIER_2_CONTEXTUAL = "tier_2_contextual"
    TIER_3_ENRICHMENT = "tier_3_enrichment"


class DetectionType(StrEnum):
    """Evidence required to decide whether a security pattern applies."""

    VERSION_ONLY = "version_only"
    VERSION_API = "version_api"
    VERSION_API_CONFIGURATION = "version_api_configuration"
    VERSION_API_DATAFLOW = "version_api_dataflow"
    VERSION_API_CONFIGURATION_DATAFLOW = "version_api_configuration_dataflow"
    SECURITY_ASSUMPTION_MISMATCH = "security_assumption_mismatch"


class KBDocumentType(StrEnum):
    """Retrieval-document family."""

    VERSION = "version"
    ADVISORY = "advisory"
    PATCH = "patch"
    SECURITY_PATTERN = "security_pattern"


class PackageRecord(ContractModel):
    """Package identity embedded in normalized records."""

    name: NonEmptyStr
    ecosystem: NonEmptyStr
    purl: NonEmptyStr


class ProvenanceRecord(ContractModel):
    """Trace from a normalized claim to one preserved raw source."""

    source_type: NonEmptyStr
    source_id: NonEmptyStr
    retrieved_at: AwareDatetime
    raw_sha256: Sha256Hex
    extractor_version: NonEmptyStr


class Confidence(ContractModel):
    """Bounded confidence with explicit supporting rationale."""

    score: Annotated[float, Field(ge=0.0, le=1.0)]
    rationale: list[NonEmptyStr] = Field(default_factory=list)

    _sort_rationale = field_validator("rationale")(_sorted_unique)


class VersionEvent(ContractModel):
    """One ordered boundary event from an upstream version range."""

    introduced: NonEmptyStr | None = None
    fixed: NonEmptyStr | None = None
    last_affected: NonEmptyStr | None = None
    limit: NonEmptyStr | None = None

    @model_validator(mode="after")
    def exactly_one_boundary(self) -> VersionEvent:
        boundaries = (
            self.introduced,
            self.fixed,
            self.last_affected,
            self.limit,
        )
        if sum(value is not None for value in boundaries) != 1:
            raise ValueError("a version event must define exactly one boundary")
        return self


class VersionRange(ContractModel):
    """Auditable source range plus optional resolver output."""

    raw: NonEmptyStr | None = None
    events: list[VersionEvent] = Field(default_factory=list)
    resolved: list[NonEmptyStr] = Field(default_factory=list)
    fixed_versions: list[NonEmptyStr] = Field(default_factory=list)

    _sort_resolved = field_validator("resolved")(_normalized_versions)
    _sort_fixed = field_validator("fixed_versions")(_normalized_versions)


class AdvisoryIdentifiers(ContractModel):
    """Canonical advisory identity and explicitly observed aliases."""

    canonical: NonEmptyStr
    aliases: list[NonEmptyStr] = Field(default_factory=list)
    cve: NonEmptyStr | None = None
    ghsa: NonEmptyStr | None = None
    osv: NonEmptyStr | None = None

    _sort_aliases = field_validator("aliases")(_sorted_unique)


class CVSSRecord(ContractModel):
    """CVSS data as reported by a source; absent values remain null."""

    version: NonEmptyStr | None = None
    score: Annotated[float, Field(ge=0.0, le=10.0)] | None = None
    vector: NonEmptyStr | None = None


class DistributionArtifact(ContractModel):
    """Published distribution metadata for a package version."""

    filename: NonEmptyStr
    url: NonEmptyStr | None = None
    size: Annotated[int, Field(ge=0)] | None = None
    sha256: Sha256Hex | None = None
    package_type: NonEmptyStr | None = None
    python_version: NonEmptyStr | None = None
    requires_python: NonEmptyStr | None = None
    upload_time: AwareDatetime | None = None
    is_yanked: bool = False
    yanked_reason: NonEmptyStr | None = None

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
            raise ValueError("artifact filename must be a safe basename")
        return value

    @model_validator(mode="after")
    def validate_yanked_reason(self) -> DistributionArtifact:
        if self.yanked_reason is not None and not self.is_yanked:
            raise ValueError("a yanked reason requires is_yanked=true")
        return self


class NormalizedRecord(ContractModel):
    """Fields required on every top-level normalized knowledge record."""

    schema_version: Literal["1.0"]
    record_id: RecordId
    package: PackageRecord
    provenance: list[ProvenanceRecord] = Field(min_length=1)

    @field_validator("provenance")
    @classmethod
    def sort_provenance(cls, values: list[ProvenanceRecord]) -> list[ProvenanceRecord]:
        return sorted(
            values,
            key=lambda item: (
                item.source_type,
                item.source_id,
                item.retrieved_at.isoformat(),
                item.raw_sha256,
                item.extractor_version,
            ),
        )


class VersionRecord(NormalizedRecord):
    """Normalized package release and repository-correlation metadata."""

    record_type: Literal["version"]
    raw_version: NonEmptyStr
    normalized_version: NonEmptyStr
    release_date: AwareDatetime | None = None
    is_prerelease: bool
    is_yanked: bool
    yanked_reason: NonEmptyStr | None = None
    requires_python: NonEmptyStr | None = None
    git_tag: NonEmptyStr | None = None
    commit_sha: CommitSha | None = None
    support_branch: NonEmptyStr | None = None
    support_status: NonEmptyStr | None = None
    artifacts: list[DistributionArtifact] = Field(default_factory=list)

    @field_validator("normalized_version")
    @classmethod
    def normalize_version(cls, value: str) -> str:
        try:
            return str(Version(value))
        except InvalidVersion as error:
            raise ValueError(f"invalid PEP 440 version: {value}") from error

    @field_validator("artifacts")
    @classmethod
    def sort_artifacts(
        cls, values: list[DistributionArtifact]
    ) -> list[DistributionArtifact]:
        return sorted(values, key=lambda item: item.filename)


class AdvisoryRecord(NormalizedRecord):
    """Normalized security advisory without inferred aliases or ranges."""

    record_type: Literal["advisory"]
    identifiers: AdvisoryIdentifiers
    summary: NonEmptyStr | None = None
    detailed_impact: NonEmptyStr | None = None
    cwe: list[NonEmptyStr] = Field(default_factory=list)
    severity: NonEmptyStr | None = None
    cvss: CVSSRecord | None = None
    affected_ranges: list[VersionRange] = Field(default_factory=list)
    affected_versions: list[NonEmptyStr] = Field(default_factory=list)
    fixed_versions: list[NonEmptyStr] = Field(default_factory=list)
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    workarounds: list[NonEmptyStr] = Field(default_factory=list)
    references: list[NonEmptyStr] = Field(default_factory=list)
    patch_commits: list[CommitSha] = Field(default_factory=list)
    source_priority: SourcePriority
    confidence: Confidence

    _sort_cwe = field_validator("cwe")(_sorted_unique)
    _sort_affected = field_validator("affected_versions")(_normalized_versions)
    _sort_fixed = field_validator("fixed_versions")(_normalized_versions)
    _sort_workarounds = field_validator("workarounds")(_sorted_unique)
    _sort_references = field_validator("references")(_sorted_unique)
    _sort_commits = field_validator("patch_commits")(_sorted_unique)


class PatchRecord(NormalizedRecord):
    """Normalized patch and regression-evidence correlation."""

    record_type: Literal["patch"]
    advisory_ids: list[NonEmptyStr] = Field(min_length=1)
    commit_sha: CommitSha
    parent_sha: CommitSha | None = None
    repository_url: NonEmptyStr | None = None
    changed_files: list[NonEmptyStr] = Field(default_factory=list)
    changed_symbols: list[NonEmptyStr] = Field(default_factory=list)
    added_guards: list[NonEmptyStr] = Field(default_factory=list)
    behavioral_differences: list[NonEmptyStr] = Field(default_factory=list)
    regression_tests: list[NonEmptyStr] = Field(default_factory=list)
    fixed_versions: list[NonEmptyStr] = Field(default_factory=list)
    confidence: Confidence

    _sort_advisories = field_validator("advisory_ids")(_sorted_unique)
    _sort_files = field_validator("changed_files")(_sorted_unique)
    _sort_symbols = field_validator("changed_symbols")(_sorted_unique)
    _sort_guards = field_validator("added_guards")(_sorted_unique)
    _sort_differences = field_validator("behavioral_differences")(_sorted_unique)
    _sort_tests = field_validator("regression_tests")(_sorted_unique)
    _sort_fixed = field_validator("fixed_versions")(_normalized_versions)


class VulnerableUsage(ContractModel):
    """Application conditions required for a vulnerability to apply."""

    modules: list[NonEmptyStr] = Field(default_factory=list)
    classes: list[NonEmptyStr] = Field(default_factory=list)
    symbols: list[NonEmptyStr] = Field(default_factory=list)
    arguments: list[NonEmptyStr] = Field(default_factory=list)
    api_sequence: list[NonEmptyStr] = Field(default_factory=list)
    preconditions: list[NonEmptyStr] = Field(default_factory=list)
    sources: list[NonEmptyStr] = Field(default_factory=list)
    sinks: list[NonEmptyStr] = Field(default_factory=list)
    required_dataflow: list[NonEmptyStr] = Field(default_factory=list)

    _sort_modules = field_validator("modules")(_sorted_unique)
    _sort_classes = field_validator("classes")(_sorted_unique)
    _sort_symbols = field_validator("symbols")(_sorted_unique)
    _sort_arguments = field_validator("arguments")(_sorted_unique)
    _sort_preconditions = field_validator("preconditions")(_sorted_unique)
    _sort_sources = field_validator("sources")(_sorted_unique)
    _sort_sinks = field_validator("sinks")(_sorted_unique)


class ImpactRecord(ContractModel):
    """Structured impact without fabricated conclusions."""

    confidentiality: NonEmptyStr | None = None
    integrity: NonEmptyStr | None = None
    availability: NonEmptyStr | None = None
    ssrf: bool | None = None
    rce: bool | None = None
    data_exposure: bool | None = None
    notes: list[NonEmptyStr] = Field(default_factory=list)

    _sort_notes = field_validator("notes")(_sorted_unique)


class RemediationRecord(ContractModel):
    """Observed remediation options and fixed releases."""

    fixed_versions: list[NonEmptyStr] = Field(default_factory=list)
    upgrade_guidance: NonEmptyStr | None = None
    workarounds: list[NonEmptyStr] = Field(default_factory=list)
    safe_alternatives: list[NonEmptyStr] = Field(default_factory=list)

    _sort_fixed = field_validator("fixed_versions")(_normalized_versions)
    _sort_workarounds = field_validator("workarounds")(_sorted_unique)
    _sort_alternatives = field_validator("safe_alternatives")(_sorted_unique)


class EvidenceRecord(ContractModel):
    """One patch or regression-test evidence pointer."""

    evidence_type: NonEmptyStr
    source_id: NonEmptyStr
    reference: NonEmptyStr | None = None
    notes: NonEmptyStr | None = None


class SecurityPatternRecord(NormalizedRecord):
    """Version- and usage-aware knowledge consumed by SAST analysis."""

    record_type: Literal["security_pattern"]
    identifiers: AdvisoryIdentifiers
    version: VersionRange
    cwe: list[NonEmptyStr] = Field(default_factory=list)
    severity: NonEmptyStr | None = None
    cvss: CVSSRecord | None = None
    detection_type: DetectionType
    vulnerable_usage: VulnerableUsage
    negative_conditions: list[NonEmptyStr] = Field(default_factory=list)
    impact: ImpactRecord
    remediation: RemediationRecord
    patch_evidence: list[EvidenceRecord] = Field(default_factory=list)
    test_evidence: list[EvidenceRecord] = Field(default_factory=list)
    confidence: Confidence

    _sort_cwe = field_validator("cwe")(_sorted_unique)
    _sort_negative = field_validator("negative_conditions")(_sorted_unique)

    @field_validator("patch_evidence", "test_evidence")
    @classmethod
    def sort_evidence(cls, values: list[EvidenceRecord]) -> list[EvidenceRecord]:
        return sorted(
            values,
            key=lambda item: (
                item.evidence_type,
                item.source_id,
                item.reference or "",
                item.notes or "",
            ),
        )


class KBDocumentMetadata(ContractModel):
    """Filters attached to a retrieval-oriented document."""

    package_name: NonEmptyStr
    advisory_ids: list[NonEmptyStr] = Field(default_factory=list)
    affected_versions: list[NonEmptyStr] = Field(default_factory=list)
    fixed_versions: list[NonEmptyStr] = Field(default_factory=list)
    symbols: list[NonEmptyStr] = Field(default_factory=list)
    detection_type: DetectionType | None = None
    confidence: Confidence | None = None

    _sort_advisories = field_validator("advisory_ids")(_sorted_unique)
    _sort_affected = field_validator("affected_versions")(_normalized_versions)
    _sort_fixed = field_validator("fixed_versions")(_normalized_versions)
    _sort_symbols = field_validator("symbols")(_sorted_unique)


class KBDocumentRecord(NormalizedRecord):
    """Retrieval-oriented document derived from normalized records."""

    record_type: Literal["kb_document"]
    document_type: KBDocumentType
    title: NonEmptyStr
    content: NonEmptyStr
    metadata: KBDocumentMetadata
    source_record_ids: list[RecordId] = Field(min_length=1)

    _sort_source_records = field_validator("source_record_ids")(_sorted_unique)


__all__ = [
    "AdvisoryIdentifiers",
    "AdvisoryRecord",
    "CVSSRecord",
    "Confidence",
    "DetectionType",
    "DistributionArtifact",
    "EvidenceRecord",
    "ImpactRecord",
    "KBDocumentMetadata",
    "KBDocumentRecord",
    "KBDocumentType",
    "PackageRecord",
    "PatchRecord",
    "ProvenanceRecord",
    "RemediationRecord",
    "SecurityPatternRecord",
    "SourcePriority",
    "VersionEvent",
    "VersionRange",
    "VersionRecord",
    "VulnerableUsage",
]
