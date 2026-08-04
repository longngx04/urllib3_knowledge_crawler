"""Normalize GitHub commit payloads into provenance-backed patch records."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from crawler.extractors.patch_diff import (
    PatchDiffExtractionError,
    extract_patch_diff_from_commit,
)
from crawler.models import Confidence, PackageRecord, PatchRecord, ProvenanceRecord
from crawler.utils.hashing import stable_record_id
from crawler.utils.http import RetrievedResponse

_COMMIT_SHA_LENGTHS = {40, 64}


class PatchNormalizationError(ValueError):
    """Raised when commit data cannot be normalized into a patch record."""


@dataclass(frozen=True, slots=True)
class UnresolvedPatchRef:
    """One patch reference that could not be normalized."""

    commit_sha: str
    reason: str
    advisory_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PatchInventory:
    """Normalized patch records plus unresolved references."""

    package: PackageRecord
    records: tuple[PatchRecord, ...]
    unresolved_refs: tuple[UnresolvedPatchRef, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)


def _normalize_commit_sha(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise PatchNormalizationError(f"commit payload missing '{field}'")
    normalized = value.strip().lower()
    if len(normalized) not in _COMMIT_SHA_LENGTHS:
        raise PatchNormalizationError(f"invalid commit SHA for '{field}': {value!r}")
    if not all(character in "0123456789abcdef" for character in normalized):
        raise PatchNormalizationError(f"invalid commit SHA for '{field}': {value!r}")
    return normalized


def verify_repository_owner(
    owner: str,
    repo: str,
    *,
    expected_owner: str = "urllib3",
    expected_repo: str = "urllib3",
) -> None:
    """Ensure a commit belongs to the configured official repository."""
    if owner != expected_owner or repo != expected_repo:
        raise PatchNormalizationError(
            f"commit repository {owner}/{repo} does not match "
            f"configured {expected_owner}/{expected_repo}"
        )


def _resolve_fixed_versions(
    commit_sha: str,
    advisory_fixed_versions: Sequence[str],
    commit_tag_map: Mapping[str, str] | None,
) -> list[str]:
    """Return fixed versions backed by tag or advisory evidence only."""
    fixed: set[str] = set()
    if commit_tag_map is not None:
        tagged_version = commit_tag_map.get(commit_sha)
        if tagged_version:
            fixed.add(tagged_version)
    for version in advisory_fixed_versions:
        if isinstance(version, str) and version.strip():
            fixed.add(version.strip())
    return sorted(fixed, key=str)


def normalize_github_commit(
    payload: dict[str, Any],
    *,
    provenance: ProvenanceRecord,
    advisory_ids: Sequence[str],
    package: PackageRecord,
    owner: str,
    repo: str,
    expected_owner: str = "urllib3",
    expected_repo: str = "urllib3",
    advisory_fixed_versions: Sequence[str] = (),
    commit_tag_map: Mapping[str, str] | None = None,
) -> PatchRecord:
    """Normalize one GitHub commit JSON payload into a ``PatchRecord``."""
    verify_repository_owner(
        owner,
        repo,
        expected_owner=expected_owner,
        expected_repo=expected_repo,
    )

    cleaned_advisory_ids = sorted(
        {
            item.strip()
            for item in advisory_ids
            if isinstance(item, str) and item.strip()
        }
    )
    if not cleaned_advisory_ids:
        raise PatchNormalizationError("at least one advisory ID is required")

    commit_sha = _normalize_commit_sha(payload.get("sha"), "sha")
    parent_sha: str | None = None
    parents = payload.get("parents")
    if isinstance(parents, list) and parents:
        first_parent = parents[0]
        if isinstance(first_parent, dict) and "sha" in first_parent:
            parent_sha = _normalize_commit_sha(first_parent["sha"], "parent.sha")

    html_url = payload.get("html_url")
    repository_url = (
        html_url.rsplit("/commit/", 1)[0]
        if isinstance(html_url, str) and "/commit/" in html_url
        else f"https://github.com/{owner}/{repo}"
    )

    try:
        diff_evidence = extract_patch_diff_from_commit(payload)
    except PatchDiffExtractionError as error:
        raise PatchNormalizationError(str(error)) from error

    fixed_versions = _resolve_fixed_versions(
        commit_sha,
        advisory_fixed_versions,
        commit_tag_map,
    )

    record_id = stable_record_id(
        "patch",
        {
            "commit_sha": commit_sha,
            "package": package.name,
            "ecosystem": package.ecosystem,
        },
    )

    confidence = Confidence(
        score=0.95,
        rationale=["official repository commit with extracted diff evidence"],
    )

    return PatchRecord(
        schema_version="1.0",
        record_id=record_id,
        record_type="patch",
        package=package,
        provenance=[provenance],
        advisory_ids=cleaned_advisory_ids,
        commit_sha=commit_sha,
        parent_sha=parent_sha,
        repository_url=repository_url,
        changed_files=list(diff_evidence.changed_files),
        changed_symbols=list(diff_evidence.changed_symbols),
        added_guards=list(diff_evidence.added_guards),
        behavioral_differences=[],
        regression_tests=list(diff_evidence.regression_tests),
        fixed_versions=fixed_versions,
        confidence=confidence,
    )


def normalize_github_commit_response(
    response: RetrievedResponse,
    *,
    advisory_ids: Sequence[str],
    package: PackageRecord,
    owner: str,
    repo: str,
    expected_owner: str = "urllib3",
    expected_repo: str = "urllib3",
    advisory_fixed_versions: Sequence[str] = (),
    commit_tag_map: Mapping[str, str] | None = None,
    source_type: str = "github_commit",
) -> PatchRecord:
    """Parse a retrieved GitHub commit response and normalize it."""
    try:
        payload = json.loads(response.content)
    except json.JSONDecodeError as error:
        raise PatchNormalizationError("commit response is not valid JSON") from error
    if not isinstance(payload, dict):
        raise PatchNormalizationError("commit response must be a JSON object")

    provenance = ProvenanceRecord(
        source_type=source_type,
        source_id=f"{owner}/{repo}@{payload.get('sha', 'unknown')}",
        retrieved_at=response.retrieved_at,
        raw_sha256=response.body_sha256,
        extractor_version="0.1.0",
    )
    return normalize_github_commit(
        payload,
        provenance=provenance,
        advisory_ids=advisory_ids,
        package=package,
        owner=owner,
        repo=repo,
        expected_owner=expected_owner,
        expected_repo=expected_repo,
        advisory_fixed_versions=advisory_fixed_versions,
        commit_tag_map=commit_tag_map,
    )


def build_patch_inventory(
    *,
    package: PackageRecord,
    records: Sequence[PatchRecord],
    unresolved_refs: Sequence[UnresolvedPatchRef] = (),
) -> PatchInventory:
    """Return a deterministic patch inventory ordered by commit SHA."""
    sorted_records = tuple(
        sorted(records, key=lambda item: (item.commit_sha, item.record_id))
    )
    sorted_unresolved = tuple(
        sorted(
            unresolved_refs,
            key=lambda item: (item.commit_sha, item.reason, item.advisory_ids),
        )
    )
    seen_ids: set[str] = set()
    for record in sorted_records:
        if record.record_id in seen_ids:
            raise PatchNormalizationError(
                f"duplicate patch record_id: {record.record_id}"
            )
        seen_ids.add(record.record_id)
    return PatchInventory(
        package=package,
        records=sorted_records,
        unresolved_refs=sorted_unresolved,
    )


__all__ = [
    "PatchInventory",
    "PatchNormalizationError",
    "UnresolvedPatchRef",
    "build_patch_inventory",
    "normalize_github_commit",
    "normalize_github_commit_response",
    "verify_repository_owner",
]
