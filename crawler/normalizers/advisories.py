"""Normalize raw OSV vulnerability responses into typed AdvisoryRecords."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from packaging.version import InvalidVersion, Version

from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    CVSSRecord,
    PackageRecord,
    ProvenanceRecord,
    SourcePriority,
    VersionEvent,
    VersionRange,
)
from crawler.utils.hashing import stable_record_id

_COMMIT_HEX_PATTERN = re.compile(r"\b([0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE)
_COMMIT_URL_PATTERN = re.compile(
    r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{40}|[0-9a-f]{64})", re.IGNORECASE
)


class AdvisoryNormalizationError(ValueError):
    """Raised when raw vulnerability data cannot be safely normalized."""


@dataclass(frozen=True, slots=True)
class AdvisoryInventory:
    """Deterministic collection of normalized advisory records."""

    package: PackageRecord
    records: tuple[AdvisoryRecord, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)


def select_canonical_identifier(identifiers: Sequence[str]) -> str:
    """Select canonical advisory ID: GHSA > CVE > OSV/PYSEC > first available."""
    if not identifiers:
        raise AdvisoryNormalizationError(
            "cannot select canonical ID from empty identifiers"
        )

    clean_ids = [str(i).strip() for i in identifiers if str(i).strip()]
    if not clean_ids:
        raise AdvisoryNormalizationError(
            "cannot select canonical ID from whitespace identifiers"
        )

    # Priority 1: GHSA
    for item in clean_ids:
        if item.upper().startswith("GHSA-"):
            return item

    # Priority 2: CVE
    for item in clean_ids:
        if item.upper().startswith("CVE-"):
            return item

    # Priority 3: PYSEC or OSV
    for item in clean_ids:
        if item.upper().startswith("PYSEC-") or item.upper().startswith("OSV-"):
            return item

    return clean_ids[0]


def extract_commit_shas(references: Sequence[str]) -> list[str]:
    """Extract unique 40 or 64-char commit SHAs from reference URLs."""
    shas: set[str] = set()
    for ref in references:
        match = _COMMIT_URL_PATTERN.search(ref)
        if match:
            shas.add(match.group(1).lower())
    return sorted(shas)


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    cleaned = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            return None
        return dt
    except ValueError:
        return None


_COMMIT_SHA_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)


def _clean_pep440(version_str: str) -> str | None:
    if not isinstance(version_str, str) or not version_str.strip():
        return None
    try:
        return str(Version(version_str.strip()))
    except InvalidVersion:
        return None


def _boundary_for_event(raw_value: object) -> tuple[str | None, str | None]:
    """Return ``(pep440_or_zero, commit_sha)`` for one OSV range boundary."""

    if not isinstance(raw_value, str) or not raw_value.strip():
        return None, None
    cleaned = raw_value.strip()
    if cleaned == "0":
        return "0", None
    pep440 = _clean_pep440(cleaned)
    if pep440 is not None:
        return pep440, None
    if _COMMIT_SHA_PATTERN.fullmatch(cleaned):
        return None, cleaned.lower()
    return None, None


def normalize_osv_vulnerability(
    payload: dict[str, Any],
    *,
    provenance: ProvenanceRecord,
    package_name: str = "urllib3",
    ecosystem: str = "PyPI",
) -> AdvisoryRecord:
    """Normalize a single raw OSV vulnerability dictionary into an AdvisoryRecord."""
    vuln_id = payload.get("id")
    if not isinstance(vuln_id, str) or not vuln_id.strip():
        raise AdvisoryNormalizationError("OSV vulnerability payload missing 'id'")

    raw_aliases = payload.get("aliases", [])
    if not isinstance(raw_aliases, list):
        raw_aliases = []

    all_ids = set()
    all_ids.add(vuln_id.strip())
    for item in raw_aliases:
        if isinstance(item, str) and item.strip():
            all_ids.add(item.strip())

    sorted_all_ids = sorted(all_ids)
    canonical_id = select_canonical_identifier(sorted_all_ids)

    ghsa_id = next((i for i in sorted_all_ids if i.upper().startswith("GHSA-")), None)
    cve_id = next((i for i in sorted_all_ids if i.upper().startswith("CVE-")), None)
    osv_id = next(
        (
            i
            for i in sorted_all_ids
            if i.upper().startswith("OSV-")
            or i.upper().startswith("PYSEC-")
            or i == vuln_id
        ),
        None,
    )

    aliases = [i for i in sorted_all_ids if i != canonical_id]
    identifiers = AdvisoryIdentifiers(
        canonical=canonical_id,
        aliases=aliases,
        cve=cve_id,
        ghsa=ghsa_id,
        osv=osv_id,
    )

    raw_summary = payload.get("summary")
    summary = (
        raw_summary.strip()
        if isinstance(raw_summary, str) and raw_summary.strip()
        else None
    )

    details = payload.get("details")
    if isinstance(details, str) and details.strip():
        detailed_impact = details.strip()
    else:
        detailed_impact = None

    # CWE extraction
    cwes: set[str] = set()
    db_spec = payload.get("database_specific")
    if isinstance(db_spec, dict):
        cwe_list = db_spec.get("cwe_ids") or db_spec.get("cwe")
        if isinstance(cwe_list, list):
            for cwe_item in cwe_list:
                if isinstance(cwe_item, str) and cwe_item.strip():
                    val = cwe_item.strip()
                    if not val.upper().startswith("CWE-") and val.isdigit():
                        val = f"CWE-{val}"
                    cwes.add(val)

    # CVSS & Severity
    cvss_record: CVSSRecord | None = None
    severity_str: str | None = None
    if isinstance(db_spec, dict) and isinstance(db_spec.get("severity"), str):
        severity_str = db_spec["severity"].strip().upper()

    osv_severity = payload.get("severity")
    if isinstance(osv_severity, list):
        for sev in osv_severity:
            if isinstance(sev, dict):
                sev_type = str(sev.get("type", "")).upper()
                score_str = str(sev.get("score", "")).strip()
                if "CVSS" in sev_type and score_str:
                    ver = (
                        "3.1"
                        if "V3" in sev_type
                        else ("2.0" if "V2" in sev_type else "4.0")
                    )
                    cvss_record = CVSSRecord(version=ver, score=None, vector=score_str)
                    break

    # References & Commit SHAs
    references_list: list[str] = []
    raw_refs = payload.get("references")
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if (
                isinstance(ref, dict)
                and isinstance(ref.get("url"), str)
                and ref["url"].strip()
            ):
                references_list.append(ref["url"].strip())

    sorted_refs = sorted(set(references_list))
    patch_commit_set = set(extract_commit_shas(sorted_refs))

    # Affected ranges & versions
    affected_ranges: list[VersionRange] = []
    affected_versions_set: set[str] = set()
    fixed_versions_set: set[str] = set()

    raw_affected = payload.get("affected")
    if isinstance(raw_affected, list):
        for aff in raw_affected:
            if not isinstance(aff, dict):
                continue
            # Check package name match if present
            aff_pkg = aff.get("package")
            if isinstance(aff_pkg, dict):
                aff_name = aff_pkg.get("name")
                if (
                    isinstance(aff_name, str)
                    and aff_name.strip().lower() != package_name.lower()
                ):
                    continue

            # Extracted static versions
            v_list = aff.get("versions")
            if isinstance(v_list, list):
                for v in v_list:
                    clean_v = _clean_pep440(v)
                    if clean_v:
                        affected_versions_set.add(clean_v)

            # Extracted range events
            r_list = aff.get("ranges")
            if isinstance(r_list, list):
                for r_item in r_list:
                    if not isinstance(r_item, dict):
                        continue
                    r_type = str(r_item.get("type", "ECOSYSTEM")).upper()
                    events_raw = r_item.get("events")
                    if not isinstance(events_raw, list):
                        continue

                    events: list[VersionEvent] = []
                    range_fixed: set[str] = set()
                    for ev in events_raw:
                        if not isinstance(ev, dict):
                            continue
                        if "introduced" in ev:
                            intro_v, intro_commit = _boundary_for_event(
                                ev["introduced"]
                            )
                            if intro_v is not None:
                                events.append(VersionEvent(introduced=intro_v))
                            if intro_commit is not None:
                                patch_commit_set.add(intro_commit)
                        elif "fixed" in ev:
                            fix_v, fix_commit = _boundary_for_event(ev["fixed"])
                            if fix_v is not None:
                                events.append(VersionEvent(fixed=fix_v))
                                range_fixed.add(fix_v)
                                fixed_versions_set.add(fix_v)
                            if fix_commit is not None:
                                patch_commit_set.add(fix_commit)
                        elif "last_affected" in ev:
                            la_v, la_commit = _boundary_for_event(ev["last_affected"])
                            if la_v is not None:
                                events.append(VersionEvent(last_affected=la_v))
                            if la_commit is not None:
                                patch_commit_set.add(la_commit)
                        elif "limit" in ev:
                            lim_v, lim_commit = _boundary_for_event(ev["limit"])
                            if lim_v is not None:
                                events.append(VersionEvent(limit=lim_v))
                            if lim_commit is not None:
                                patch_commit_set.add(lim_commit)

                    if events:
                        affected_ranges.append(
                            VersionRange(
                                raw=r_type,
                                events=events,
                                fixed_versions=sorted(range_fixed),
                            )
                        )

    patch_commits = sorted(patch_commit_set)

    package = PackageRecord(
        name=package_name,
        ecosystem=ecosystem,
        purl=f"pkg:{ecosystem.lower()}/{package_name.lower()}",
    )

    rec_id = stable_record_id(
        "advisory",
        {
            "canonical_id": canonical_id,
            "package": package_name,
            "ecosystem": ecosystem,
        },
    )

    published_at = _parse_datetime(payload.get("published"))
    modified_at = _parse_datetime(payload.get("modified"))

    confidence = Confidence(
        score=1.0,
        rationale=["Authoritative OSV vulnerability metadata"],
    )

    return AdvisoryRecord(
        schema_version="1.0",
        record_id=rec_id,
        record_type="advisory",
        package=package,
        provenance=[provenance],
        identifiers=identifiers,
        summary=summary,
        detailed_impact=detailed_impact,
        cwe=sorted(cwes),
        severity=severity_str,
        cvss=cvss_record,
        affected_ranges=affected_ranges,
        affected_versions=sorted(affected_versions_set),
        fixed_versions=sorted(fixed_versions_set),
        published_at=published_at,
        modified_at=modified_at,
        workarounds=[],
        references=sorted_refs,
        patch_commits=patch_commits,
        source_priority=SourcePriority.TIER_1_AUTHORITATIVE,
        confidence=confidence,
    )


__all__ = [
    "AdvisoryInventory",
    "AdvisoryNormalizationError",
    "extract_commit_shas",
    "normalize_osv_vulnerability",
    "select_canonical_identifier",
]
