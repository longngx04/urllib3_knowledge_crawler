"""Resolve, merge, and cluster advisory aliases into unified AdvisoryRecords."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from crawler.models import (
    AdvisoryIdentifiers,
    AdvisoryRecord,
    Confidence,
    ProvenanceRecord,
    VersionRange,
)
from crawler.normalizers.advisories import select_canonical_identifier
from crawler.utils.hashing import stable_record_id


@dataclass(frozen=True, slots=True)
class AliasConflict:
    """Report an ambiguous or conflicting alias merging state."""

    canonical_id: str
    conflicting_ids: list[str]
    reason: str


class AliasResolver:
    """Merge explicitly linked advisory alias clusters and detect source conflicts."""

    def resolve_advisories(
        self, advisories: Sequence[AdvisoryRecord]
    ) -> tuple[list[AdvisoryRecord], list[AliasConflict]]:
        """Group linked advisories into clusters and merge them deterministically."""
        if not advisories:
            return [], []

        # 1. Build adjacency list of linked advisory indexes
        n = len(advisories)
        id_to_indices: dict[str, set[int]] = {}

        for idx, adv in enumerate(advisories):
            all_ids = set()
            all_ids.add(adv.identifiers.canonical)
            all_ids.update(adv.identifiers.aliases)
            if adv.identifiers.cve:
                all_ids.add(adv.identifiers.cve)
            if adv.identifiers.ghsa:
                all_ids.add(adv.identifiers.ghsa)
            if adv.identifiers.osv:
                all_ids.add(adv.identifiers.osv)

            for item_id in all_ids:
                if item_id:
                    id_to_indices.setdefault(item_id, set()).add(idx)

        # 2. Find connected components of advisories
        visited = [False] * n
        clusters: list[list[int]] = []

        for i in range(n):
            if visited[i]:
                continue
            component: list[int] = []
            queue = [i]
            visited[i] = True

            while queue:
                curr = queue.pop()
                component.append(curr)
                adv = advisories[curr]
                curr_ids = {adv.identifiers.canonical, *adv.identifiers.aliases}

                for item_id in curr_ids:
                    for neighbor in id_to_indices.get(item_id, set()):
                        if not visited[neighbor]:
                            visited[neighbor] = True
                            queue.append(neighbor)

            clusters.append(sorted(component))

        # 3. Merge each cluster
        merged_advisories: list[AdvisoryRecord] = []
        conflicts: list[AliasConflict] = []

        for cluster in clusters:
            if len(cluster) == 1:
                merged_advisories.append(advisories[cluster[0]])
                continue

            cluster_advisories = [advisories[idx] for idx in cluster]
            merged, conflict = self._merge_cluster(cluster_advisories)
            merged_advisories.append(merged)
            if conflict:
                conflicts.append(conflict)

        # Sort merged advisories by canonical ID for determinism
        merged_advisories.sort(key=lambda a: a.identifiers.canonical)
        return merged_advisories, conflicts

    def _merge_cluster(
        self, cluster: list[AdvisoryRecord]
    ) -> tuple[AdvisoryRecord, AliasConflict | None]:
        """Merge multiple AdvisoryRecords belonging to the same alias cluster."""
        all_ids: set[str] = set()
        all_provenance: dict[tuple[str, str], ProvenanceRecord] = {}
        all_cwes: set[str] = set()
        all_affected_versions: set[str] = set()
        all_fixed_versions: set[str] = set()
        all_workarounds: set[str] = set()
        all_references: set[str] = set()
        all_patch_commits: set[str] = set()
        all_ranges: list[VersionRange] = []

        summary_candidates: list[str] = []
        details_candidates: list[str] = []
        published_dates: list[datetime] = []
        modified_dates: list[datetime] = []

        first_pkg = cluster[0].package
        first_priority = cluster[0].source_priority

        cvss_choice = None
        severity_choice = None

        for adv in cluster:
            all_ids.add(adv.identifiers.canonical)
            all_ids.update(adv.identifiers.aliases)
            if adv.identifiers.cve:
                all_ids.add(adv.identifiers.cve)
            if adv.identifiers.ghsa:
                all_ids.add(adv.identifiers.ghsa)
            if adv.identifiers.osv:
                all_ids.add(adv.identifiers.osv)

            for prov in adv.provenance:
                key = (prov.source_type, prov.source_id)
                if key not in all_provenance:
                    all_provenance[key] = prov

            all_cwes.update(adv.cwe)
            all_affected_versions.update(adv.affected_versions)
            all_fixed_versions.update(adv.fixed_versions)
            all_workarounds.update(adv.workarounds)
            all_references.update(adv.references)
            all_patch_commits.update(adv.patch_commits)

            for r in adv.affected_ranges:
                if r not in all_ranges:
                    all_ranges.append(r)

            if adv.summary:
                summary_candidates.append(adv.summary)
            if adv.detailed_impact:
                details_candidates.append(adv.detailed_impact)
            if adv.published_at:
                published_dates.append(adv.published_at)
            if adv.modified_at:
                modified_dates.append(adv.modified_at)

            if adv.cvss and cvss_choice is None:
                cvss_choice = adv.cvss
            if adv.severity and severity_choice is None:
                severity_choice = adv.severity

        canonical_id = select_canonical_identifier(sorted(all_ids))

        ghsa_id = next(
            (i for i in sorted(all_ids) if i.upper().startswith("GHSA-")), None
        )
        cve_id = next(
            (i for i in sorted(all_ids) if i.upper().startswith("CVE-")), None
        )
        osv_id = next(
            (
                i
                for i in sorted(all_ids)
                if i.upper().startswith("OSV-") or i.upper().startswith("PYSEC-")
            ),
            None,
        )

        aliases = sorted(all_ids - {canonical_id})
        identifiers = AdvisoryIdentifiers(
            canonical=canonical_id,
            aliases=aliases,
            cve=cve_id,
            ghsa=ghsa_id,
            osv=osv_id,
        )

        best_summary = summary_candidates[0] if summary_candidates else None
        best_details = max(details_candidates, key=len) if details_candidates else None
        published_at = min(published_dates) if published_dates else None
        modified_at = max(modified_dates) if modified_dates else None

        rec_id = stable_record_id(
            "advisory",
            {
                "canonical_id": canonical_id,
                "package": first_pkg.name,
                "ecosystem": first_pkg.ecosystem,
            },
        )

        conflict: AliasConflict | None = None
        # Detect clusters that merged multiple distinct GHSA advisories
        ghsas_in_cluster = [
            adv.identifiers.canonical
            for adv in cluster
            if adv.identifiers.canonical.startswith("GHSA-")
        ]
        if len(set(ghsas_in_cluster)) > 1:
            conflict = AliasConflict(
                canonical_id=canonical_id,
                conflicting_ids=sorted(set(ghsas_in_cluster)),
                reason=(
                    "multiple distinct GHSA canonical IDs merged into single cluster"
                ),
            )

        merged_record = AdvisoryRecord(
            schema_version="1.0",
            record_id=rec_id,
            record_type="advisory",
            package=first_pkg,
            provenance=list(all_provenance.values()),
            identifiers=identifiers,
            summary=best_summary,
            detailed_impact=best_details,
            cwe=sorted(all_cwes),
            severity=severity_choice,
            cvss=cvss_choice,
            affected_ranges=all_ranges,
            affected_versions=sorted(all_affected_versions),
            fixed_versions=sorted(all_fixed_versions),
            published_at=published_at,
            modified_at=modified_at,
            workarounds=sorted(all_workarounds),
            references=sorted(all_references),
            patch_commits=sorted(all_patch_commits),
            source_priority=first_priority,
            confidence=Confidence(
                score=1.0,
                rationale=[f"Merged {len(cluster)} alias-linked advisory records"],
            ),
        )

        return merged_record, conflict


__all__ = ["AliasConflict", "AliasResolver"]
