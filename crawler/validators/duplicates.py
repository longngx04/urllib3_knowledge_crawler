"""Duplicate canonical advisory and record-id detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from crawler.models import AdvisoryRecord
from crawler.validators.findings import ValidationFinding


def detect_duplicate_advisories(
    advisories: Sequence[AdvisoryRecord],
) -> list[ValidationFinding]:
    """Report duplicate canonical advisory IDs and alias collisions."""
    findings: list[ValidationFinding] = []
    canonical_to_records: dict[str, list[str]] = defaultdict(list)
    alias_to_canonical: dict[str, set[str]] = defaultdict(set)

    for advisory in advisories:
        canonical = advisory.identifiers.canonical
        canonical_to_records[canonical].append(advisory.record_id)
        alias_to_canonical[canonical].add(canonical)
        for alias in advisory.identifiers.aliases:
            alias_to_canonical[alias].add(canonical)
        for typed_alias in (
            advisory.identifiers.cve,
            advisory.identifiers.ghsa,
            advisory.identifiers.osv,
        ):
            if typed_alias is not None:
                alias_to_canonical[typed_alias].add(canonical)

    for canonical, record_ids in sorted(canonical_to_records.items()):
        if len(record_ids) > 1:
            for record_id in record_ids:
                findings.append(
                    ValidationFinding(
                        record_id=record_id,
                        check="duplicate",
                        reason=(
                            "duplicate canonical advisory identifier "
                            f"{canonical!r} appears on {len(record_ids)} records"
                        ),
                    )
                )

    for alias, canonical_ids in sorted(alias_to_canonical.items()):
        if len(canonical_ids) > 1:
            findings.append(
                ValidationFinding(
                    record_id=next(iter(sorted(canonical_ids))),
                    check="alias",
                    reason=(
                        f"alias {alias!r} maps to multiple canonical advisories: "
                        + ", ".join(sorted(canonical_ids))
                    ),
                )
            )

    return findings


def detect_duplicate_record_ids(record_ids: Sequence[str]) -> list[ValidationFinding]:
    """Report duplicate normalized record identifiers across an inventory bundle."""
    counts: dict[str, int] = defaultdict(int)
    for record_id in record_ids:
        counts[record_id] += 1

    findings: list[ValidationFinding] = []
    for record_id, count in sorted(counts.items()):
        if count > 1:
            findings.append(
                ValidationFinding(
                    record_id=record_id,
                    check="duplicate",
                    reason=f"duplicate record_id appears {count} times in inventory",
                )
            )
    return findings


__all__ = ["detect_duplicate_advisories", "detect_duplicate_record_ids"]
