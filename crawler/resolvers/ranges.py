"""Resolve advisory version ranges against a PEP 440 version inventory."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from crawler.models import AdvisoryRecord, VersionEvent, VersionRange
from crawler.normalizers.versions import VersionInventory

_BEGINNING = "0"


class RangeIssueKind(StrEnum):
    """Classified range-resolution problem reported to operators."""

    INVALID_RANGE = "invalid_range"
    MISSING_FIXED_VERSION = "missing_fixed_version"
    CONTRADICTORY_RANGES = "contradictory_ranges"
    UNRESOLVABLE = "unresolvable"


@dataclass(frozen=True, slots=True)
class RangeResolutionIssue:
    """One auditable problem found while resolving advisory ranges."""

    advisory_id: str
    kind: RangeIssueKind
    message: str
    range_index: int | None = None


@dataclass(frozen=True, slots=True)
class RangeResolutionStats:
    """Deterministic coverage metrics for one resolution pass."""

    total_advisories: int
    resolvable_advisories: int
    unresolvable_advisories: int
    total_ranges: int
    resolved_ranges: int
    invalid_ranges: int
    missing_fixed_versions: int
    contradictory_ranges: int

    @property
    def coverage_ratio(self) -> float:
        if self.total_advisories == 0:
            return 1.0
        return self.resolvable_advisories / self.total_advisories


@dataclass(frozen=True, slots=True)
class RangeResolutionResult:
    """Resolved advisories plus operator-visible issues and metrics."""

    advisories: tuple[AdvisoryRecord, ...]
    issues: tuple[RangeResolutionIssue, ...]
    stats: RangeResolutionStats


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _boundary_version(value: str) -> Version | None:
    """Return a PEP 440 version, or ``None`` for OSV's beginning sentinel ``0``."""

    if value == _BEGINNING:
        return None
    return _parse_version(value)


def _is_specifier_expression(raw: str) -> bool:
    stripped = raw.strip()
    if not stripped or stripped.upper() in {"ECOSYSTEM", "SEMVER", "GIT"}:
        return False
    return any(char in stripped for char in "<>!=~")


def version_matches_events(version: Version, events: Sequence[VersionEvent]) -> bool:
    """Evaluate OSV introduced/fixed/last_affected/limit events for one version."""

    vulnerable = False
    for event in events:
        if event.introduced is not None:
            introduced = _boundary_version(event.introduced)
            if event.introduced != _BEGINNING and introduced is None:
                return False
            if introduced is None or version >= introduced:
                vulnerable = True
        elif event.fixed is not None:
            fixed = _parse_version(event.fixed)
            if fixed is None:
                return False
            if version >= fixed:
                vulnerable = False
        elif event.last_affected is not None:
            last_affected = _parse_version(event.last_affected)
            if last_affected is None:
                return False
            if version > last_affected:
                vulnerable = False
        elif event.limit is not None:
            limit = _parse_version(event.limit)
            if limit is None:
                return False
            if version >= limit:
                vulnerable = False
    return vulnerable


def version_matches_specifier(version: Version, specifier: str) -> bool:
    """Return whether ``version`` satisfies a PEP 440 specifier expression."""

    try:
        spec = SpecifierSet(specifier, prereleases=True)
    except InvalidSpecifier as error:
        raise ValueError(f"invalid PEP 440 specifier: {specifier}") from error
    return version in spec


def _validate_events(events: Sequence[VersionEvent]) -> str | None:
    if not events:
        return "version range has no events"
    for event in events:
        if event.introduced is not None:
            if (
                event.introduced != _BEGINNING
                and _parse_version(event.introduced) is None
            ):
                return f"invalid introduced boundary: {event.introduced!r}"
        elif event.fixed is not None and _parse_version(event.fixed) is None:
            return f"invalid fixed boundary: {event.fixed!r}"
        elif (
            event.last_affected is not None
            and _parse_version(event.last_affected) is None
        ):
            return f"invalid last_affected boundary: {event.last_affected!r}"
        elif event.limit is not None and _parse_version(event.limit) is None:
            return f"invalid limit boundary: {event.limit!r}"
    return None


def _inventory_versions(inventory: VersionInventory) -> tuple[Version, ...]:
    parsed: list[Version] = []
    for record in inventory.records:
        version = _parse_version(record.normalized_version)
        if version is None:
            raise ValueError(
                "inventory contains an unparsable normalized version: "
                f"{record.normalized_version!r}"
            )
        parsed.append(version)
    return tuple(parsed)


def resolve_version_range(
    version_range: VersionRange,
    inventory_versions: Sequence[Version],
) -> tuple[list[str], str | None]:
    """Resolve one range against known releases.

    Returns ``(resolved_versions, error_message)``. ``resolved`` is PEP 440 sorted.
    Raw source ranges are preserved on the input; this function does not mutate it.
    """

    if version_range.events:
        error = _validate_events(version_range.events)
        if error is not None:
            return [], error
        matched = [
            str(version)
            for version in inventory_versions
            if version_matches_events(version, version_range.events)
        ]
        return matched, None

    if version_range.raw and _is_specifier_expression(version_range.raw):
        try:
            matched = [
                str(version)
                for version in inventory_versions
                if version_matches_specifier(version, version_range.raw)
            ]
        except ValueError as error:
            return [], str(error)
        return matched, None

    if version_range.raw:
        return [], f"unsupported raw range expression: {version_range.raw!r}"
    return [], "version range has neither events nor a parseable raw specifier"


def _merge_unique_versions(*groups: Sequence[str]) -> list[str]:
    values: set[str] = set()
    for group in groups:
        for item in group:
            parsed = _parse_version(item)
            if parsed is not None:
                values.add(str(parsed))
    return sorted(values, key=Version)


def resolve_advisory_ranges(
    advisories: Sequence[AdvisoryRecord],
    inventory: VersionInventory,
) -> RangeResolutionResult:
    """Resolve every advisory's ranges against the PyPI inventory.

    - Preserves each range's ``raw`` and ``events``.
    - Writes deterministic ``resolved`` lists onto each ``VersionRange``.
    - Unions explicit source versions with resolved versions onto the advisory.
    - Never invents fixed versions; missing inventory matches are reported.
    - Reports invalid, contradictory, and unresolvable ranges without dropping
      the advisory.
    """

    inventory_versions = _inventory_versions(inventory)
    inventory_set = {str(version) for version in inventory_versions}

    resolved_advisories: list[AdvisoryRecord] = []
    issues: list[RangeResolutionIssue] = []
    resolvable = 0
    unresolvable = 0
    total_ranges = 0
    resolved_ranges = 0
    invalid_ranges = 0
    missing_fixed = 0
    contradictory = 0

    for advisory in advisories:
        advisory_id = advisory.identifiers.canonical
        total_ranges += len(advisory.affected_ranges)
        resolved_range_models: list[VersionRange] = []
        range_resolved_versions: list[str] = []
        range_errors = 0
        had_resolvable_range = False

        for index, version_range in enumerate(advisory.affected_ranges):
            resolved, error = resolve_version_range(version_range, inventory_versions)
            if error is not None:
                range_errors += 1
                invalid_ranges += 1
                issues.append(
                    RangeResolutionIssue(
                        advisory_id=advisory_id,
                        kind=RangeIssueKind.INVALID_RANGE,
                        message=error,
                        range_index=index,
                    )
                )
                resolved_range_models.append(
                    VersionRange(
                        raw=version_range.raw,
                        events=list(version_range.events),
                        resolved=[],
                        fixed_versions=list(version_range.fixed_versions),
                    )
                )
                continue

            had_resolvable_range = True
            resolved_ranges += 1
            range_resolved_versions.extend(resolved)
            fixed_in_range = _merge_unique_versions(version_range.fixed_versions)
            contradiction = sorted(
                set(resolved) & set(fixed_in_range),
                key=Version,
            )
            if contradiction:
                contradictory += 1
                issues.append(
                    RangeResolutionIssue(
                        advisory_id=advisory_id,
                        kind=RangeIssueKind.CONTRADICTORY_RANGES,
                        message=(
                            "fixed versions also appear in the resolved affected set: "
                            + ", ".join(contradiction)
                        ),
                        range_index=index,
                    )
                )

            resolved_range_models.append(
                VersionRange(
                    raw=version_range.raw,
                    events=list(version_range.events),
                    resolved=resolved,
                    fixed_versions=list(version_range.fixed_versions),
                )
            )

        explicit_affected = _merge_unique_versions(advisory.affected_versions)
        merged_affected = _merge_unique_versions(
            explicit_affected,
            range_resolved_versions,
        )
        fixed_versions = _merge_unique_versions(
            advisory.fixed_versions,
            *(item.fixed_versions for item in resolved_range_models),
        )

        for fixed in fixed_versions:
            if fixed not in inventory_set:
                missing_fixed += 1
                issues.append(
                    RangeResolutionIssue(
                        advisory_id=advisory_id,
                        kind=RangeIssueKind.MISSING_FIXED_VERSION,
                        message=f"fixed version not present in inventory: {fixed}",
                    )
                )

        overlap = sorted(set(merged_affected) & set(fixed_versions), key=Version)
        if overlap:
            contradictory += 1
            issues.append(
                RangeResolutionIssue(
                    advisory_id=advisory_id,
                    kind=RangeIssueKind.CONTRADICTORY_RANGES,
                    message=(
                        "advisory fixed versions overlap resolved affected versions: "
                        + ", ".join(overlap)
                    ),
                )
            )

        can_resolve = (
            had_resolvable_range
            or bool(explicit_affected)
            or (not advisory.affected_ranges and not advisory.affected_versions)
        )
        # Advisories with only invalid ranges and no explicit versions are unresolvable.
        if (
            advisory.affected_ranges
            and not had_resolvable_range
            and not explicit_affected
        ):
            can_resolve = False

        if not can_resolve:
            unresolvable += 1
            issues.append(
                RangeResolutionIssue(
                    advisory_id=advisory_id,
                    kind=RangeIssueKind.UNRESOLVABLE,
                    message=(
                        "no resolvable range or explicit affected versions "
                        f"remain after {range_errors} invalid range(s)"
                    ),
                )
            )
        else:
            resolvable += 1

        resolved_advisories.append(
            advisory.model_copy(
                update={
                    "affected_ranges": resolved_range_models,
                    "affected_versions": merged_affected,
                    "fixed_versions": fixed_versions,
                }
            )
        )

    stats = RangeResolutionStats(
        total_advisories=len(advisories),
        resolvable_advisories=resolvable,
        unresolvable_advisories=unresolvable,
        total_ranges=total_ranges,
        resolved_ranges=resolved_ranges,
        invalid_ranges=invalid_ranges,
        missing_fixed_versions=missing_fixed,
        contradictory_ranges=contradictory,
    )
    return RangeResolutionResult(
        advisories=tuple(resolved_advisories),
        issues=tuple(issues),
        stats=stats,
    )


__all__ = [
    "RangeIssueKind",
    "RangeResolutionIssue",
    "RangeResolutionResult",
    "RangeResolutionStats",
    "resolve_advisory_ranges",
    "resolve_version_range",
    "version_matches_events",
    "version_matches_specifier",
]
