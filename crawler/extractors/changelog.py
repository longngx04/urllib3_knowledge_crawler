"""Pure changelog parser for RST and Markdown formats."""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_PATTERN = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:(?:a|b|rc|\.dev|\.post)\d+)?)")
_DATE_PATTERN = re.compile(r"\((\d{4}-\d{2}-\d{2})\)")
_RST_UNDERLINE = re.compile(r"^[-=~^]{3,}$")
_MD_HEADING = re.compile(r"^#{2,3}\s+(.+)$")
_ENTRY_START = re.compile(r"^\s*[-*]\s+(.+)$")

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")
_ISSUE_PATTERN = re.compile(r"#(\d+)")
_COMMIT_PATTERN = re.compile(r"(?:^|\s)([0-9a-f]{7,40})(?:\s|$)")

_SECURITY_KEYWORDS = re.compile(
    r"\b(?:CVE|GHSA|vulnerability|vulnerabilities|security)\b", re.IGNORECASE
)
_DEPRECATION_KEYWORDS = re.compile(r"\bdeprecat", re.IGNORECASE)
_DEPRECATION_START = re.compile(r"^\s*[-*]\s+Deprecated\b", re.IGNORECASE)
_BUGFIX_START = re.compile(r"^\s*[-*]\s+(?:Bugfix|Bug|Fix|Fixed)\b", re.IGNORECASE)
_DOC_KEYWORDS = re.compile(r"\bdoc(?:umentation|s)?\b", re.IGNORECASE)
_FEATURE_START = re.compile(
    r"^\s*[-*]\s+(?:Added|New|Support|Implement)", re.IGNORECASE
)

_MAX_CONTENT_LENGTH = 10_000_000
_MAX_RELEASES = 10_000
_MAX_ENTRIES_PER_RELEASE = 5_000


class ChangelogParseError(ValueError):
    """Raised when changelog content cannot be safely parsed."""


@dataclass(frozen=True, slots=True)
class ChangelogEntry:
    """One classified changelog line with extracted references."""

    category: str
    text: str
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChangelogRelease:
    """All entries for one release heading."""

    version: str
    date: str | None
    entries: tuple[ChangelogEntry, ...]


@dataclass(frozen=True, slots=True)
class ParsedChangelog:
    """Complete parsed changelog with format metadata."""

    releases: tuple[ChangelogRelease, ...]
    format: str


def _extract_references(text: str) -> tuple[str, ...]:
    """Extract CVE, GHSA, issue/PR, and commit references from text."""
    refs: list[str] = []
    refs.extend(_CVE_PATTERN.findall(text))
    refs.extend(_GHSA_PATTERN.findall(text))
    for match in _ISSUE_PATTERN.finditer(text):
        refs.append(f"#{match.group(1)}")
    for match in _COMMIT_PATTERN.finditer(text):
        candidate = match.group(1)
        if len(candidate) >= 7 and not candidate.isdigit():
            refs.append(candidate)
    return tuple(sorted(set(refs)))


def _classify_entry(raw_line: str, text: str) -> str:
    """Classify a changelog entry by its content."""
    if _SECURITY_KEYWORDS.search(text):
        return "security"
    if _DEPRECATION_START.match(raw_line) or _DEPRECATION_KEYWORDS.search(text):
        return "deprecation"
    if _BUGFIX_START.match(raw_line):
        return "bugfix"
    if _DOC_KEYWORDS.search(text):
        return "documentation"
    if _FEATURE_START.match(raw_line):
        return "feature"
    return "other"


def _parse_entry(raw_line: str) -> ChangelogEntry | None:
    """Parse a single changelog entry line."""
    match = _ENTRY_START.match(raw_line)
    if match is None:
        return None
    text = match.group(1).strip()
    if not text:
        return None
    return ChangelogEntry(
        category=_classify_entry(raw_line, text),
        text=text,
        references=_extract_references(text),
    )


def _extract_version_from_heading(heading: str) -> str | None:
    """Extract a version string from a heading line."""
    match = _VERSION_PATTERN.search(heading)
    return match.group(1) if match else None


def _extract_date_from_heading(heading: str) -> str | None:
    """Extract a (YYYY-MM-DD) date from a heading line."""
    match = _DATE_PATTERN.search(heading)
    return match.group(1) if match else None


def _parse_rst(lines: list[str]) -> list[ChangelogRelease]:
    """Parse an RST changelog with underlined headings."""
    releases: list[ChangelogRelease] = []
    current_heading: str | None = None
    current_entries: list[ChangelogEntry] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        if i + 1 < len(lines) and _RST_UNDERLINE.match(lines[i + 1].strip()):
            if current_heading is not None:
                version = _extract_version_from_heading(current_heading)
                if version is not None:
                    if len(releases) >= _MAX_RELEASES:
                        raise ChangelogParseError(
                            f"changelog exceeds {_MAX_RELEASES} releases"
                        )
                    releases.append(
                        ChangelogRelease(
                            version=version,
                            date=_extract_date_from_heading(current_heading),
                            entries=tuple(current_entries),
                        )
                    )
                current_entries = []
            current_heading = line.strip()
            i += 2
            continue

        if current_heading is not None:
            entry = _parse_entry(line)
            if entry is not None:
                if len(current_entries) >= _MAX_ENTRIES_PER_RELEASE:
                    raise ChangelogParseError(
                        f"release exceeds {_MAX_ENTRIES_PER_RELEASE} entries"
                    )
                current_entries.append(entry)
        i += 1

    if current_heading is not None:
        version = _extract_version_from_heading(current_heading)
        if version is not None:
            releases.append(
                ChangelogRelease(
                    version=version,
                    date=_extract_date_from_heading(current_heading),
                    entries=tuple(current_entries),
                )
            )

    return releases


def _parse_markdown(lines: list[str]) -> list[ChangelogRelease]:
    """Parse a Markdown changelog with ## headings."""
    releases: list[ChangelogRelease] = []
    current_heading: str | None = None
    current_entries: list[ChangelogEntry] = []

    for line in lines:
        md_match = _MD_HEADING.match(line.strip())
        if md_match is not None:
            if current_heading is not None:
                version = _extract_version_from_heading(current_heading)
                if version is not None:
                    if len(releases) >= _MAX_RELEASES:
                        raise ChangelogParseError(
                            f"changelog exceeds {_MAX_RELEASES} releases"
                        )
                    releases.append(
                        ChangelogRelease(
                            version=version,
                            date=_extract_date_from_heading(current_heading),
                            entries=tuple(current_entries),
                        )
                    )
                current_entries = []
            current_heading = md_match.group(1).strip()
            continue

        if current_heading is not None:
            entry = _parse_entry(line)
            if entry is not None:
                if len(current_entries) >= _MAX_ENTRIES_PER_RELEASE:
                    raise ChangelogParseError(
                        f"release exceeds {_MAX_ENTRIES_PER_RELEASE} entries"
                    )
                current_entries.append(entry)

    if current_heading is not None:
        version = _extract_version_from_heading(current_heading)
        if version is not None:
            releases.append(
                ChangelogRelease(
                    version=version,
                    date=_extract_date_from_heading(current_heading),
                    entries=tuple(current_entries),
                )
            )

    return releases


def parse_changelog(content: str, format: str = "rst") -> ParsedChangelog:
    """Parse a changelog file into structured release entries.

    This function is pure — no I/O, no network access. It classifies each entry
    by category and extracts CVE, GHSA, issue/PR, and commit references.
    """
    if not isinstance(content, str):
        raise ChangelogParseError("changelog content must be a string")
    if len(content) > _MAX_CONTENT_LENGTH:
        raise ChangelogParseError(f"changelog exceeds {_MAX_CONTENT_LENGTH} characters")
    if format not in ("rst", "markdown"):
        raise ChangelogParseError(f"unsupported changelog format: {format!r}")

    lines = content.splitlines()

    releases = _parse_rst(lines) if format == "rst" else _parse_markdown(lines)

    return ParsedChangelog(releases=tuple(releases), format=format)


__all__ = [
    "ChangelogEntry",
    "ChangelogParseError",
    "ChangelogRelease",
    "ParsedChangelog",
    "parse_changelog",
]
