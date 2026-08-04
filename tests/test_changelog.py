"""Offline tests for the changelog extractor."""

from __future__ import annotations

from pathlib import Path

import pytest

from crawler.extractors.changelog import (
    ChangelogParseError,
    parse_changelog,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestRSTParser:
    def test_fixture_changelog(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        assert result.format == "rst"
        assert len(result.releases) == 4
        assert result.releases[0].version == "2.7.0"
        assert result.releases[0].date == "2025-07-16"
        assert result.releases[1].version == "2.6.0"
        assert result.releases[2].version == "2.5.0"
        assert result.releases[3].version == "2.4.0"

    def test_security_classification(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.7.0 first entry is about SSRF vulnerability
        security_entries = [
            e for e in result.releases[0].entries if e.category == "security"
        ]
        assert len(security_entries) >= 1
        assert "CVE-2025-43802" in security_entries[0].text

    def test_bugfix_classification(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.6.0 first entry is a bugfix
        bugfix_entries = [
            e for e in result.releases[1].entries if e.category == "bugfix"
        ]
        assert len(bugfix_entries) >= 1

    def test_feature_classification(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.7.0 has "Added HTTP/2 support"
        feature_entries = [
            e for e in result.releases[0].entries if e.category == "feature"
        ]
        assert len(feature_entries) >= 1

    def test_deprecation_classification(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.7.0 has "Deprecated HTTPResponse.getheaders()"
        deprecation_entries = [
            e for e in result.releases[0].entries if e.category == "deprecation"
        ]
        assert len(deprecation_entries) >= 1

    def test_documentation_classification(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.7.0 has "Updated API documentation"
        doc_entries = [
            e for e in result.releases[0].entries if e.category == "documentation"
        ]
        assert len(doc_entries) >= 1

    def test_cve_reference_extraction(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        security_entries = [
            e for e in result.releases[0].entries if e.category == "security"
        ]
        assert any("CVE-2025-43802" in e.references for e in security_entries)

    def test_ghsa_reference_extraction(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        security_entries = [
            e for e in result.releases[0].entries if e.category == "security"
        ]
        assert any("GHSA-vqfr-h8mv-ghfj" in e.references for e in security_entries)

    def test_issue_reference_extraction(self) -> None:
        content = (FIXTURES / "changelog.rst").read_text("utf-8")
        result = parse_changelog(content, format="rst")
        # 2.7.0 second entry has #3456
        entries_with_issues = [
            e for e in result.releases[0].entries if "#3456" in e.references
        ]
        assert len(entries_with_issues) >= 1

    def test_empty_content(self) -> None:
        result = parse_changelog("", format="rst")
        assert len(result.releases) == 0

    def test_no_version_headings(self) -> None:
        content = "Some random text\nwith no version headings\n"
        result = parse_changelog(content, format="rst")
        assert len(result.releases) == 0


class TestMarkdownParser:
    def test_basic_markdown(self) -> None:
        content = """## 2.0.0 (2025-01-01)

- Added new feature
- Fixed bug (#100)

## 1.0.0 (2024-06-01)

- Initial release
"""
        result = parse_changelog(content, format="markdown")
        assert result.format == "markdown"
        assert len(result.releases) == 2
        assert result.releases[0].version == "2.0.0"
        assert result.releases[0].date == "2025-01-01"
        assert result.releases[1].version == "1.0.0"

    def test_markdown_security_entry(self) -> None:
        content = """## 1.5.0 (2025-03-01)

- Security: Fixed vulnerability (CVE-2025-99999)
"""
        result = parse_changelog(content, format="markdown")
        assert len(result.releases) == 1
        security = [e for e in result.releases[0].entries if e.category == "security"]
        assert len(security) == 1
        assert "CVE-2025-99999" in security[0].references


class TestEdgeCases:
    def test_unsupported_format(self) -> None:
        with pytest.raises(ChangelogParseError, match="unsupported"):
            parse_changelog("content", format="xml")

    def test_non_string_content(self) -> None:
        with pytest.raises(ChangelogParseError, match="must be a string"):
            parse_changelog(42, format="rst")  # type: ignore[arg-type]

    def test_heading_without_version(self) -> None:
        content = """Introduction
-------------------

Some text here.

2.0.0 (2025-01-01)
-------------------

- A change
"""
        result = parse_changelog(content, format="rst")
        assert len(result.releases) == 1
        assert result.releases[0].version == "2.0.0"

    def test_entry_with_asterisk_bullets(self) -> None:
        content = """1.0.0 (2024-01-01)
-------------------

* Added a feature
* Fixed a bug
"""
        result = parse_changelog(content, format="rst")
        assert len(result.releases) == 1
        assert len(result.releases[0].entries) == 2
