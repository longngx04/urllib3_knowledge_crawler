"""Offline tests for KB document generation and export."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crawler.exporters.jsonl import export_kb_document_inventory
from crawler.exporters.schemas import build_json_schemas
from crawler.models import (
    DetectionType,
    KBDocumentType,
    PackageRecord,
    ProvenanceRecord,
)
from crawler.normalizers.advisories import normalize_osv_vulnerability
from crawler.normalizers.kb_documents import (
    MAX_CONTENT_BYTES,
    KBDocumentContentTooLargeError,
    KBDocumentTopic,
    build_kb_document_inventory,
    generate_kb_documents_for_pattern,
    generate_kb_documents_from_patterns,
)
from crawler.normalizers.patches import normalize_github_commit
from crawler.normalizers.patterns import normalize_security_pattern

FIXTURES = Path(__file__).parent / "fixtures"
PACKAGE = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")

CASES = (
    (
        "version_api",
        "osv_vuln_version_api.json",
        "github_commit_version_api.json",
        ["CVE-2023-45803"],
        ["2.0.7"],
        DetectionType.VERSION_API,
    ),
    (
        "version_api_configuration",
        "osv_vuln_version_api_config.json",
        "github_commit_version_api_config.json",
        ["GHSA-q69q-g6gr-6q4p"],
        ["1.26.18"],
        DetectionType.VERSION_API_CONFIGURATION,
    ),
    (
        "version_api_dataflow",
        "osv_vuln_version_api_dataflow.json",
        "github_commit_version_api_dataflow.json",
        ["GHSA-565x-2c8m-578w"],
        ["2.6.3"],
        DetectionType.VERSION_API_DATAFLOW,
    ),
)


def _provenance(source_id: str, source_type: str = "osv") -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type=source_type,
        source_id=source_id,
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


def _build_pattern_bundle(
    osv_fixture: str,
    commit_fixture: str,
    *,
    advisory_ids: list[str],
    fixed_versions: list[str],
    changelog_text: str | None = None,
) -> tuple[object, object, object]:
    osv_payload = json.loads((FIXTURES / osv_fixture).read_text("utf-8"))
    commit_payload = json.loads((FIXTURES / commit_fixture).read_text("utf-8"))
    advisory = normalize_osv_vulnerability(
        osv_payload,
        provenance=_provenance(str(osv_payload["id"])),
    )
    patch = normalize_github_commit(
        commit_payload,
        provenance=_provenance(
            f"urllib3/urllib3@{commit_payload['sha']}",
            source_type="github_commit",
        ),
        advisory_ids=advisory_ids,
        package=PACKAGE,
        owner="urllib3",
        repo="urllib3",
        advisory_fixed_versions=fixed_versions,
    )
    pattern = normalize_security_pattern(
        advisory,
        patch=patch,
        changelog_text=changelog_text,
    )
    return advisory, patch, pattern


@pytest.mark.parametrize(
    (
        "label",
        "osv_fixture",
        "commit_fixture",
        "advisory_ids",
        "fixed_versions",
        "detection",
    ),
    CASES,
)
class TestGenerateKbDocumentsForPattern:
    def test_produces_multiple_topic_documents_with_filters(
        self,
        label: str,
        osv_fixture: str,
        commit_fixture: str,
        advisory_ids: list[str],
        fixed_versions: list[str],
        detection: DetectionType,
    ) -> None:
        advisory, patch, pattern = _build_pattern_bundle(
            osv_fixture,
            commit_fixture,
            advisory_ids=advisory_ids,
            fixed_versions=fixed_versions,
        )
        documents = generate_kb_documents_for_pattern(
            pattern,
            advisory=advisory,
            patch=patch,
        )
        assert len(documents) >= 4
        titles = {doc.title for doc in documents}
        assert any("Vulnerability overview" in title for title in titles)
        assert any("Detection guidance" in title for title in titles)
        assert any("Negative conditions" in title for title in titles)
        assert any("Remediation guidance" in title for title in titles)

        detection_doc = next(
            doc for doc in documents if doc.title.startswith("Detection guidance")
        )
        assert detection_doc.document_type is KBDocumentType.SECURITY_PATTERN
        assert detection_doc.metadata.package_name == "urllib3"
        assert detection_doc.metadata.detection_type == detection
        assert detection_doc.metadata.symbols
        assert detection_doc.metadata.advisory_ids
        assert (
            detection_doc.metadata.affected_versions
            or detection_doc.metadata.fixed_versions
        )
        assert detection_doc.metadata.confidence is not None
        assert detection_doc.source_record_ids
        assert pattern.record_id in detection_doc.source_record_ids

        overview = next(
            doc for doc in documents if doc.title.startswith("Vulnerability overview")
        )
        assert overview.document_type is KBDocumentType.ADVISORY
        assert advisory.record_id in overview.source_record_ids

        schema = build_json_schemas()["kb_document.schema.json"]
        validator = Draft202012Validator(schema)
        for doc in documents:
            validator.validate(json.loads(doc.model_dump_json(by_alias=True)))
            assert len(doc.content.encode("utf-8")) <= MAX_CONTENT_BYTES


class TestKbDocumentInventoryAndExport:
    def test_three_patterns_yield_many_documents_and_export(
        self, tmp_path: Path
    ) -> None:
        advisories = []
        patches = []
        patterns = []
        for (
            _,
            osv_fixture,
            commit_fixture,
            advisory_ids,
            fixed_versions,
            detection,
        ) in CASES:
            advisory, patch, pattern = _build_pattern_bundle(
                osv_fixture,
                commit_fixture,
                advisory_ids=advisory_ids,
                fixed_versions=fixed_versions,
                changelog_text=(
                    "Attacker-controlled redirect Location header."
                    if detection == DetectionType.VERSION_API_DATAFLOW
                    else None
                ),
            )
            advisories.append(advisory)
            patches.append(patch)
            patterns.append(pattern)

        result = generate_kb_documents_from_patterns(
            package=PACKAGE,
            patterns=patterns,
            advisories=advisories,
            patches=patches,
        )
        assert result.inventory.record_count >= 12
        assert result.stats.documents_written == result.inventory.record_count
        assert result.stats.duplicate_rate == 0.0

        first = export_kb_document_inventory(result.inventory, tmp_path / "first")
        second = export_kb_document_inventory(result.inventory, tmp_path / "second")
        assert first.path.name == second.path.name == "documents.jsonl"
        assert first.path.parent.name == "kb"
        assert first.path.read_bytes() == second.path.read_bytes()
        assert first.sha256 == second.sha256
        assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256

        schema = build_json_schemas()["kb_document.schema.json"]
        validator = Draft202012Validator(schema)
        titles: list[str] = []
        for line in first.path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            validator.validate(payload)
            titles.append(payload["title"])
        assert len(titles) == result.inventory.record_count
        exported_titles = [record.title for record in result.inventory.records]
        assert titles == exported_titles

    def test_duplicate_content_is_reported(self) -> None:
        advisory, patch, pattern = _build_pattern_bundle(
            CASES[0][1],
            CASES[0][2],
            advisory_ids=list(CASES[0][3]),
            fixed_versions=list(CASES[0][4]),
        )
        docs = list(
            generate_kb_documents_for_pattern(pattern, advisory=advisory, patch=patch)
        )
        duplicate = docs[0].model_copy(
            update={
                "record_id": "kb_document:" + ("f" * 64),
                "title": docs[0].title + " (copy)",
            }
        )
        result = build_kb_document_inventory(
            package=PACKAGE,
            records=[*docs, duplicate],
        )
        assert result.stats.documents_attempted == len(docs) + 1
        assert result.stats.duplicates_skipped == 1
        assert result.stats.duplicate_rate == pytest.approx(1 / (len(docs) + 1))
        assert result.inventory.record_count == len(docs)

    def test_content_size_limit_is_enforced(self) -> None:
        advisory, patch, pattern = _build_pattern_bundle(
            CASES[0][1],
            CASES[0][2],
            advisory_ids=list(CASES[0][3]),
            fixed_versions=list(CASES[0][4]),
        )
        oversized = "x" * (MAX_CONTENT_BYTES + 1)
        huge_pattern = pattern.model_copy(
            update={
                "negative_conditions": [oversized],
            }
        )
        with pytest.raises(KBDocumentContentTooLargeError):
            generate_kb_documents_for_pattern(
                huge_pattern,
                advisory=advisory,
                patch=patch,
                topics=[KBDocumentTopic.NEGATIVE_CONDITIONS],
            )
