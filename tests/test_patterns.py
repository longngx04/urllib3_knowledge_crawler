"""Offline tests for security-pattern normalization and JSONL export."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crawler.exporters.jsonl import export_security_pattern_inventory
from crawler.exporters.schemas import build_json_schemas
from crawler.models import DetectionType, PackageRecord, ProvenanceRecord
from crawler.normalizers.advisories import normalize_osv_vulnerability
from crawler.normalizers.patches import normalize_github_commit
from crawler.normalizers.patterns import (
    build_security_pattern_inventory,
    normalize_security_pattern,
)

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


def _build_pattern(
    osv_fixture: str,
    commit_fixture: str,
    *,
    advisory_ids: list[str],
    fixed_versions: list[str],
    changelog_text: str | None = None,
) -> object:
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
    return normalize_security_pattern(
        advisory,
        patch=patch,
        changelog_text=changelog_text,
    )


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
class TestNormalizeSecurityPattern:
    def test_builds_schema_valid_record_with_required_fields(
        self,
        label: str,
        osv_fixture: str,
        commit_fixture: str,
        advisory_ids: list[str],
        fixed_versions: list[str],
        detection: DetectionType,
    ) -> None:
        changelog = (
            "Redirect Location header reaches validation."
            if detection == DetectionType.VERSION_API_DATAFLOW
            else None
        )
        record = _build_pattern(
            osv_fixture,
            commit_fixture,
            advisory_ids=advisory_ids,
            fixed_versions=fixed_versions,
            changelog_text=changelog,
        )
        assert record.detection_type == detection
        assert record.version.events or record.version.resolved
        assert record.version.fixed_versions == fixed_versions
        assert record.vulnerable_usage.symbols
        assert record.vulnerable_usage.preconditions
        assert record.negative_conditions
        assert record.impact.notes or record.impact.confidentiality
        assert record.remediation.fixed_versions == fixed_versions
        assert record.patch_evidence or record.test_evidence
        assert record.confidence.score > 0.0
        assert record.provenance

        schema = build_json_schemas()["security_pattern.schema.json"]
        Draft202012Validator(schema).validate(
            json.loads(record.model_dump_json(by_alias=True))
        )


class TestSecurityPatternInventoryAndExport:
    def test_export_three_patterns_is_deterministic(self, tmp_path: Path) -> None:
        records = [
            _build_pattern(
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
            for (
                _,
                osv_fixture,
                commit_fixture,
                advisory_ids,
                fixed_versions,
                detection,
            ) in CASES
        ]
        inventory = build_security_pattern_inventory(package=PACKAGE, records=records)
        assert inventory.record_count == 3

        first = export_security_pattern_inventory(inventory, tmp_path / "first")
        second = export_security_pattern_inventory(inventory, tmp_path / "second")
        assert first.path.name == second.path.name == "security_patterns.jsonl"
        assert first.path.read_bytes() == second.path.read_bytes()
        assert first.sha256 == second.sha256
        assert first.record_count == 3
        assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256

        schema = build_json_schemas()["security_pattern.schema.json"]
        validator = Draft202012Validator(schema)
        canonical_ids: list[str] = []
        for line in first.path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            validator.validate(payload)
            canonical_ids.append(payload["identifiers"]["canonical"])
        assert len(canonical_ids) == 3
        assert canonical_ids == sorted(canonical_ids)

    def test_inventory_orders_by_canonical_id(self) -> None:
        records = [
            _build_pattern(
                osv_fixture,
                commit_fixture,
                advisory_ids=advisory_ids,
                fixed_versions=fixed_versions,
            )
            for _, osv_fixture, commit_fixture, advisory_ids, fixed_versions, _ in CASES
        ]
        inventory = build_security_pattern_inventory(package=PACKAGE, records=records)
        canonical_ids = [item.identifiers.canonical for item in inventory.records]
        assert canonical_ids == sorted(canonical_ids)
