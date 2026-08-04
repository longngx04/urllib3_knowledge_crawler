"""Unit tests for advisory normalization and canonical identifier selection."""

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from crawler.models import AdvisoryRecord, ProvenanceRecord
from crawler.normalizers.advisories import (
    AdvisoryNormalizationError,
    extract_commit_shas,
    normalize_osv_vulnerability,
    select_canonical_identifier,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"


@pytest.fixture
def dummy_provenance() -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id="GHSA-565x-2c8m-578w",
        retrieved_at=datetime(2023, 10, 18, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


@pytest.fixture
def advisory_schema() -> dict:
    with open(SCHEMAS_DIR / "advisory.schema.json", encoding="utf-8") as f:
        return json.load(f)


def test_select_canonical_identifier_priority():
    # Priority: GHSA > CVE > OSV/PYSEC > first
    ids1 = ["CVE-2023-45803", "GHSA-565x-2c8m-578w", "PYSEC-2023-999"]
    assert select_canonical_identifier(ids1) == "GHSA-565x-2c8m-578w"

    ids2 = ["PYSEC-2023-999", "CVE-2023-45803"]
    assert select_canonical_identifier(ids2) == "CVE-2023-45803"

    ids3 = ["PYSEC-2023-999", "OSV-2023-1"]
    assert select_canonical_identifier(ids3) == "PYSEC-2023-999"


def test_select_canonical_identifier_empty():
    with pytest.raises(AdvisoryNormalizationError):
        select_canonical_identifier([])


def test_extract_commit_shas():
    refs = [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
        "https://github.com/urllib3/urllib3/commit/1234567890abcdef1234567890abcdef12345678",
        "https://github.com/urllib3/urllib3/commit/2d4a3fee6de2bc4580e49e096f6004ccb70868f0",
    ]
    shas = extract_commit_shas(refs)
    assert len(shas) == 2
    assert "1234567890abcdef1234567890abcdef12345678" in shas
    assert "2d4a3fee6de2bc4580e49e096f6004ccb70868f0" in shas


def test_normalize_osv_vulnerability_ghsa_fixture(dummy_provenance, advisory_schema):
    with open(FIXTURES_DIR / "osv_vuln_ghsa.json", encoding="utf-8") as f:
        payload = json.load(f)

    record = normalize_osv_vulnerability(
        payload, provenance=dummy_provenance, package_name="urllib3", ecosystem="PyPI"
    )

    assert isinstance(record, AdvisoryRecord)
    assert record.identifiers.canonical == "GHSA-v845-j25r-839j"
    assert "CVE-2021-33503" in record.identifiers.aliases
    assert "PYSEC-2021-108" in record.identifiers.aliases
    assert record.identifiers.cve == "CVE-2021-33503"
    assert record.identifiers.ghsa == "GHSA-v845-j25r-839j"
    assert record.cwe == ["CWE-200"]
    assert record.severity == "HIGH"
    assert "2d4a3fee6de2bc4580e49e096f6004ccb70868f0" in record.patch_commits
    assert "1.26.5" in record.fixed_versions

    # Validate against JSON Schema
    record_json = json.loads(record.model_dump_json(by_alias=True))
    jsonschema.validate(instance=record_json, schema=advisory_schema)


def test_normalize_osv_vulnerability_cve_fixture(dummy_provenance, advisory_schema):
    with open(FIXTURES_DIR / "osv_vuln_cve.json", encoding="utf-8") as f:
        payload = json.load(f)

    record = normalize_osv_vulnerability(
        payload, provenance=dummy_provenance, package_name="urllib3", ecosystem="PyPI"
    )

    assert record.identifiers.canonical == "CVE-2020-26137"
    assert record.identifiers.cve == "CVE-2020-26137"
    assert record.cwe == ["CWE-93"]
    assert record.severity == "MODERATE"
    assert "1dd69c581fd19dddd57f142b3ac99926a112ec3d" in record.patch_commits

    record_json = json.loads(record.model_dump_json(by_alias=True))
    jsonschema.validate(instance=record_json, schema=advisory_schema)


def test_normalize_osv_vulnerability_missing_id(dummy_provenance):
    with pytest.raises(AdvisoryNormalizationError, match="missing 'id'"):
        normalize_osv_vulnerability({}, provenance=dummy_provenance)
