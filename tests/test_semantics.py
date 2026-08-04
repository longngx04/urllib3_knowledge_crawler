"""Offline tests for rule-based security semantic extraction."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from crawler.extractors.semantics import (
    assign_detection_type,
    compute_sast_usefulness_score,
    extract_security_semantics,
)
from crawler.models import (
    DetectionType,
    EvidenceRecord,
    PackageRecord,
    ProvenanceRecord,
    VersionEvent,
    VersionRange,
)
from crawler.normalizers.advisories import normalize_osv_vulnerability
from crawler.normalizers.patches import normalize_github_commit

FIXTURES = Path(__file__).parent / "fixtures"
PACKAGE = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


def _provenance(source_id: str) -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="osv",
        source_id=source_id,
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="a" * 64,
        extractor_version="0.1.0",
    )


def _patch_provenance(source_id: str) -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="github_commit",
        source_id=source_id,
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="d" * 64,
        extractor_version="0.1.0",
    )


def _load_osv(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text("utf-8"))


def _load_commit(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text("utf-8"))


def _advisory_and_patch(
    osv_fixture: str,
    commit_fixture: str,
    *,
    advisory_ids: list[str],
    fixed_versions: list[str],
) -> tuple[object, object]:
    osv_payload = _load_osv(osv_fixture)
    assert isinstance(osv_payload, dict)
    advisory = normalize_osv_vulnerability(
        osv_payload,
        provenance=_provenance(str(osv_payload.get("id", "fixture"))),
        package_name="urllib3",
        ecosystem="PyPI",
    )
    commit_payload = _load_commit(commit_fixture)
    assert isinstance(commit_payload, dict)
    patch = normalize_github_commit(
        commit_payload,
        provenance=_patch_provenance(f"urllib3/urllib3@{commit_payload['sha']}"),
        advisory_ids=advisory_ids,
        package=PACKAGE,
        owner="urllib3",
        repo="urllib3",
        advisory_fixed_versions=fixed_versions,
    )
    return advisory, patch


class TestAssignDetectionType:
    def test_version_api_when_only_symbols_present(self) -> None:
        assert (
            assign_detection_type(
                symbols=["HTTPResponse.drain_conn"],
                arguments=[],
                required_dataflow=[],
                sources=[],
            )
            == DetectionType.VERSION_API
        )

    def test_version_api_configuration_when_arguments_present(self) -> None:
        assert (
            assign_detection_type(
                symbols=["create_urllib3_context"],
                arguments=["cert_reqs=ssl.CERT_NONE"],
                required_dataflow=[],
                sources=[],
            )
            == DetectionType.VERSION_API_CONFIGURATION
        )

    def test_version_api_dataflow_when_dataflow_present(self) -> None:
        assert (
            assign_detection_type(
                symbols=["HTTPConnectionPool._validate_redirect_url"],
                arguments=[],
                required_dataflow=["redirect_location_header->sink"],
                sources=["redirect_location_header"],
            )
            == DetectionType.VERSION_API_DATAFLOW
        )


class TestComputeSastUsefulnessScore:
    def test_full_score_when_all_components_present(self) -> None:
        score = compute_sast_usefulness_score(
            version=VersionRange(
                raw=">=2.0.0,<2.0.7",
                events=[
                    VersionEvent(introduced="2.0.0"),
                    VersionEvent(fixed="2.0.7"),
                ],
                resolved=["2.0.6"],
                fixed_versions=["2.0.7"],
            ),
            symbols=["HTTPResponse.drain_conn"],
            preconditions=["drain_conn invoked"],
            arguments=["redirect=True"],
            negative_conditions=["already patched"],
            remediation_upgrade="Upgrade to 2.0.7",
            remediation_workarounds=[],
            patch_evidence=[EvidenceRecord(evidence_type="commit", source_id="a" * 40)],
            test_evidence=[],
        )
        assert score == 1.0

    def test_partial_score_documents_missing_components(self) -> None:
        score = compute_sast_usefulness_score(
            version=VersionRange(events=[VersionEvent(introduced="2.0.0")]),
            symbols=[],
            preconditions=[],
            arguments=[],
            negative_conditions=[],
            remediation_upgrade=None,
            remediation_workarounds=[],
            patch_evidence=[],
            test_evidence=[],
        )
        assert score == 0.125


class TestExtractSecuritySemantics:
    def test_version_api_extraction_from_advisory_and_patch(self) -> None:
        advisory, patch = _advisory_and_patch(
            "osv_vuln_version_api.json",
            "github_commit_version_api.json",
            advisory_ids=["CVE-2023-45803"],
            fixed_versions=["2.0.7"],
        )
        semantics = extract_security_semantics(advisory, patch=patch)
        assert semantics.detection_type == DetectionType.VERSION_API
        assert "urllib3.response" in semantics.modules
        assert any("drain_conn" in symbol for symbol in semantics.symbols)
        assert semantics.version.fixed_versions == ["2.0.7"]
        assert semantics.version.events
        assert semantics.preconditions
        assert semantics.negative_conditions
        assert semantics.patch_evidence
        assert semantics.test_evidence
        assert 0.0 < semantics.sast_usefulness_score <= 1.0
        assert any(
            "unsupported inference" in item or "patch diff" in item
            for item in semantics.confidence_rationale
        )

    def test_version_api_configuration_extraction(self) -> None:
        advisory, patch = _advisory_and_patch(
            "osv_vuln_version_api_config.json",
            "github_commit_version_api_config.json",
            advisory_ids=["GHSA-q69q-g6gr-6q4p"],
            fixed_versions=["1.26.18"],
        )
        semantics = extract_security_semantics(advisory, patch=patch)
        assert semantics.detection_type == DetectionType.VERSION_API_CONFIGURATION
        assert "cert_reqs=ssl.CERT_NONE" in semantics.arguments
        assert semantics.version.fixed_versions == ["1.26.18"]
        assert semantics.preconditions
        assert semantics.negative_conditions

    def test_version_api_dataflow_extraction(self) -> None:
        advisory, patch = _advisory_and_patch(
            "osv_vuln_version_api_dataflow.json",
            "github_commit_version_api_dataflow.json",
            advisory_ids=["GHSA-565x-2c8m-578w"],
            fixed_versions=["2.6.3"],
        )
        changelog = (
            "Follow redirects when Location header contains protocol-relative URLs."
        )
        semantics = extract_security_semantics(
            advisory,
            patch=patch,
            changelog_text=changelog,
        )
        assert semantics.detection_type == DetectionType.VERSION_API_DATAFLOW
        assert semantics.sources
        assert semantics.required_dataflow
        assert semantics.version.fixed_versions == ["2.6.3"]
        assert semantics.preconditions
        assert semantics.negative_conditions

    def test_does_not_invent_affected_ranges_without_advisory_evidence(self) -> None:
        osv_payload = _load_osv("osv_vuln_version_api.json")
        assert isinstance(osv_payload, dict)
        osv_payload = {**osv_payload, "affected": []}
        advisory = normalize_osv_vulnerability(
            osv_payload,
            provenance=_provenance("CVE-2023-45803"),
        )
        semantics = extract_security_semantics(advisory)
        assert semantics.version.events == []
        assert semantics.version.resolved == []
        assert any(
            "unsupported inference" in item and "range absent" in item
            for item in semantics.confidence_rationale
        )

    def test_advisory_only_marks_unsupported_inferences(self) -> None:
        osv_payload = _load_osv("osv_vuln_version_api.json")
        assert isinstance(osv_payload, dict)
        advisory = normalize_osv_vulnerability(
            osv_payload,
            provenance=_provenance("CVE-2023-45803"),
        )
        semantics = extract_security_semantics(advisory)
        assert any(
            "patch evidence unavailable" in item
            for item in semantics.confidence_rationale
        )
