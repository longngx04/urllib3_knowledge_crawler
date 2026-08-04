"""Offline tests for patch normalization and JSONL export."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crawler.exporters.jsonl import export_patch_inventory
from crawler.exporters.schemas import build_json_schemas
from crawler.models import PackageRecord, ProvenanceRecord
from crawler.normalizers.patches import (
    PatchNormalizationError,
    UnresolvedPatchRef,
    build_patch_inventory,
    normalize_github_commit,
    verify_repository_owner,
)
from crawler.utils.http import RetrievedResponse

FIXTURES = Path(__file__).parent / "fixtures"
PACKAGE = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


def _provenance(source_id: str = "urllib3/urllib3@fixture") -> ProvenanceRecord:
    return ProvenanceRecord(
        source_type="github_commit",
        source_id=source_id,
        retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
        raw_sha256="d" * 64,
        extractor_version="0.1.0",
    )


def _load_commit(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text("utf-8"))


def _normalize_fixture(
    fixture_name: str,
    *,
    advisory_ids: list[str],
    advisory_fixed_versions: list[str] | None = None,
    commit_tag_map: dict[str, str] | None = None,
) -> object:
    payload = _load_commit(fixture_name)
    assert isinstance(payload, dict)
    return normalize_github_commit(
        payload,
        provenance=_provenance(),
        advisory_ids=advisory_ids,
        package=PACKAGE,
        owner="urllib3",
        repo="urllib3",
        advisory_fixed_versions=advisory_fixed_versions or [],
        commit_tag_map=commit_tag_map,
    )


class TestVerifyRepositoryOwner:
    def test_accepts_configured_repository(self) -> None:
        verify_repository_owner("urllib3", "urllib3")

    def test_rejects_foreign_repository(self) -> None:
        with pytest.raises(PatchNormalizationError, match="does not match"):
            verify_repository_owner("evil", "urllib3")


class TestNormalizeGithubCommit:
    def test_version_api_patch_record(self) -> None:
        record = _normalize_fixture(
            "github_commit_version_api.json",
            advisory_ids=["CVE-2023-45803"],
            advisory_fixed_versions=["2.0.7"],
            commit_tag_map={
                "a1b2c3d4e5f6789012345678901234567890abcd": "2.0.7",
            },
        )
        assert record.commit_sha == "a1b2c3d4e5f6789012345678901234567890abcd"
        assert record.advisory_ids == ["CVE-2023-45803"]
        assert "src/urllib3/response.py" in record.changed_files
        assert "drain_conn" in record.changed_symbols
        assert record.fixed_versions == ["2.0.7"]
        assert record.regression_tests == ["test/test_response.py"]

    def test_version_api_configuration_patch_record(self) -> None:
        record = _normalize_fixture(
            "github_commit_version_api_config.json",
            advisory_ids=["GHSA-q69q-g6gr-6q4p"],
            advisory_fixed_versions=["1.26.18"],
        )
        assert "src/urllib3/util/ssl_.py" in record.changed_files
        assert any("CERT_NONE" in guard for guard in record.added_guards)

    def test_version_api_dataflow_patch_record(self) -> None:
        record = _normalize_fixture(
            "github_commit_version_api_dataflow.json",
            advisory_ids=["GHSA-565x-2c8m-578w"],
            advisory_fixed_versions=["2.6.3"],
        )
        assert "src/urllib3/connectionpool.py" in record.changed_files
        assert "test/test_poolmanager.py" in record.regression_tests

    def test_does_not_invent_fixed_versions_without_evidence(self) -> None:
        record = _normalize_fixture(
            "github_commit_version_api.json",
            advisory_ids=["CVE-2023-45803"],
        )
        assert record.fixed_versions == []

    def test_rejects_wrong_repository(self) -> None:
        payload = _load_commit("github_commit_version_api.json")
        assert isinstance(payload, dict)
        with pytest.raises(PatchNormalizationError, match="does not match"):
            normalize_github_commit(
                payload,
                provenance=_provenance(),
                advisory_ids=["CVE-2023-45803"],
                package=PACKAGE,
                owner="evil",
                repo="urllib3",
            )


class TestPatchInventoryAndExport:
    def test_build_inventory_reports_unresolved_refs(self) -> None:
        inventory = build_patch_inventory(
            package=PACKAGE,
            records=[
                _normalize_fixture(
                    "github_commit_version_api.json",
                    advisory_ids=["CVE-2023-45803"],
                )
            ],
            unresolved_refs=[
                UnresolvedPatchRef(
                    commit_sha="deadbeef" * 5,
                    reason="commit not found in fixture corpus",
                    advisory_ids=("CVE-2099-0001",),
                )
            ],
        )
        assert inventory.record_count == 1
        assert len(inventory.unresolved_refs) == 1
        assert inventory.unresolved_refs[0].commit_sha == "deadbeef" * 5

    def test_export_three_patch_records_is_deterministic(self, tmp_path: Path) -> None:
        records = [
            _normalize_fixture(
                "github_commit_version_api.json",
                advisory_ids=["CVE-2023-45803"],
                advisory_fixed_versions=["2.0.7"],
            ),
            _normalize_fixture(
                "github_commit_version_api_config.json",
                advisory_ids=["GHSA-q69q-g6gr-6q4p"],
                advisory_fixed_versions=["1.26.18"],
            ),
            _normalize_fixture(
                "github_commit_version_api_dataflow.json",
                advisory_ids=["GHSA-565x-2c8m-578w"],
                advisory_fixed_versions=["2.6.3"],
            ),
        ]
        inventory = build_patch_inventory(package=PACKAGE, records=records)
        assert inventory.record_count == 3

        first = export_patch_inventory(inventory, tmp_path / "first")
        second = export_patch_inventory(inventory, tmp_path / "second")
        assert first.path.name == second.path.name == "patches.jsonl"
        assert first.path.read_bytes() == second.path.read_bytes()
        assert first.sha256 == second.sha256
        assert first.record_count == 3
        assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256

        schema = build_json_schemas()["patch.schema.json"]
        validator = Draft202012Validator(schema)
        shas: list[str] = []
        for line in first.path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            validator.validate(payload)
            shas.append(payload["commit_sha"])
        assert len(shas) == 3
        assert shas == sorted(shas)

    def test_normalize_github_commit_response(self) -> None:
        body = (FIXTURES / "github_commit_version_api.json").read_bytes()
        response = RetrievedResponse(
            status_code=200,
            url=(
                "https://api.github.com/repos/urllib3/urllib3/commits/"
                "a1b2c3d4e5f6789012345678901234567890abcd"
            ),
            headers={"content-type": "application/json"},
            content=body,
            retrieved_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
            body_sha256=hashlib.sha256(body).hexdigest(),
            cache_key="e" * 64,
            from_cache=False,
            attempts=1,
        )
        from crawler.normalizers.patches import normalize_github_commit_response

        record = normalize_github_commit_response(
            response,
            advisory_ids=["CVE-2023-45803"],
            package=PACKAGE,
            owner="urllib3",
            repo="urllib3",
            advisory_fixed_versions=["2.0.7"],
        )
        assert record.commit_sha == "a1b2c3d4e5f6789012345678901234567890abcd"
