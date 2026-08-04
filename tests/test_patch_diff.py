"""Offline tests for unified diff and commit patch extraction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from crawler.extractors.patch_diff import (
    PatchDiffExtractionError,
    extract_patch_diff_evidence,
    extract_patch_diff_from_commit,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestExtractPatchDiffEvidence:
    def test_extracts_changed_files_and_symbols(self) -> None:
        files = [
            {
                "filename": "src/urllib3/response.py",
                "patch": (
                    "@@ -1,3 +1,4 @@\n"
                    " class HTTPResponse:\n"
                    "     def drain_conn(self):\n"
                    "+        if self._fp is None:\n"
                    "+            return\n"
                ),
            }
        ]
        evidence = extract_patch_diff_evidence(files)
        assert evidence.changed_files == ("src/urllib3/response.py",)
        assert "HTTPResponse" in evidence.changed_symbols
        assert "drain_conn" in evidence.changed_symbols
        assert any("if self._fp is None" in guard for guard in evidence.added_guards)

    def test_detects_regression_test_paths(self) -> None:
        files = [
            {
                "filename": "test/test_response.py",
                "patch": (
                    "@@ -1,1 +1,5 @@\n"
                    "+def test_drain_conn_noop_when_fp_missing():\n"
                    "+    pass\n"
                ),
            }
        ]
        evidence = extract_patch_diff_evidence(files)
        assert evidence.regression_tests == ("test/test_response.py",)
        assert "test_drain_conn_noop_when_fp_missing" in evidence.changed_symbols

    def test_rejects_unsafe_filename(self) -> None:
        with pytest.raises(PatchDiffExtractionError, match="unsafe changed filename"):
            extract_patch_diff_evidence([{"filename": "../evil.py", "patch": ""}])


class TestExtractPatchDiffFromCommit:
    def test_version_api_fixture(self) -> None:
        payload = json.loads(
            (FIXTURES / "github_commit_version_api.json").read_text("utf-8")
        )
        evidence = extract_patch_diff_from_commit(payload)
        assert "src/urllib3/response.py" in evidence.changed_files
        assert "test/test_response.py" in evidence.regression_tests
        assert "drain_conn" in evidence.changed_symbols

    def test_version_api_configuration_fixture(self) -> None:
        payload = json.loads(
            (FIXTURES / "github_commit_version_api_config.json").read_text("utf-8")
        )
        evidence = extract_patch_diff_from_commit(payload)
        assert "src/urllib3/util/ssl_.py" in evidence.changed_files
        assert any("CERT_NONE" in guard for guard in evidence.added_guards)

    def test_version_api_dataflow_fixture(self) -> None:
        payload = json.loads(
            (FIXTURES / "github_commit_version_api_dataflow.json").read_text("utf-8")
        )
        evidence = extract_patch_diff_from_commit(payload)
        assert "src/urllib3/connectionpool.py" in evidence.changed_files
        assert any("redirect URL" in guard for guard in evidence.added_guards)

    def test_missing_files_returns_empty_evidence(self) -> None:
        evidence = extract_patch_diff_from_commit({"sha": "a" * 40})
        assert evidence.changed_files == ()

    def test_invalid_files_type_raises(self) -> None:
        with pytest.raises(PatchDiffExtractionError, match="must be a list"):
            extract_patch_diff_from_commit({"files": "bad"})
