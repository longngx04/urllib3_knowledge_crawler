"""Fixture tests for PyPI version normalization and semantic validation."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crawler.models import PackageRecord
from crawler.normalizers.versions import (
    PyPIDataError,
    VersionNormalizationConflictError,
    normalize_pypi_versions,
)
from crawler.utils.http import RetrievedResponse
from crawler.validators.versions import (
    VersionInventoryValidationError,
    validate_version_inventory,
)

FIXTURE = Path(__file__).parent / "fixtures" / "pypi_project.json"


def _package() -> PackageRecord:
    return PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")


def _response(content: bytes | None = None) -> RetrievedResponse:
    body = FIXTURE.read_bytes() if content is None else content
    return RetrievedResponse(
        status_code=200,
        url="https://pypi.org/pypi/urllib3/json",
        headers={"content-type": "application/json"},
        content=body,
        retrieved_at=datetime(2026, 8, 4, 9, 0, tzinfo=UTC),
        body_sha256=hashlib.sha256(body).hexdigest(),
        cache_key="a" * 64,
        from_cache=False,
        attempts=1,
    )


def _payload() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_normalizer_preserves_release_and_artifact_evidence() -> None:
    inventory = normalize_pypi_versions(_response(), _package())

    assert [record.normalized_version for record in inventory.records] == [
        "1.26.18",
        "2.0.0a1",
        "2.1.0",
        "2.2.0",
        "3.0.0",
    ]
    assert inventory.unparsable_versions == ("not-a-version",)
    assert inventory.stats.total_versions == 5
    assert inventory.stats.total_prereleases == 1
    assert inventory.stats.total_yanked_versions == 1
    assert inventory.stats.total_artifacts == 6
    assert inventory.stats.total_unparsable_versions == 1

    prerelease = inventory.records[1]
    yanked = inventory.records[2]
    mixed_requirement = inventory.records[3]
    empty = inventory.records[4]
    assert prerelease.is_prerelease is True
    assert yanked.is_yanked is True
    assert yanked.yanked_reason == "synthetic fixture reason"
    assert yanked.requires_python == ">=3.8"
    assert yanked.release_date == datetime(2023, 11, 13, 12, 0, tzinfo=UTC)
    assert len(yanked.artifacts) == 2
    assert all(artifact.is_yanked for artifact in yanked.artifacts)
    assert mixed_requirement.requires_python is None
    assert {artifact.requires_python for artifact in mixed_requirement.artifacts} == {
        ">=3.8",
        ">=3.9",
    }
    assert empty.release_date is None
    assert empty.artifacts == []


def test_normalizer_attaches_exact_raw_provenance() -> None:
    response = _response()
    inventory = normalize_pypi_versions(response, _package())

    for record in inventory.records:
        assert len(record.provenance) == 1
        provenance = record.provenance[0]
        assert provenance.source_type == "pypi"
        assert provenance.source_id == response.url
        assert provenance.raw_sha256 == response.body_sha256
        assert provenance.retrieved_at == response.retrieved_at


def test_normalizer_rejects_invalid_json_and_wrong_project() -> None:
    with pytest.raises(PyPIDataError, match="valid UTF-8 JSON"):
        normalize_pypi_versions(_response(b"not-json"), _package())

    payload = _payload()
    info = payload["info"]
    assert isinstance(info, dict)
    info["name"] = "other-project"
    with pytest.raises(PyPIDataError, match="project mismatch"):
        normalize_pypi_versions(_response(json.dumps(payload).encode()), _package())


def test_normalizer_rejects_semantically_duplicate_versions() -> None:
    payload = _payload()
    releases = payload["releases"]
    assert isinstance(releases, dict)
    releases["2.2"] = []

    with pytest.raises(VersionNormalizationConflictError, match="both normalize"):
        normalize_pypi_versions(_response(json.dumps(payload).encode()), _package())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("filename", "other-2.1.0.tar.gz"), "expected project"),
        (("sha256", "invalid"), "invalid artifact metadata"),
        (("upload_time_iso_8601", "yesterday"), "valid ISO-8601"),
        (
            ("url", "https://example.com/urllib3-2.1.0-py3-none-any.whl"),
            "unsafe PyPI artifact URL",
        ),
    ],
)
def test_normalizer_rejects_unsafe_or_malformed_artifacts(
    mutation: tuple[str, str], message: str
) -> None:
    payload = _payload()
    releases = payload["releases"]
    assert isinstance(releases, dict)
    artifacts = releases["2.1.0"]
    assert isinstance(artifacts, list)
    artifact = artifacts[0]
    assert isinstance(artifact, dict)
    key, value = mutation
    if key == "sha256":
        digests = artifact["digests"]
        assert isinstance(digests, dict)
        digests[key] = value
    else:
        artifact[key] = value

    with pytest.raises(PyPIDataError, match=message):
        normalize_pypi_versions(_response(json.dumps(payload).encode()), _package())


def test_validator_rejects_unsorted_and_inconsistent_records() -> None:
    inventory = normalize_pypi_versions(_response(), _package())
    with pytest.raises(VersionInventoryValidationError, match="not PEP 440 sorted"):
        validate_version_inventory(reversed(inventory.records), _package())

    first = inventory.records[0].model_copy(update={"is_prerelease": True})
    broken = (first, *inventory.records[1:])
    with pytest.raises(VersionInventoryValidationError, match="prerelease flag"):
        validate_version_inventory(broken, _package())
