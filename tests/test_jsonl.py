"""Deterministic and safe JSONL export tests for version inventories."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crawler.exporters.jsonl import VersionExportError, export_version_inventory
from crawler.exporters.schemas import build_json_schemas
from crawler.models import PackageRecord
from crawler.normalizers.versions import VersionInventory, normalize_pypi_versions
from crawler.utils.http import RetrievedResponse

FIXTURE = Path(__file__).parent / "fixtures" / "pypi_project.json"


def _inventory() -> VersionInventory:
    body = FIXTURE.read_bytes()
    response = RetrievedResponse(
        status_code=200,
        url="https://pypi.org/pypi/urllib3/json",
        headers={"content-type": "application/json"},
        content=body,
        retrieved_at=datetime(2026, 8, 4, 9, 0, tzinfo=UTC),
        body_sha256=hashlib.sha256(body).hexdigest(),
        cache_key="b" * 64,
        from_cache=False,
        attempts=1,
    )
    package = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")
    return normalize_pypi_versions(response, package)


def test_export_is_byte_deterministic_and_each_line_is_schema_valid(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    first = export_version_inventory(inventory, tmp_path / "first")
    second = export_version_inventory(inventory, tmp_path / "second")

    assert first.path.name == second.path.name == "versions.jsonl"
    assert first.path.read_bytes() == second.path.read_bytes()
    assert first.sha256 == second.sha256
    assert first.record_count == second.record_count == 5
    assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256

    lines = first.path.read_text(encoding="utf-8").splitlines()
    schema = build_json_schemas()["version.schema.json"]
    validator = Draft202012Validator(schema)
    versions: list[str] = []
    for line in lines:
        payload = json.loads(line)
        validator.validate(payload)
        versions.append(payload["normalized_version"])
    assert versions == ["1.26.18", "2.0.0a1", "2.1.0", "2.2.0", "3.0.0"]


def test_export_rejects_symlink_output_paths(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    symlink_directory = tmp_path / "linked"
    symlink_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(VersionExportError, match="must not be a symlink"):
        export_version_inventory(_inventory(), symlink_directory)
