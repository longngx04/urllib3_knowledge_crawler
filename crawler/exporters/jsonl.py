"""Atomic deterministic JSONL export for normalized version inventories."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from crawler.normalizers.versions import VersionInventory
from crawler.validators.versions import validate_version_inventory


class VersionExportError(OSError):
    """Raised when a version inventory cannot be exported safely."""


@dataclass(frozen=True, slots=True)
class VersionExportResult:
    """Observable metadata for one deterministic versions.jsonl export."""

    path: Path
    sha256: str
    record_count: int


def _jsonl_bytes(inventory: VersionInventory) -> bytes:
    records = validate_version_inventory(inventory.records, inventory.package)
    lines = [
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for record in records
    ]
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def export_version_inventory(
    inventory: VersionInventory, output_directory: Path
) -> VersionExportResult:
    """Atomically write a validated inventory to fixed ``versions.jsonl``."""
    if output_directory.is_symlink():
        raise VersionExportError("output directory must not be a symlink")
    try:
        output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise VersionExportError("cannot create version output directory") from error
    if not output_directory.is_dir():
        raise VersionExportError("version output path must be a directory")

    output_path = output_directory / "versions.jsonl"
    if output_path.is_symlink():
        raise VersionExportError("versions.jsonl must not be a symlink")
    payload = _jsonl_bytes(inventory)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output_directory, prefix=".versions.", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(payload)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    except OSError as error:
        raise VersionExportError("cannot atomically write versions.jsonl") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return VersionExportResult(
        path=output_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=len(inventory.records),
    )


__all__ = ["VersionExportError", "VersionExportResult", "export_version_inventory"]
