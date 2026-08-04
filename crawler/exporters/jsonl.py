"""Atomic deterministic JSONL export for normalized inventories."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from crawler.normalizers.kb_documents import KBDocumentInventory
from crawler.normalizers.patches import PatchInventory
from crawler.normalizers.patterns import SecurityPatternInventory
from crawler.normalizers.versions import VersionInventory
from crawler.validators.versions import validate_version_inventory


class JsonlExportError(OSError):
    """Raised when a normalized JSONL export cannot be written safely."""


class VersionExportError(JsonlExportError):
    """Raised when a version inventory cannot be exported safely."""


class PatchExportError(JsonlExportError):
    """Raised when a patch inventory cannot be exported safely."""


class SecurityPatternExportError(JsonlExportError):
    """Raised when a security-pattern inventory cannot be exported safely."""


class KBDocumentExportError(JsonlExportError):
    """Raised when a KB document inventory cannot be exported safely."""


@dataclass(frozen=True, slots=True)
class JsonlExportResult:
    """Observable metadata for one deterministic JSONL export."""

    path: Path
    sha256: str
    record_count: int


VersionExportResult = JsonlExportResult


class _JsonlRecord(Protocol):
    def model_dump(self, *, mode: str) -> dict[str, object]: ...


def _jsonl_bytes_from_records(records: tuple[_JsonlRecord, ...]) -> bytes:
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


def _atomic_write_jsonl(
    payload: bytes,
    output_directory: Path,
    filename: str,
    temporary_prefix: str,
    error_context: str,
    error_type: type[JsonlExportError] = JsonlExportError,
) -> Path:
    if output_directory.is_symlink():
        raise error_type("output directory must not be a symlink")
    try:
        output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise error_type(f"cannot create {error_context} output directory") from error
    if not output_directory.is_dir():
        raise error_type(f"{error_context} output path must be a directory")

    output_path = output_directory / filename
    if output_path.is_symlink():
        raise error_type(f"{filename} must not be a symlink")
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output_directory,
            prefix=temporary_prefix,
            suffix=".tmp",
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
        raise error_type(f"cannot atomically write {filename}") from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output_path


def _jsonl_bytes(inventory: VersionInventory) -> bytes:
    records = validate_version_inventory(inventory.records, inventory.package)
    return _jsonl_bytes_from_records(records)


def export_version_inventory(
    inventory: VersionInventory, output_directory: Path
) -> VersionExportResult:
    """Atomically write a validated inventory to fixed ``versions.jsonl``."""
    payload = _jsonl_bytes(inventory)
    output_path = _atomic_write_jsonl(
        payload,
        output_directory,
        "versions.jsonl",
        ".versions.",
        "version",
        VersionExportError,
    )
    return VersionExportResult(
        path=output_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=len(inventory.records),
    )


def export_patch_inventory(
    inventory: PatchInventory, output_directory: Path
) -> JsonlExportResult:
    """Atomically write patch records to fixed ``patches.jsonl``."""
    payload = _jsonl_bytes_from_records(inventory.records)
    output_path = _atomic_write_jsonl(
        payload,
        output_directory,
        "patches.jsonl",
        ".patches.",
        "patch",
        PatchExportError,
    )
    return JsonlExportResult(
        path=output_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=len(inventory.records),
    )


def export_security_pattern_inventory(
    inventory: SecurityPatternInventory, output_directory: Path
) -> JsonlExportResult:
    """Atomically write security patterns to fixed ``security_patterns.jsonl``."""
    payload = _jsonl_bytes_from_records(inventory.records)
    output_path = _atomic_write_jsonl(
        payload,
        output_directory,
        "security_patterns.jsonl",
        ".security_patterns.",
        "security_pattern",
        SecurityPatternExportError,
    )
    return JsonlExportResult(
        path=output_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=len(inventory.records),
    )


def export_kb_document_inventory(
    inventory: KBDocumentInventory, output_directory: Path
) -> JsonlExportResult:
    """Atomically write KB documents to ``kb/documents.jsonl`` under output root."""
    payload = _jsonl_bytes_from_records(inventory.records)
    kb_directory = output_directory / "kb"
    output_path = _atomic_write_jsonl(
        payload,
        kb_directory,
        "documents.jsonl",
        ".kb_documents.",
        "kb_document",
        KBDocumentExportError,
    )
    return JsonlExportResult(
        path=output_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=len(inventory.records),
    )


__all__ = [
    "JsonlExportError",
    "JsonlExportResult",
    "KBDocumentExportError",
    "PatchExportError",
    "SecurityPatternExportError",
    "VersionExportError",
    "VersionExportResult",
    "export_kb_document_inventory",
    "export_patch_inventory",
    "export_security_pattern_inventory",
    "export_version_inventory",
]
