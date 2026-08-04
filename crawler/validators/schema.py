"""JSON Schema validation for normalized inventory records."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from crawler.exporters.schemas import build_json_schemas
from crawler.validators.findings import ValidationFinding

_RECORD_TYPE_TO_SCHEMA: dict[str, str] = {
    "version": "version.schema.json",
    "advisory": "advisory.schema.json",
    "patch": "patch.schema.json",
    "security_pattern": "security_pattern.schema.json",
    "kb_document": "kb_document.schema.json",
}


def _validator_for_record_type(record_type: str) -> Draft202012Validator | None:
    schema_name = _RECORD_TYPE_TO_SCHEMA.get(record_type)
    if schema_name is None:
        return None
    schema = build_json_schemas()[schema_name]
    return Draft202012Validator(schema)


def validate_record_schema(
    payload: Mapping[str, Any],
    *,
    record_id: str | None = None,
) -> list[ValidationFinding]:
    """Validate one serialized record against its JSON Schema."""
    resolved_id = record_id or str(payload.get("record_id", "unknown"))
    record_type = payload.get("record_type")
    if not isinstance(record_type, str):
        return [
            ValidationFinding(
                record_id=resolved_id,
                check="schema",
                reason="record_type is missing or not a string",
            )
        ]

    validator = _validator_for_record_type(record_type)
    if validator is None:
        return [
            ValidationFinding(
                record_id=resolved_id,
                check="schema",
                reason=f"unsupported record_type for schema validation: {record_type}",
            )
        ]

    findings: list[ValidationFinding] = []
    for error in sorted(validator.iter_errors(dict(payload)), key=str):
        path = ".".join(str(part) for part in error.absolute_path)
        location = f" at {path}" if path else ""
        findings.append(
            ValidationFinding(
                record_id=resolved_id,
                check="schema",
                reason=f"{error.message}{location}",
            )
        )
    return findings


def validate_records_schema(
    payloads: Sequence[Mapping[str, Any]],
) -> list[ValidationFinding]:
    """Validate many serialized records and return all schema findings."""
    findings: list[ValidationFinding] = []
    for payload in payloads:
        findings.extend(validate_record_schema(payload))
    return findings


__all__ = ["validate_record_schema", "validate_records_schema"]
