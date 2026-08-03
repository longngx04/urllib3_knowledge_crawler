"""Deterministic JSON Schema generation for Phase 1 models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from pydantic import BaseModel

from crawler.models import (
    AdvisoryRecord,
    KBDocumentRecord,
    PatchRecord,
    ProvenanceRecord,
    SecurityPatternRecord,
    VersionRecord,
)

SCHEMA_MODELS: Final[dict[str, type[BaseModel]]] = {
    "advisory.schema.json": AdvisoryRecord,
    "kb_document.schema.json": KBDocumentRecord,
    "patch.schema.json": PatchRecord,
    "provenance.schema.json": ProvenanceRecord,
    "security_pattern.schema.json": SecurityPatternRecord,
    "version.schema.json": VersionRecord,
}
_SCHEMA_BASE_ID = "urn:urllib3-knowledge-crawler:schema:1.0"


def build_json_schemas() -> dict[str, dict[str, object]]:
    """Build all public schemas from the executable Pydantic contracts."""
    schemas: dict[str, dict[str, object]] = {}
    for filename, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"{_SCHEMA_BASE_ID}:{filename.removesuffix('.schema.json')}"
        schemas[filename] = schema
    return schemas


def schema_json(schema: dict[str, object]) -> str:
    """Serialize a schema in the checked-in canonical format."""
    return json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def export_json_schemas(output_directory: Path) -> dict[str, Path]:
    """Write all public schemas and return their paths by schema filename."""
    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        raise NotADirectoryError(output_directory)

    written: dict[str, Path] = {}
    for filename, schema in build_json_schemas().items():
        output_path = output_directory / filename
        output_path.write_text(schema_json(schema), encoding="utf-8")
        written[filename] = output_path
    return written


__all__ = [
    "SCHEMA_MODELS",
    "build_json_schemas",
    "export_json_schemas",
    "schema_json",
]
