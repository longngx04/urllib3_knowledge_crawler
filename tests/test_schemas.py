"""Executable agreement checks for Pydantic models and checked-in schemas."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from pydantic import BaseModel

from crawler.exporters.schemas import (
    SCHEMA_MODELS,
    build_json_schemas,
    export_json_schemas,
    schema_json,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = PROJECT_ROOT / "schemas"


def test_checked_in_schemas_are_current_and_valid() -> None:
    generated = build_json_schemas()

    assert set(generated) == set(SCHEMA_MODELS)
    for filename, schema in generated.items():
        Draft202012Validator.check_schema(schema)
        checked_in = (SCHEMA_DIRECTORY / filename).read_text(encoding="utf-8")
        assert checked_in == schema_json(schema)


def test_every_model_validates_against_matching_schema(
    example_records: dict[str, BaseModel],
) -> None:
    schemas = build_json_schemas()

    assert set(example_records) == set(schemas)
    for filename, record in example_records.items():
        Draft202012Validator(schemas[filename]).validate(record.model_dump(mode="json"))


def test_schema_export_is_byte_deterministic(tmp_path: Path) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first = export_json_schemas(first_directory)
    second = export_json_schemas(second_directory)

    assert set(first) == set(second) == set(SCHEMA_MODELS)
    for filename in SCHEMA_MODELS:
        assert first[filename].read_bytes() == second[filename].read_bytes()
        assert json.loads(first[filename].read_text(encoding="utf-8"))["$schema"] == (
            "https://json-schema.org/draft/2020-12/schema"
        )
