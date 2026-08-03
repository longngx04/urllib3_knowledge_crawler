"""Tests for strict, deterministic Phase 1 domain contracts."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ValidationError

from crawler.models import (
    Confidence,
    ProvenanceRecord,
    VersionEvent,
    VersionRange,
)
from crawler.utils.hashing import stable_record_id


def test_every_model_serializes_as_json(example_records: dict[str, BaseModel]) -> None:
    for record in example_records.values():
        payload = record.model_dump(mode="json")
        assert json.loads(json.dumps(payload, ensure_ascii=False)) == payload


def test_set_like_lists_are_sorted_but_sequences_are_preserved(
    example_records: dict[str, BaseModel],
) -> None:
    advisory = example_records["advisory.schema.json"]
    pattern = example_records["security_pattern.schema.json"]

    advisory_payload = advisory.model_dump(mode="json")
    pattern_payload = pattern.model_dump(mode="json")
    assert advisory_payload["affected_versions"] == ["2.0.0", "2.1.0"]
    assert pattern_payload["vulnerable_usage"]["api_sequence"] == [
        "PoolManager",
        "request",
    ]
    assert pattern_payload["vulnerable_usage"]["required_dataflow"] == [
        "user_input",
        "url",
        "PoolManager.request",
    ]


def test_unknown_scalars_remain_null_and_empty_collections_remain_empty(
    example_records: dict[str, BaseModel],
) -> None:
    version = example_records["version.schema.json"].model_dump(mode="json")
    advisory = example_records["advisory.schema.json"].model_dump(mode="json")

    assert version["yanked_reason"] is None
    assert version["support_branch"] is None
    assert advisory["detailed_impact"] is None
    assert advisory["workarounds"] == []


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Confidence(score=0.5, rationale=[], invented_fact="unsafe")


def test_provenance_requires_aware_timestamp_and_valid_digest() -> None:
    with pytest.raises(ValidationError):
        ProvenanceRecord(
            source_type="pypi",
            source_id="urllib3",
            retrieved_at=datetime(2026, 8, 3),
            raw_sha256="not-a-digest",
            extractor_version="0.1.0",
        )


def test_version_event_requires_exactly_one_boundary() -> None:
    with pytest.raises(ValidationError, match="exactly one boundary"):
        VersionEvent(introduced="2.0", fixed="2.1")


def test_versions_use_pep440_normalization_and_ordering() -> None:
    version_range = VersionRange(
        resolved=["2.0rc1", "1.10", "1.9", "2.0.0", "2.0"],
        fixed_versions=[],
    )
    assert version_range.resolved == ["1.9", "1.10", "2.0rc1", "2.0.0"]

    with pytest.raises(ValidationError, match="invalid PEP 440 version"):
        VersionRange(resolved=["not a version"])


def test_stable_record_id_ignores_mapping_and_set_order() -> None:
    first = stable_record_id(
        "advisory",
        {
            "canonical": "GHSA-example",
            "aliases": {"CVE-2099-0001", "PYSEC-2099-1"},
        },
    )
    second = stable_record_id(
        "advisory",
        {
            "aliases": {"PYSEC-2099-1", "CVE-2099-0001"},
            "canonical": "GHSA-example",
        },
    )
    assert first == second
    assert first.startswith("advisory:")
    assert len(first) == len("advisory:") + 64


@pytest.mark.parametrize(
    ("record_type", "identity", "error"),
    [
        ("Advisory", {}, ValueError),
        ("advisory", {"score": float("nan")}, ValueError),
        ("advisory", {"seen": datetime(2026, 8, 3)}, ValueError),
        ("advisory", {"unsupported": object()}, TypeError),
    ],
)
def test_stable_record_id_rejects_ambiguous_input(
    record_type: str, identity: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        stable_record_id(record_type, identity)


def test_stable_record_id_accepts_aware_timestamp() -> None:
    identifier = stable_record_id(
        "version",
        {"released_at": datetime(2026, 8, 3, tzinfo=UTC)},
    )
    assert identifier.startswith("version:")
