"""Phase 12 deterministic-output tests for the offline fixture pipeline."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from crawler.config import load_crawler_config
from crawler.pipeline import build_pipeline_state, run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "configs" / "urllib3.yaml"
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "pipeline"

DETERMINISTIC_JSONL_OUTPUTS = (
    "normalized/versions.jsonl",
    "normalized/advisories.jsonl",
    "normalized/patches.jsonl",
    "normalized/security_patterns.jsonl",
    "kb/documents.jsonl",
)


def _strip_retrieved_at(value: Any) -> Any:
    """Remove volatile provenance timestamps before content hashing."""
    if isinstance(value, list):
        return [_strip_retrieved_at(item) for item in value]
    if isinstance(value, dict):
        cleaned = {
            key: _strip_retrieved_at(item)
            for key, item in value.items()
            if key != "retrieved_at"
        }
        return cleaned
    return value


def normalized_jsonl_digest(path: Path) -> str:
    """Return a SHA-256 digest of JSONL records with volatile timestamps removed."""
    canonical_lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = _strip_retrieved_at(json.loads(line))
        canonical_lines.append(
            json.dumps(record, sort_keys=True, separators=(",", ":"))
        )
    payload = "\n".join(canonical_lines)
    if canonical_lines:
        payload += "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_offline_pipeline(output_dir: Path) -> Mapping[str, str]:
    config = load_crawler_config(CONFIG_PATH)
    state = build_pipeline_state(
        config,
        output_override=output_dir,
        offline=True,
        fixture_dir=FIXTURE_DIR,
    )
    run_pipeline(state)
    digests: dict[str, str] = {}
    for relative in DETERMINISTIC_JSONL_OUTPUTS:
        path = output_dir / relative
        assert path.is_file(), relative
        digests[relative] = normalized_jsonl_digest(path)
    return digests


def test_offline_fixture_pipeline_is_semantically_deterministic_across_runs(
    tmp_path: Path,
) -> None:
    """Fresh output dirs match after stripping volatile provenance timestamps."""
    first = _run_offline_pipeline(tmp_path / "run-a")
    second = _run_offline_pipeline(tmp_path / "run-b")
    assert first == second
    assert all(digest for digest in first.values())


def test_offline_fixture_pipeline_is_byte_identical_when_cache_is_reused(
    tmp_path: Path,
) -> None:
    """Reusing one output dir replays cached raw bodies with stable timestamps."""
    output_dir = tmp_path / "shared-output"

    def _raw_digests() -> dict[str, str]:
        _run_offline_pipeline(output_dir)
        return {
            relative: hashlib.sha256((output_dir / relative).read_bytes()).hexdigest()
            for relative in DETERMINISTIC_JSONL_OUTPUTS
        }

    assert _raw_digests() == _raw_digests()
