"""Rule-based extraction of patch evidence from GitHub commit file payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_GUARD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\+\s*if\s+.+:"),
    re.compile(r"^\+\s*raise\s+\w"),
    re.compile(r"^\+\s*assert\s+.+"),
)
_PYTHON_SYMBOL_PATTERN = re.compile(
    r"^[+\- ]?\s*(?:async\s+)?(?:(?:def|class)\s+([A-Za-z_]\w*))"
)
_TEST_FILE_PATTERN = re.compile(r"(?:^|/)(?:tests?/)?(?:.*/)?test_[A-Za-z0-9_]+\.py$")


class PatchDiffExtractionError(ValueError):
    """Raised when commit file payloads cannot be safely parsed."""


@dataclass(frozen=True, slots=True)
class PatchDiffEvidence:
    """Structured evidence extracted from one commit's file patches."""

    changed_files: tuple[str, ...]
    changed_symbols: tuple[str, ...]
    added_guards: tuple[str, ...]
    regression_tests: tuple[str, ...]


def _normalize_filename(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."}:
        return None
    if ".." in cleaned or "\x00" in cleaned or cleaned.startswith("/"):
        raise PatchDiffExtractionError(f"unsafe changed filename: {value!r}")
    return cleaned.replace("\\", "/")


def _extract_symbols_from_patch(patch: str) -> set[str]:
    symbols: set[str] = set()
    for line in patch.splitlines():
        match = _PYTHON_SYMBOL_PATTERN.match(line)
        if match:
            symbols.add(match.group(1))
    return symbols


def _extract_guards_from_patch(patch: str) -> set[str]:
    guards: set[str] = set()
    for line in patch.splitlines():
        if not line.startswith("+"):
            continue
        stripped = line[1:].strip()
        if not stripped or stripped.startswith("+++"):
            continue
        for pattern in _GUARD_PATTERNS:
            if pattern.match(line):
                guards.add(stripped)
                break
    return guards


def _is_regression_test_path(path: str) -> bool:
    return _TEST_FILE_PATTERN.search(path) is not None


def extract_patch_diff_evidence(
    files: Sequence[Mapping[str, Any]],
) -> PatchDiffEvidence:
    """Extract changed files, symbols, guards, and tests from commit ``files``."""
    changed_files: set[str] = set()
    changed_symbols: set[str] = set()
    added_guards: set[str] = set()
    regression_tests: set[str] = set()

    for item in files:
        filename = _normalize_filename(item.get("filename"))
        if filename is None:
            continue
        changed_files.add(filename)
        if _is_regression_test_path(filename):
            regression_tests.add(filename)

        patch = item.get("patch")
        if not isinstance(patch, str) or not patch.strip():
            continue
        changed_symbols.update(_extract_symbols_from_patch(patch))
        added_guards.update(_extract_guards_from_patch(patch))

    return PatchDiffEvidence(
        changed_files=tuple(sorted(changed_files)),
        changed_symbols=tuple(sorted(changed_symbols)),
        added_guards=tuple(sorted(added_guards)),
        regression_tests=tuple(sorted(regression_tests)),
    )


def extract_patch_diff_from_commit(payload: dict[str, Any]) -> PatchDiffEvidence:
    """Extract patch evidence from a GitHub commit JSON payload."""
    raw_files = payload.get("files")
    if raw_files is None:
        return PatchDiffEvidence((), (), (), ())
    if not isinstance(raw_files, list):
        raise PatchDiffExtractionError("commit payload 'files' must be a list")
    typed_files = [item for item in raw_files if isinstance(item, dict)]
    return extract_patch_diff_evidence(typed_files)


__all__ = [
    "PatchDiffEvidence",
    "PatchDiffExtractionError",
    "extract_patch_diff_evidence",
    "extract_patch_diff_from_commit",
]
