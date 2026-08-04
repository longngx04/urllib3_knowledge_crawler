"""Shared validation finding and result types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """One auditable validation problem tied to a normalized record."""

    record_id: str
    reason: str
    check: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Aggregate outcome for one inventory validation pass."""

    findings: tuple[ValidationFinding, ...]

    @property
    def error_count(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> bool:
        return not self.findings


class PipelineValidationError(ValueError):
    """Raised in strict mode when validation findings are present."""

    def __init__(self, findings: tuple[ValidationFinding, ...]) -> None:
        self.findings = findings
        count = len(findings)
        super().__init__(f"pipeline validation failed with {count} finding(s)")


__all__ = ["PipelineValidationError", "ValidationFinding", "ValidationResult"]
