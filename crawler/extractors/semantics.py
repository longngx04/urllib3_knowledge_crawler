"""Rule-based security-semantic extraction from advisory and patch evidence."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from crawler.models import (
    AdvisoryRecord,
    DetectionType,
    EvidenceRecord,
    PatchRecord,
    VersionRange,
)

_ARGUMENT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bCERT_NONE\b"), "cert_reqs=ssl.CERT_NONE"),
    (re.compile(r"\bcert_reqs\b"), "cert_reqs"),
    (re.compile(r"\bredirect\s*=\s*True\b", re.I), "redirect=True"),
    (re.compile(r"\bfollow_redirects\b"), "follow_redirects"),
    (re.compile(r"\bassert_hostname\b"), "assert_hostname"),
    (re.compile(r"\bpreload_content\b"), "preload_content"),
)

_DATAFLOW_KEYWORDS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"\bredirect\b|\bLocation\b|\blocation header\b", re.I),
        "redirect_location_header",
        "redirect handler",
    ),
    (
        re.compile(r"\battacker[- ]controlled\b|\buntrusted\b|\buser[- ]input\b", re.I),
        "untrusted_input",
        "vulnerable API",
    ),
    (
        re.compile(r"\bcookie\b|\bCookie header\b", re.I),
        "cookie_header",
        "proxy destination",
    ),
    (
        re.compile(r"\brequest body\b|\bHTTP body\b", re.I),
        "request_body",
        "redirect follow-up request",
    ),
)

_IMPACT_KEYWORDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bSSRF\b|server[- ]side request forgery", re.I), "ssrf"),
    (re.compile(r"\bRCE\b|remote code execution", re.I), "rce"),
    (
        re.compile(
            r"\bdata exposure\b|\binformation disclosure\b|\bleak\b",
            re.I,
        ),
        "data_exposure",
    ),
    (re.compile(r"\bdenial of service\b|\bDoS\b", re.I), "availability"),
    (re.compile(r"\bintegrity\b", re.I), "integrity"),
    (re.compile(r"\bconfidentiality\b|\bdisclosure\b", re.I), "confidentiality"),
)

_CLASS_IN_PATCH = re.compile(r"class\s+([A-Za-z_]\w*)")
_DEF_IN_PATCH = re.compile(r"def\s+([A-Za-z_]\w*)")
_FILE_MODULE_PATTERN = re.compile(r"(?:^|/)(?:src/)?urllib3/(.+)\.py$")

_SAST_COMPONENT_COUNT = 8


class SemanticExtractionError(ValueError):
    """Raised when advisory evidence cannot support semantic extraction."""


@dataclass(frozen=True, slots=True)
class SemanticExtraction:
    """Structured SAST-oriented fields extracted from authoritative evidence."""

    version: VersionRange
    modules: tuple[str, ...]
    classes: tuple[str, ...]
    symbols: tuple[str, ...]
    arguments: tuple[str, ...]
    api_sequence: tuple[str, ...]
    preconditions: tuple[str, ...]
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    required_dataflow: tuple[str, ...]
    negative_conditions: tuple[str, ...]
    impact_notes: tuple[str, ...]
    impact_confidentiality: str | None
    impact_integrity: str | None
    impact_availability: str | None
    impact_ssrf: bool | None
    impact_rce: bool | None
    impact_data_exposure: bool | None
    remediation_upgrade: str | None
    remediation_workarounds: tuple[str, ...]
    remediation_alternatives: tuple[str, ...]
    detection_type: DetectionType
    confidence_score: float
    confidence_rationale: tuple[str, ...]
    sast_usefulness_score: float
    patch_evidence: tuple[EvidenceRecord, ...]
    test_evidence: tuple[EvidenceRecord, ...]


def _sorted_unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({item.strip() for item in values if item.strip()}))


def _module_from_path(path: str) -> str | None:
    match = _FILE_MODULE_PATTERN.search(path.replace("\\", "/"))
    if match is None:
        return None
    return "urllib3." + match.group(1).replace("/", ".")


def _qualify_symbols(
    changed_files: Sequence[str],
    changed_symbols: Sequence[str],
    patch_texts: Sequence[str],
) -> tuple[str, ...]:
    """Qualify bare symbol names using patch context and file paths."""
    classes_in_patches: set[str] = set()
    defs_in_patches: set[str] = set()
    for patch in patch_texts:
        classes_in_patches.update(_CLASS_IN_PATCH.findall(patch))
        defs_in_patches.update(_DEF_IN_PATCH.findall(patch))

    modules = [_module_from_path(path) for path in changed_files]
    modules = [item for item in modules if item is not None]

    qualified: set[str] = set()
    for symbol in changed_symbols:
        if "." in symbol:
            qualified.add(symbol)
            continue
        owner_class = next((name for name in classes_in_patches if name), None)
        if owner_class is not None and symbol in defs_in_patches:
            qualified.add(f"{owner_class}.{symbol}")
            continue
        if modules:
            qualified.add(f"{modules[0]}.{symbol}")
        else:
            qualified.add(symbol)
    return tuple(sorted(qualified))


def _collect_patch_texts(patch: PatchRecord | None) -> tuple[str, ...]:
    if patch is None:
        return ()
    return tuple(
        sorted(
            {
                *patch.added_guards,
                *patch.behavioral_differences,
                *patch.changed_symbols,
            }
        )
    )


def _extract_arguments(
    advisory: AdvisoryRecord,
    patch: PatchRecord | None,
    changelog_text: str | None,
) -> tuple[str, ...]:
    corpus_parts = [
        advisory.summary or "",
        advisory.detailed_impact or "",
        *(advisory.workarounds or []),
        changelog_text or "",
    ]
    if patch is not None:
        corpus_parts.extend(patch.added_guards)
        corpus_parts.extend(patch.changed_symbols)
    corpus = "\n".join(corpus_parts)
    found: set[str] = set()
    for pattern, label in _ARGUMENT_PATTERNS:
        if pattern.search(corpus):
            found.add(label)
    return tuple(sorted(found))


def _extract_dataflow(
    advisory: AdvisoryRecord,
    symbols: Sequence[str],
    changelog_text: str | None,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    corpus = "\n".join(
        [
            advisory.summary or "",
            advisory.detailed_impact or "",
            changelog_text or "",
        ]
    )
    sources: set[str] = set()
    sinks: set[str] = set()
    flows: set[str] = set()
    for pattern, source, sink in _DATAFLOW_KEYWORDS:
        if pattern.search(corpus):
            sources.add(source)
            sinks.add(sink)
            flows.add(f"{source}->{sink}")
    for symbol in symbols:
        lowered = symbol.lower()
        if "redirect" in lowered or "location" in lowered:
            sources.add("redirect_location_header")
            sinks.add(symbol)
            flows.add(f"redirect_location_header->{symbol}")
    return (
        tuple(sorted(sources)),
        tuple(sorted(sinks)),
        tuple(sorted(flows)),
    )


def _extract_preconditions(
    advisory: AdvisoryRecord,
    patch: PatchRecord | None,
    symbols: Sequence[str],
) -> tuple[str, ...]:
    preconditions: set[str] = set()
    if symbols:
        preconditions.add(f"vulnerable API invoked: {symbols[0]}")
    summary = advisory.summary or ""
    details = advisory.detailed_impact or ""
    for text in (summary, details):
        lowered = text.lower()
        if "redirect" in lowered:
            preconditions.add("application follows HTTP redirects")
        if "cert_none" in lowered or "cert_none" in lowered.replace("-", "_"):
            preconditions.add("HTTPS connection uses cert_reqs=ssl.CERT_NONE")
        if "proxy" in lowered:
            preconditions.add("ProxyManager or HTTP(S) proxy in use")
    if patch is not None:
        for guard in patch.added_guards:
            lowered = guard.lower()
            if "cert_none" in lowered:
                preconditions.add(
                    "create_urllib3_context called with cert_reqs=ssl.CERT_NONE"
                )
            if "redirect url" in lowered or "protocol-relative" in lowered:
                preconditions.add(
                    "redirect Location header reaches redirect validation"
                )
            if "_fp is none" in lowered:
                preconditions.add(
                    "HTTPResponse.drain_conn called with active body reader"
                )
    return tuple(sorted(preconditions))


def _extract_negative_conditions(
    patch: PatchRecord | None,
    arguments: Sequence[str],
) -> tuple[str, ...]:
    negatives: set[str] = set()
    if patch is not None:
        for guard in patch.added_guards:
            lowered = guard.lower()
            if "_fp is none" in lowered:
                negatives.add("HTTPResponse._fp is None (no body to drain)")
            if "cert_none is not permitted" in lowered:
                negatives.add("cert_reqs is not ssl.CERT_NONE")
            if "protocol-relative redirects are not allowed" in lowered:
                negatives.add("redirect URL is not protocol-relative")
            if "redirect url must not be none" in lowered:
                negatives.add("redirect URL is a non-null string")
    if "cert_reqs=ssl.CERT_NONE" in arguments:
        negatives.add("cert_reqs defaults to ssl.CERT_REQUIRED")
    if not negatives and patch is not None and patch.fixed_versions:
        negatives.add(
            f"installed version is at or above fixed release {patch.fixed_versions[-1]}"
        )
    return tuple(sorted(negatives))


def _extract_impact(
    advisory: AdvisoryRecord,
) -> tuple[
    tuple[str, ...],
    str | None,
    str | None,
    str | None,
    bool | None,
    bool | None,
    bool | None,
]:
    corpus = "\n".join(
        [
            advisory.summary or "",
            advisory.detailed_impact or "",
            *advisory.cwe,
        ]
    )
    notes: set[str] = set()
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None
    ssrf: bool | None = None
    rce: bool | None = None
    data_exposure: bool | None = None

    if advisory.summary:
        notes.add(advisory.summary)
    if advisory.detailed_impact:
        notes.add(advisory.detailed_impact)

    for pattern, label in _IMPACT_KEYWORDS:
        if not pattern.search(corpus):
            continue
        if label == "ssrf":
            ssrf = True
        elif label == "rce":
            rce = True
        elif label == "data_exposure":
            data_exposure = True
        elif label == "availability":
            availability = "source-reported availability impact"
        elif label == "integrity":
            integrity = "source-reported integrity impact"
        elif label == "confidentiality":
            confidentiality = "source-reported confidentiality impact"

    if advisory.severity and not notes:
        notes.add(f"severity: {advisory.severity}")

    return (
        tuple(sorted(notes)),
        confidentiality,
        integrity,
        availability,
        ssrf,
        rce,
        data_exposure,
    )


def _copy_version_range(advisory: AdvisoryRecord) -> VersionRange:
    """Copy affected-range evidence from the advisory without inventing bounds."""
    if advisory.affected_ranges:
        primary = advisory.affected_ranges[0]
        return VersionRange(
            raw=primary.raw,
            events=list(primary.events),
            resolved=list(primary.resolved or advisory.affected_versions),
            fixed_versions=list(primary.fixed_versions or advisory.fixed_versions),
        )
    if advisory.affected_versions or advisory.fixed_versions:
        return VersionRange(
            raw=None,
            events=[],
            resolved=list(advisory.affected_versions),
            fixed_versions=list(advisory.fixed_versions),
        )
    return VersionRange(raw=None, events=[], resolved=[], fixed_versions=[])


def _build_evidence(
    patch: PatchRecord | None,
) -> tuple[tuple[EvidenceRecord, ...], tuple[EvidenceRecord, ...]]:
    if patch is None:
        return (), ()
    patch_rows = (
        EvidenceRecord(
            evidence_type="commit",
            source_id=patch.commit_sha,
            reference=patch.repository_url,
            notes="patch diff symbols and guards",
        ),
    )
    test_rows = tuple(
        EvidenceRecord(
            evidence_type="regression_test",
            source_id=test_path,
            reference=test_path,
        )
        for test_path in patch.regression_tests
    )
    return patch_rows, test_rows


def compute_sast_usefulness_score(
    *,
    version: VersionRange,
    symbols: Sequence[str],
    preconditions: Sequence[str],
    arguments: Sequence[str],
    negative_conditions: Sequence[str],
    remediation_upgrade: str | None,
    remediation_workarounds: Sequence[str],
    patch_evidence: Sequence[EvidenceRecord],
    test_evidence: Sequence[EvidenceRecord],
) -> float:
    """Score SAST usefulness as available_components / 8 (see project context)."""
    components = 0
    if version.events or version.resolved or version.raw:
        components += 1
    if version.fixed_versions:
        components += 1
    if symbols:
        components += 1
    if preconditions:
        components += 1
    if arguments:
        components += 1
    if negative_conditions:
        components += 1
    if remediation_upgrade or remediation_workarounds:
        components += 1
    if patch_evidence or test_evidence:
        components += 1
    return round(components / _SAST_COMPONENT_COUNT, 4)


def assign_detection_type(
    *,
    symbols: Sequence[str],
    arguments: Sequence[str],
    required_dataflow: Sequence[str],
    sources: Sequence[str],
) -> DetectionType:
    """Assign the coarsest detection class supported by extracted evidence."""
    has_api = bool(symbols)
    has_config = bool(arguments)
    has_dataflow = bool(required_dataflow or sources)
    if has_api and has_config and has_dataflow:
        return DetectionType.VERSION_API_CONFIGURATION_DATAFLOW
    if has_api and has_dataflow:
        return DetectionType.VERSION_API_DATAFLOW
    if has_api and has_config:
        return DetectionType.VERSION_API_CONFIGURATION
    if has_api:
        return DetectionType.VERSION_API
    return DetectionType.VERSION_ONLY


def _confidence_from_evidence(
    advisory: AdvisoryRecord,
    patch: PatchRecord | None,
    *,
    symbols: Sequence[str],
    unsupported: Sequence[str],
) -> tuple[float, tuple[str, ...]]:
    score = advisory.confidence.score
    rationale = list(advisory.confidence.rationale)
    if patch is not None:
        score = min(1.0, score + 0.05)
        rationale.append("patch diff evidence linked")
    if symbols:
        rationale.append("vulnerable symbols extracted from patch paths")
    else:
        unsupported = (
            *unsupported,
            "no vulnerable symbol extracted from patch evidence",
        )
    if not advisory.affected_ranges and not advisory.affected_versions:
        unsupported = (
            *unsupported,
            "affected version range absent on advisory; not inferred",
        )
    for note in unsupported:
        rationale.append(f"unsupported inference: {note}")
    return round(min(score, 1.0), 4), tuple(sorted(set(rationale)))


def extract_security_semantics(
    advisory: AdvisoryRecord,
    *,
    patch: PatchRecord | None = None,
    changelog_text: str | None = None,
) -> SemanticExtraction:
    """Extract SAST-oriented semantics from advisory and optional patch evidence."""
    if advisory.record_type != "advisory":
        raise SemanticExtractionError("expected an AdvisoryRecord")

    version = _copy_version_range(advisory)
    patch_texts = _collect_patch_texts(patch)

    modules: set[str] = set()
    if patch is not None:
        for path in patch.changed_files:
            module = _module_from_path(path)
            if module is not None:
                modules.add(module)

    symbols = _qualify_symbols(
        patch.changed_files if patch is not None else (),
        patch.changed_symbols if patch is not None else (),
        patch_texts,
    )
    classes = _sorted_unique(
        [
            symbol.split(".", 1)[0]
            for symbol in symbols
            if "." in symbol and symbol.split(".", 1)[0][:1].isupper()
        ]
    )
    arguments = _extract_arguments(advisory, patch, changelog_text)
    sources, sinks, required_dataflow = _extract_dataflow(
        advisory, symbols, changelog_text
    )
    preconditions = _extract_preconditions(advisory, patch, symbols)
    negative_conditions = _extract_negative_conditions(patch, arguments)
    (
        impact_notes,
        impact_confidentiality,
        impact_integrity,
        impact_availability,
        impact_ssrf,
        impact_rce,
        impact_data_exposure,
    ) = _extract_impact(advisory)

    fixed_versions = list(version.fixed_versions or advisory.fixed_versions)
    upgrade_guidance: str | None = None
    if fixed_versions:
        upgrade_guidance = f"Upgrade to {fixed_versions[-1]} or later."
    workarounds = _sorted_unique(advisory.workarounds)

    patch_evidence, test_evidence = _build_evidence(patch)

    detection_type = assign_detection_type(
        symbols=symbols,
        arguments=arguments,
        required_dataflow=required_dataflow,
        sources=sources,
    )

    unsupported: list[str] = []
    if not patch:
        unsupported.append(
            "patch evidence unavailable; API usage inferred from advisory text only"
        )
    if not changelog_text:
        unsupported.append("changelog text not supplied")

    confidence_score, confidence_rationale = _confidence_from_evidence(
        advisory,
        patch,
        symbols=symbols,
        unsupported=unsupported,
    )

    api_sequence: tuple[str, ...] = ()
    if classes:
        method = symbols[0].split(".")[-1] if symbols else classes[0]
        api_sequence = (classes[0], method)

    sast_usefulness_score = compute_sast_usefulness_score(
        version=version,
        symbols=symbols,
        preconditions=preconditions,
        arguments=arguments,
        negative_conditions=negative_conditions,
        remediation_upgrade=upgrade_guidance,
        remediation_workarounds=workarounds,
        patch_evidence=patch_evidence,
        test_evidence=test_evidence,
    )

    return SemanticExtraction(
        version=version,
        modules=tuple(sorted(modules)),
        classes=classes,
        symbols=symbols,
        arguments=arguments,
        api_sequence=api_sequence,
        preconditions=preconditions,
        sources=sources,
        sinks=sinks,
        required_dataflow=required_dataflow,
        negative_conditions=negative_conditions,
        impact_notes=impact_notes,
        impact_confidentiality=impact_confidentiality,
        impact_integrity=impact_integrity,
        impact_availability=impact_availability,
        impact_ssrf=impact_ssrf,
        impact_rce=impact_rce,
        impact_data_exposure=impact_data_exposure,
        remediation_upgrade=upgrade_guidance,
        remediation_workarounds=workarounds,
        remediation_alternatives=(),
        detection_type=detection_type,
        confidence_score=confidence_score,
        confidence_rationale=confidence_rationale,
        sast_usefulness_score=sast_usefulness_score,
        patch_evidence=patch_evidence,
        test_evidence=test_evidence,
    )


__all__ = [
    "SemanticExtraction",
    "SemanticExtractionError",
    "assign_detection_type",
    "compute_sast_usefulness_score",
    "extract_security_semantics",
]
