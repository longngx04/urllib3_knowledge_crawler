"""Orchestrate crawl, normalization, enrichment, validation, and query stages."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from crawler.clients.github import GitHubClient
from crawler.clients.osv import OSVClient
from crawler.clients.pypi import PyPIClient
from crawler.config import CrawlerConfig
from crawler.exporters.jsonl import (
    export_advisory_inventory,
    export_kb_document_inventory,
    export_patch_inventory,
    export_security_pattern_inventory,
    export_version_inventory,
    load_jsonl_records,
)
from crawler.exporters.stats import (
    compute_pipeline_stats,
    export_manifest,
    export_stats,
    sha256_file,
)
from crawler.extractors.changelog import parse_changelog
from crawler.models import (
    AdvisoryRecord,
    KBDocumentRecord,
    PackageRecord,
    PatchRecord,
    SecurityPatternRecord,
    VersionRecord,
)
from crawler.normalizers.advisories import (
    AdvisoryInventory,
    normalize_osv_vulnerability,
)
from crawler.normalizers.kb_documents import (
    KBDocumentInventory,
    generate_kb_documents_from_patterns,
)
from crawler.normalizers.patches import (
    PatchInventory,
    UnresolvedPatchRef,
    build_patch_inventory,
    normalize_github_commit_response,
)
from crawler.normalizers.patterns import (
    SecurityPatternInventory,
    build_security_pattern_inventory,
    normalize_security_pattern,
)
from crawler.normalizers.releases import (
    ReleaseCorrelation,
    TagMapping,
    correlate_releases,
    map_tags_to_versions,
)
from crawler.normalizers.versions import VersionInventory, normalize_pypi_versions
from crawler.resolvers.aliases import AliasConflict, AliasResolver
from crawler.resolvers.ranges import RangeResolutionIssue, resolve_advisory_ranges
from crawler.utils.cache import RawResponseStore
from crawler.utils.http import RetrievalClient, RetrievedResponse
from crawler.validators.findings import PipelineValidationError, ValidationResult
from crawler.validators.pipeline import (
    InventoryBundle,
    ValidationOptions,
    export_validation_errors,
    validate_inventory_bundle,
)

logger = logging.getLogger(__name__)

EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILURE = 1
EXIT_USAGE_ERROR = 2


class PipelineError(RuntimeError):
    """Raised when a pipeline stage cannot complete safely."""


@dataclass(frozen=True, slots=True)
class PipelinePaths:
    """Resolved filesystem layout for one pipeline run."""

    root: Path
    raw: Path
    normalized: Path
    kb: Path


@dataclass
class PipelineState:
    """Mutable in-memory artifacts produced across pipeline stages."""

    config: CrawlerConfig
    paths: PipelinePaths
    offline: bool
    fixture_dir: Path | None
    package: PackageRecord
    version_inventory: VersionInventory | None = None
    advisories: tuple[AdvisoryRecord, ...] = ()
    range_issues: tuple[RangeResolutionIssue, ...] = ()
    alias_conflicts: tuple[AliasConflict, ...] = ()
    patches: PatchInventory | None = None
    patterns: SecurityPatternInventory | None = None
    kb_documents: KBDocumentInventory | None = None
    validation: ValidationResult | None = None
    exports: dict[str, str] = field(default_factory=dict)


def package_record_from_config(config: CrawlerConfig) -> PackageRecord:
    """Build the shared ``PackageRecord`` for one configured package."""
    return PackageRecord(
        name=config.package.name,
        ecosystem=config.package.ecosystem,
        purl=config.package.purl,
    )


def resolve_pipeline_paths(
    config: CrawlerConfig, output_override: Path | None
) -> PipelinePaths:
    """Resolve output directories from config with an optional CLI override."""
    root = output_override or Path(config.output.directory)
    return PipelinePaths(
        root=root,
        raw=root / "raw",
        normalized=root / "normalized",
        kb=root / "kb",
    )


def is_offline_requested(*, offline_flag: bool, fixture_dir: Path | None) -> bool:
    """Return whether the pipeline must avoid live network access."""
    if offline_flag:
        return True
    if fixture_dir is not None:
        return True
    return os.getenv("CRAWLER_OFFLINE", "").strip() in {"1", "true", "yes", "on"}


def _repository_owner_repo(config: CrawlerConfig) -> tuple[str, str]:
    repository = config.package.repository
    if "/" not in repository:
        raise PipelineError(f"invalid repository slug: {repository!r}")
    owner, repo = repository.split("/", maxsplit=1)
    if not owner or not repo:
        raise PipelineError(f"invalid repository slug: {repository!r}")
    return owner, repo


def _fixture_path(fixture_dir: Path, *names: str) -> Path | None:
    for name in names:
        candidate = fixture_dir / name
        if candidate.is_file():
            return candidate
    return None


def _build_fixture_transport(fixture_dir: Path) -> httpx.MockTransport:
    """Serve deterministic fixture payloads for offline crawl and enrich stages."""
    parent = fixture_dir.parent if fixture_dir.name == "pipeline" else fixture_dir

    def _resolve_fixture(request: httpx.Request) -> Path:
        url = str(request.url)
        method = request.method.upper()
        if method == "GET" and url.endswith("/pypi/urllib3/json"):
            path = (
                _fixture_path(fixture_dir, "pypi_project.json")
                or parent / "pypi_project.json"
            )
        elif method == "GET" and "/releases?" in url:
            path = (
                _fixture_path(fixture_dir, "github_releases.json")
                or parent / "github_releases.json"
            )
        elif method == "GET" and "/tags?" in url:
            path = (
                _fixture_path(fixture_dir, "github_tags.json")
                or parent / "github_tags.json"
            )
        elif method == "GET" and "raw.githubusercontent.com" in url:
            path = (
                _fixture_path(fixture_dir, "changelog.rst") or parent / "changelog.rst"
            )
        elif method == "POST" and url.endswith("/v1/query"):
            path = (
                _fixture_path(fixture_dir, "osv_query.json")
                or parent / "osv_query.json"
            )
        elif method == "GET" and "/commits/" in url:
            sha = url.rsplit("/commits/", maxsplit=1)[-1].lower()
            commit_path = fixture_dir / "commits" / f"{sha}.json"
            if commit_path.is_file():
                path = commit_path
            else:
                for candidate in parent.glob("github_commit_*.json"):
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                    if str(payload.get("sha", "")).lower() == sha:
                        path = candidate
                        break
                else:
                    raise AssertionError(f"no fixture commit for SHA {sha}")
        else:
            raise AssertionError(f"unexpected offline request: {method} {url}")
        if not path.is_file():
            raise AssertionError(f"missing fixture for {method} {url}: {path}")
        return path

    def handler(request: httpx.Request) -> httpx.Response:
        path = _resolve_fixture(request)
        content = path.read_bytes()
        content_type = (
            "application/json"
            if path.suffix == ".json"
            else "text/plain; charset=utf-8"
        )
        return httpx.Response(
            200,
            headers={"Content-Type": content_type},
            content=content,
            request=request,
        )

    return httpx.MockTransport(handler)


def _retrieval_client(state: PipelineState) -> RetrievalClient:
    """Build one retrieval client, using fixtures when offline."""
    store = RawResponseStore(state.paths.raw)
    transport: httpx.BaseTransport | None = None
    if state.offline:
        if state.fixture_dir is None:
            raise PipelineError(
                "offline mode requires --fixture-dir or CRAWLER_OFFLINE=1"
            )
        transport = _build_fixture_transport(state.fixture_dir)
    return RetrievalClient(
        config=state.config.crawl,
        store=store,
        transport=transport,
    )


def _apply_release_correlations(
    inventory: VersionInventory,
    correlations: Sequence[ReleaseCorrelation],
) -> VersionInventory:
    correlation_by_version = {item.version: item for item in correlations}
    updated: list[VersionRecord] = []
    for record in inventory.records:
        correlation = correlation_by_version.get(record.normalized_version)
        if correlation is not None and correlation.is_resolved:
            updated.append(
                record.model_copy(
                    update={
                        "git_tag": correlation.git_tag,
                        "commit_sha": correlation.commit_sha,
                    }
                )
            )
        else:
            updated.append(record)
    return VersionInventory(
        package=inventory.package,
        records=tuple(updated),
        unparsable_versions=inventory.unparsable_versions,
    )


def stage_crawl(state: PipelineState) -> None:
    """Fetch authoritative raw sources into the configured raw store."""
    owner, repo = _repository_owner_repo(state.config)
    sources = state.config.sources
    with _retrieval_client(state) as retrieval:
        if sources.pypi:
            logger.info("crawl stage: fetching PyPI project metadata")
            PyPIClient(retrieval).fetch_project(state.package.name)
        if sources.github_releases:
            logger.info("crawl stage: fetching GitHub releases")
            GitHubClient(retrieval).fetch_releases(owner, repo)
        if sources.github_tags:
            logger.info("crawl stage: fetching GitHub tags")
            GitHubClient(retrieval).fetch_tags(owner, repo)
        if sources.changelog:
            for candidate in state.config.repository.changelog_candidates:
                logger.info("crawl stage: fetching changelog candidate %s", candidate)
                try:
                    GitHubClient(retrieval).fetch_file(
                        owner,
                        repo,
                        candidate,
                        ref=state.config.repository.default_branch,
                    )
                    break
                except Exception as error:  # noqa: BLE001 - report and continue
                    logger.warning("changelog candidate unavailable: %s", error)
        if sources.osv:
            logger.info("crawl stage: querying OSV package vulnerabilities")
            OSVClient(retrieval).query_package(
                state.package.name,
                ecosystem=state.package.ecosystem,
            )


def stage_normalize(state: PipelineState) -> None:
    """Normalize raw sources into version and advisory JSONL inventories."""
    owner, repo = _repository_owner_repo(state.config)
    sources = state.config.sources
    with _retrieval_client(state) as retrieval:
        version_inventory: VersionInventory | None = None
        if sources.pypi:
            pypi_response = PyPIClient(retrieval).fetch_project(state.package.name)
            version_inventory = normalize_pypi_versions(pypi_response, state.package)
        else:
            raise PipelineError("normalize requires PyPI source to be enabled")

        tag_mappings: tuple[TagMapping, ...] = ()
        if sources.github_tags or sources.github_releases or sources.changelog:
            if sources.github_tags:
                tags_response = GitHubClient(retrieval).fetch_tags(owner, repo)
                tags_payload = json.loads(tags_response.content.decode("utf-8"))
                tag_mappings = map_tags_to_versions(
                    tags_payload, state.config.package.repository
                )

            releases_payload: list[dict[str, Any]] = []
            if sources.github_releases:
                releases_response = GitHubClient(retrieval).fetch_releases(owner, repo)
                loaded = json.loads(releases_response.content.decode("utf-8"))
                if isinstance(loaded, list):
                    releases_payload = loaded

            changelog = None
            if sources.changelog:
                for candidate in state.config.repository.changelog_candidates:
                    try:
                        changelog_response = GitHubClient(retrieval).fetch_file(
                            owner,
                            repo,
                            candidate,
                            ref=state.config.repository.default_branch,
                        )
                        changelog = parse_changelog(
                            changelog_response.content.decode("utf-8"),
                            format="rst" if candidate.endswith(".rst") else "md",
                        )
                        break
                    except Exception:  # noqa: BLE001 - try next candidate
                        continue

            release_inventory = correlate_releases(
                list(version_inventory.records),
                tag_mappings,
                releases_json=releases_payload,
                changelog=changelog,
            )
            version_inventory = _apply_release_correlations(
                version_inventory,
                release_inventory.correlations,
            )

        advisories: list[AdvisoryRecord] = []
        if sources.osv:
            osv_response = OSVClient(retrieval).query_package(
                state.package.name,
                ecosystem=state.package.ecosystem,
            )
            query_payload = json.loads(osv_response.content.decode("utf-8"))
            vulns = query_payload.get("vulns", [])
            if not isinstance(vulns, list):
                raise PipelineError("OSV query response missing vulns list")
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                provenance = RetrievedResponse(
                    status_code=osv_response.status_code,
                    url=osv_response.url,
                    headers=osv_response.headers,
                    content=json.dumps(vuln, sort_keys=True).encode("utf-8"),
                    retrieved_at=osv_response.retrieved_at,
                    body_sha256=osv_response.body_sha256,
                    cache_key=osv_response.cache_key,
                    from_cache=osv_response.from_cache,
                    attempts=osv_response.attempts,
                )
                advisories.append(
                    normalize_osv_vulnerability(
                        vuln,
                        provenance=_provenance_from_response(
                            provenance, "osv", str(vuln.get("id", "unknown"))
                        ),
                        package_name=state.package.name,
                        ecosystem=state.package.ecosystem,
                    )
                )

        merged_advisories: list[AdvisoryRecord] = advisories
        alias_conflicts: list[AliasConflict] = []
        if advisories:
            resolver = AliasResolver()
            merged_advisories, alias_conflicts = resolver.resolve_advisories(advisories)

        range_result = resolve_advisory_ranges(merged_advisories, version_inventory)

        state.version_inventory = version_inventory
        state.advisories = range_result.advisories
        state.range_issues = range_result.issues
        state.alias_conflicts = tuple(alias_conflicts)

        normalized_dir = state.paths.normalized
        version_export = export_version_inventory(version_inventory, normalized_dir)
        state.exports["normalized/versions.jsonl"] = version_export.sha256

        advisory_inventory = AdvisoryInventory(
            package=state.package,
            records=range_result.advisories,
        )
        advisory_export = export_advisory_inventory(advisory_inventory, normalized_dir)
        state.exports["normalized/advisories.jsonl"] = advisory_export.sha256


def _provenance_from_response(
    response: RetrievedResponse,
    source_type: str,
    source_id: str,
) -> Any:
    from crawler.models import ProvenanceRecord

    return ProvenanceRecord(
        source_type=source_type,
        source_id=source_id,
        retrieved_at=response.retrieved_at,
        raw_sha256=response.body_sha256,
        extractor_version="0.1.0",
    )


def _load_or_build_state(state: PipelineState) -> None:
    """Hydrate in-memory inventories from exported JSONL when needed."""
    normalized = state.paths.normalized
    if state.version_inventory is None:
        versions_path = normalized / "versions.jsonl"
        if versions_path.is_file():
            records = load_jsonl_records(versions_path, VersionRecord)
            state.version_inventory = VersionInventory(
                package=state.package,
                records=tuple(records),
                unparsable_versions=(),
            )
    if not state.advisories:
        advisories_path = normalized / "advisories.jsonl"
        if advisories_path.is_file():
            state.advisories = load_jsonl_records(advisories_path, AdvisoryRecord)


def stage_enrich(state: PipelineState) -> None:
    """Enrich advisories with patch evidence and security patterns."""
    _load_or_build_state(state)
    if state.version_inventory is None:
        raise PipelineError("enrich requires normalized version inventory")

    owner, repo = _repository_owner_repo(state.config)
    sources = state.config.sources
    tag_map: dict[str, str] = {}
    for record in state.version_inventory.records:
        if record.commit_sha and record.git_tag:
            tag_map[record.commit_sha] = record.normalized_version

    patch_records: list[PatchRecord] = []
    unresolved: list[UnresolvedPatchRef] = []
    if sources.patches:
        with _retrieval_client(state) as retrieval:
            github = GitHubClient(retrieval)
            seen_commits: set[str] = set()
            for advisory in state.advisories:
                for commit_sha in advisory.patch_commits:
                    if commit_sha in seen_commits:
                        continue
                    seen_commits.add(commit_sha)
                    try:
                        response = github.fetch_commit(owner, repo, commit_sha)
                        patch_records.append(
                            normalize_github_commit_response(
                                response,
                                advisory_ids=[advisory.identifiers.canonical],
                                package=state.package,
                                owner=owner,
                                repo=repo,
                                expected_owner=owner,
                                expected_repo=repo,
                                advisory_fixed_versions=advisory.fixed_versions,
                                commit_tag_map=tag_map,
                            )
                        )
                    except Exception as error:  # noqa: BLE001 - record unresolved
                        unresolved.append(
                            UnresolvedPatchRef(
                                commit_sha=commit_sha,
                                reason=str(error),
                                advisory_ids=(advisory.identifiers.canonical,),
                            )
                        )

    patch_inventory = build_patch_inventory(
        package=state.package,
        records=patch_records,
        unresolved_refs=unresolved,
    )
    state.patches = patch_inventory
    patch_export = export_patch_inventory(patch_inventory, state.paths.normalized)
    state.exports["normalized/patches.jsonl"] = patch_export.sha256

    patch_by_advisory = {
        advisory_id: patch
        for patch in patch_inventory.records
        for advisory_id in patch.advisory_ids
    }
    pattern_records: list[SecurityPatternRecord] = []
    for advisory in state.advisories:
        pattern_records.append(
            normalize_security_pattern(
                advisory,
                patch=patch_by_advisory.get(advisory.identifiers.canonical),
            )
        )
    pattern_inventory = build_security_pattern_inventory(
        package=state.package,
        records=pattern_records,
    )
    state.patterns = pattern_inventory
    pattern_export = export_security_pattern_inventory(
        pattern_inventory,
        state.paths.normalized,
    )
    state.exports["normalized/security_patterns.jsonl"] = pattern_export.sha256


def stage_validate(state: PipelineState, *, strict: bool = False) -> ValidationResult:
    """Validate the current inventory bundle and optionally export findings."""
    _load_or_build_state(state)
    if state.patches is None:
        patches_path = state.paths.normalized / "patches.jsonl"
        if patches_path.is_file():
            records = load_jsonl_records(patches_path, PatchRecord)
            state.patches = PatchInventory(
                package=state.package,
                records=tuple(records),
                unresolved_refs=(),
            )
        else:
            state.patches = PatchInventory(
                package=state.package,
                records=(),
                unresolved_refs=(),
            )
    if state.patterns is None:
        patterns_path = state.paths.normalized / "security_patterns.jsonl"
        if patterns_path.is_file():
            pattern_records = load_jsonl_records(
                patterns_path, SecurityPatternRecord
            )
            state.patterns = SecurityPatternInventory(
                package=state.package,
                records=tuple(pattern_records),
            )
        else:
            state.patterns = SecurityPatternInventory(
                package=state.package,
                records=(),
            )
    if state.kb_documents is None:
        kb_path = state.paths.kb / "documents.jsonl"
        if kb_path.is_file():
            kb_records = load_jsonl_records(kb_path, KBDocumentRecord)
            state.kb_documents = KBDocumentInventory(
                package=state.package,
                records=tuple(kb_records),
            )
        else:
            state.kb_documents = KBDocumentInventory(
                package=state.package,
                records=(),
            )

    bundle = InventoryBundle(
        package=state.package,
        versions=state.version_inventory.records if state.version_inventory else (),
        advisories=state.advisories,
        patches=state.patches.records,
        security_patterns=state.patterns.records,
        kb_documents=state.kb_documents.records,
        range_issues=state.range_issues,
    )
    result = validate_inventory_bundle(
        bundle,
        options=ValidationOptions(strict=strict),
    )
    state.validation = result
    if result.findings:
        export_validation_errors(result.findings, state.paths.root)
    if strict and not result.passed:
        raise PipelineValidationError(result.findings)
    return result


def stage_build_kb(state: PipelineState) -> None:
    """Generate retrieval-oriented KB documents from security patterns."""
    _load_or_build_state(state)
    if state.patterns is None:
        patterns_path = state.paths.normalized / "security_patterns.jsonl"
        if not patterns_path.is_file():
            raise PipelineError("build-kb requires security_patterns.jsonl")
        pattern_records = load_jsonl_records(patterns_path, SecurityPatternRecord)
        state.patterns = SecurityPatternInventory(
            package=state.package,
            records=tuple(pattern_records),
        )
    if state.patches is None:
        patches_path = state.paths.normalized / "patches.jsonl"
        patch_records = (
            load_jsonl_records(patches_path, PatchRecord)
            if patches_path.is_file()
            else ()
        )
        state.patches = PatchInventory(
            package=state.package,
            records=tuple(patch_records),
            unresolved_refs=(),
        )

    generation = generate_kb_documents_from_patterns(
        package=state.package,
        patterns=state.patterns.records,
        advisories=state.advisories,
        patches=state.patches.records,
    )
    state.kb_documents = generation.inventory
    kb_export = export_kb_document_inventory(generation.inventory, state.paths.root)
    state.exports["kb/documents.jsonl"] = kb_export.sha256


def stage_stats(state: PipelineState) -> None:
    """Compute quality metrics and write stats.json plus manifest.json."""
    if state.validation is None:
        stage_validate(state, strict=False)

    bundle = InventoryBundle(
        package=state.package,
        versions=state.version_inventory.records if state.version_inventory else (),
        advisories=state.advisories,
        patches=state.patches.records if state.patches else (),
        security_patterns=state.patterns.records if state.patterns else (),
        kb_documents=state.kb_documents.records if state.kb_documents else (),
        range_issues=state.range_issues,
    )
    stats = compute_pipeline_stats(bundle, validation=state.validation)
    export_stats(stats, state.paths.root)

    manifest_files = dict(state.exports)
    for relative in list(manifest_files):
        absolute = state.paths.root / relative
        if absolute.is_file():
            manifest_files[relative] = sha256_file(absolute)
    for relative_path in (
        "normalized/versions.jsonl",
        "normalized/advisories.jsonl",
        "normalized/patches.jsonl",
        "normalized/security_patterns.jsonl",
        "kb/documents.jsonl",
        "stats.json",
        "validation_errors.json",
    ):
        absolute = state.paths.root / relative_path
        if absolute.is_file():
            manifest_files[relative_path] = sha256_file(absolute)
    export_manifest(manifest_files, state.paths.root)


def run_pipeline(state: PipelineState, *, skip_crawl: bool = False) -> PipelineState:
    """Execute the full pipeline from crawl through stats."""
    if not skip_crawl:
        stage_crawl(state)
    stage_normalize(state)
    stage_enrich(state)
    stage_validate(state, strict=False)
    if state.config.output.include_kb_documents:
        stage_build_kb(state)
    stage_stats(state)
    return state


def _version_in_range(version: str, pattern: SecurityPatternRecord) -> bool:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    affected = set(pattern.version.resolved)
    if affected:
        return version in affected or str(parsed) in affected
    for event_range in (pattern.version.raw,):
        if not event_range:
            continue
        try:
            if parsed in SpecifierSet(event_range):
                return True
        except Exception:  # noqa: BLE001 - invalid specifier, skip
            continue
    for event in pattern.version.events:
        introduced = event.introduced
        fixed = event.fixed
        if introduced is not None:
            try:
                if parsed < Version(introduced if introduced != "0" else "0.0"):
                    return False
            except InvalidVersion:
                return False
        if fixed is not None:
            try:
                if parsed >= Version(fixed):
                    return False
            except InvalidVersion:
                return False
        return True
    return False


def _format_evidence(pattern: SecurityPatternRecord) -> str:
    evidence: list[str] = []
    for patch_item in pattern.patch_evidence:
        evidence.append(f"{patch_item.evidence_type}:{patch_item.source_id}")
    for test_item in pattern.test_evidence:
        evidence.append(f"{test_item.evidence_type}:{test_item.source_id}")
    for provenance_item in pattern.provenance:
        evidence.append(
            f"provenance:{provenance_item.source_type}:{provenance_item.source_id}"
        )
    return ", ".join(evidence) if evidence else "none"


def query_security_knowledge(
    *,
    package_name: str,
    version: str,
    symbol: str | None,
    normalized_directory: Path,
    fixture_dir: Path | None = None,
) -> list[Mapping[str, str]]:
    """Return evidence-backed query rows for one package version."""
    patterns_path = normalized_directory / "security_patterns.jsonl"
    if not patterns_path.is_file() and fixture_dir is not None:
        raise PipelineError(
            "query requires security_patterns.jsonl; run normalize and enrich first"
        )
    if not patterns_path.is_file():
        raise PipelineError(f"missing security patterns export: {patterns_path}")

    patterns = load_jsonl_records(patterns_path, SecurityPatternRecord)
    rows: list[Mapping[str, str]] = []
    for pattern in patterns:
        if pattern.package.name != package_name:
            continue
        symbols = list(pattern.vulnerable_usage.symbols)
        if symbol is not None and not any(
            symbol == item or symbol in item or item.endswith(symbol)
            for item in symbols
        ):
            continue
        affected = "yes" if _version_in_range(version, pattern) else "no"
        rows.append(
            {
                "Package": package_name,
                "Version": version,
                "Affected": affected,
                "Canonical advisory": pattern.identifiers.canonical,
                "Detection type": pattern.detection_type.value,
                "Relevant symbols": ", ".join(symbols) if symbols else "none",
                "Required preconditions": ", ".join(
                    pattern.vulnerable_usage.preconditions
                )
                or "none",
                "Negative conditions": ", ".join(pattern.negative_conditions) or "none",
                "Fixed version": ", ".join(pattern.remediation.fixed_versions)
                or ", ".join(pattern.version.fixed_versions)
                or "unknown",
                "Recommended remediation": pattern.remediation.upgrade_guidance
                or "none",
                "Evidence": _format_evidence(pattern),
                "Confidence": (
                    f"{pattern.confidence.score:.2f} "
                    f"({'; '.join(pattern.confidence.rationale)})"
                ),
            }
        )
    return rows


def format_query_rows(rows: Sequence[Mapping[str, str]]) -> str:
    """Render query rows as human-readable text."""
    if not rows:
        return "No matching security patterns found.\n"
    blocks: list[str] = []
    for index, row in enumerate(rows, start=1):
        lines = [f"--- Result {index} ---"]
        for key, value in row.items():
            lines.append(f"{key}: {value}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


def build_pipeline_state(
    config: CrawlerConfig,
    *,
    output_override: Path | None = None,
    offline: bool = False,
    fixture_dir: Path | None = None,
) -> PipelineState:
    """Construct the initial pipeline state for one configured run."""
    offline_mode = is_offline_requested(offline_flag=offline, fixture_dir=fixture_dir)
    return PipelineState(
        config=config,
        paths=resolve_pipeline_paths(config, output_override),
        offline=offline_mode,
        fixture_dir=fixture_dir,
        package=package_record_from_config(config),
    )


__all__ = [
    "EXIT_SUCCESS",
    "EXIT_USAGE_ERROR",
    "EXIT_VALIDATION_FAILURE",
    "PipelineError",
    "PipelinePaths",
    "PipelineState",
    "build_pipeline_state",
    "format_query_rows",
    "is_offline_requested",
    "package_record_from_config",
    "query_security_knowledge",
    "resolve_pipeline_paths",
    "run_pipeline",
    "stage_build_kb",
    "stage_crawl",
    "stage_enrich",
    "stage_normalize",
    "stage_stats",
    "stage_validate",
]
