# Implementation Plan — urllib3 Version-Aware Security Knowledge Crawler

## 1. Goal

Implement a reproducible crawler that collects and transforms `urllib3` version and
security information into a structured knowledge base for AI-assisted SAST verdicts.

The implementation should prioritize:

1. Correctness.
2. Traceability.
3. Reproducibility.
4. Security relevance.
5. Extensibility.
6. Completion of a strong pilot before broadening scope.

---

## 2. Final Deliverables

The project must produce:

### Code

- Reusable crawler package.
- CLI entry point.
- Source clients.
- Normalizers and resolvers.
- Security enrichment layer.
- Validators.
- JSONL exporters.
- Unit and integration tests.

### Data

```text
data/raw/
data/normalized/versions.jsonl
data/normalized/advisories.jsonl
data/normalized/patches.jsonl
data/normalized/api_changes.jsonl
data/normalized/security_patterns.jsonl
data/kb/documents.jsonl
data/manifest.json
data/stats.json
```

### Documentation

```text
README.md
context.md
implementation_plan.md
report.md
```

### Demo

A repeatable command that:

1. Crawls `urllib3`.
2. Normalizes data.
3. Builds security patterns.
4. Validates outputs.
5. Prints statistics.
6. Demonstrates one version-and-symbol query.

---

## 3. Delivery Strategy

Use a vertical-slice approach.

Do not build every source connector before producing usable output. Complete one
end-to-end path first:

```text
PyPI versions
→ one advisory source
→ affected-range resolution
→ one patch
→ one security pattern
→ validation
→ JSONL
```

After the first slice works, broaden coverage.

---

## 4. Priority Levels

### P0 — Required for a valid submission

- Project skeleton.
- Configuration.
- PyPI version crawler.
- OSV or GHSA advisory crawler.
- Version normalization.
- Alias normalization.
- Affected-range resolution.
- Raw and normalized JSONL output.
- Provenance.
- Validation.
- Statistics.
- At least three curated SAST security patterns.
- README and report.
- Reproducible demo.

### P1 — Strong differentiators

- Git tag and commit mapping.
- Patch-diff extraction.
- Regression-test extraction.
- Negative knowledge.
- Confidence score.
- Fixed-release verification.
- Deterministic cache.
- Query command.
- SAST usefulness score.

### P2 — Optional enhancements

- NVD enrichment.
- Automated symbol extraction from diffs.
- LLM-assisted semantic enrichment.
- Vector-ready chunk generation.
- Incremental crawling.
- Generic ecosystem adapters.
- Dashboard or visualization.

P2 work must not delay P0 completion.

---

## 5. Phase 0 — Repository Bootstrap

### Objective

Create a stable project structure and development environment before writing crawler
logic.

### Tasks

- [x] Create the repository structure described in `context.md`.
- [x] Add `pyproject.toml`.
- [x] Select a supported Python version.
- [x] Add runtime dependencies.
- [x] Add development dependencies.
- [x] Add `.gitignore`.
- [x] Add `.env.example`.
- [x] Add `configs/urllib3.yaml`.
- [x] Add an initial `README.md`.
- [x] Configure formatting, linting, and testing.
- [x] Add a minimal CLI that prints help.

### Suggested Dependencies

Runtime:

```text
httpx
pydantic
packaging
pyyaml
tenacity
jsonschema
typer
rich
```

Development:

```text
pytest
pytest-cov
respx
ruff
mypy
```

Use fewer dependencies when the standard library is sufficient.

### Acceptance Criteria

```bash
python -m crawler --help
pytest
```

Both commands run successfully in a clean environment.

---

## 6. Phase 1 — Define Schemas and Domain Models

### Objective

Stabilize data contracts before implementing multiple crawlers.

### Tasks

- [x] Define `VersionRecord`.
- [x] Define `AdvisoryRecord`.
- [x] Define `PatchRecord`.
- [x] Define `SecurityPatternRecord`.
- [x] Define `KBDocumentRecord`.
- [x] Define `ProvenanceRecord`.
- [x] Define source-priority enum.
- [x] Define detection-type enum.
- [x] Define confidence model.
- [x] Create matching JSON Schemas.
- [x] Add stable record-ID functions.
- [x] Add serialization tests.

### Required Design Decisions

Document:

- Canonical advisory ID strategy.
- Date format.
- Null versus empty-array conventions.
- Ordering rules.
- Version-range representation.
- Provenance structure.
- Schema versioning policy.

### Acceptance Criteria

- Every model serializes to valid JSON.
- Every model validates against its JSON Schema.
- Identical input produces identical record IDs.
- Unknown values are not fabricated.
- Lists are deterministically sorted.

---

## 7. Phase 2 — HTTP, Cache, Retry, and Raw Storage

### Objective

Create a reliable shared retrieval layer.

### Tasks

- [x] Implement a common HTTP client.
- [x] Add timeout configuration.
- [x] Add transient-error retry.
- [x] Respect `Retry-After`.
- [x] Detect GitHub rate limits.
- [x] Support `GITHUB_TOKEN`.
- [x] Implement response caching.
- [x] Store raw response metadata.
- [x] Compute SHA256.
- [x] Add cache hit/miss logging.
- [x] Add maximum response-size guard.
- [x] Write tests for retries and caching.

### Raw Response Metadata

Each cached response should include:

```json
{
  "request": {
    "method": "GET",
    "url": "<normalized-url>",
    "body_sha256": null
  },
  "response": {
    "status_code": 200,
    "content_type": "application/json",
    "retrieved_at": "<timestamp>",
    "body_sha256": "<sha256>"
  }
}
```

### Acceptance Criteria

- A repeated request uses the cache.
- A 429 response is retried according to policy.
- Authorization headers are never written to disk.
- Network failures produce actionable errors.
- Raw content can be reprocessed without another network request.

---

## 8. Phase 3 — PyPI Version Crawler

### Objective

Build the authoritative version inventory for `urllib3`.

### Tasks

- [x] Fetch project metadata from PyPI.
- [x] Extract all releases.
- [x] Extract all distribution files.
- [x] Capture release date.
- [x] Capture `requires_python`.
- [x] Capture yanked status and reason.
- [x] Normalize versions using PEP 440.
- [x] Mark prereleases.
- [x] Detect unparsable versions.
- [x] Export `versions.jsonl`.
- [x] Add version statistics.
- [x] Add unit tests for sorting and edge cases.

### Validation

Check:

- No duplicate normalized version records.
- Release files belong to the expected project.
- SHA256 values have valid format.
- Dates are valid.
- Prerelease classification is correct.

### Acceptance Criteria

- `data/raw/pypi/` contains the source response.
- `data/normalized/versions.jsonl` is generated.
- Versions are sorted using PEP 440.
- Yanked and prerelease releases are preserved.
- Validation passes.

---

## 9. Phase 4 — GitHub Releases, Tags, and Changelog

### Objective

Connect package releases to repository history and release notes.

### Tasks

- [x] Fetch GitHub releases.
- [x] Fetch Git tags.
- [x] Resolve annotated and lightweight tags.
- [x] Map tag to commit SHA.
- [x] Match PyPI versions to tags.
- [x] Fetch changelog candidates.
- [x] Detect changelog format.
- [x] Parse changelog by version heading.
- [x] Classify entries into security, bugfix, feature, deprecation, and documentation.
- [x] Extract CVE, GHSA, issue, PR, and commit references.
- [x] Export normalized release and changelog records.
- [x] Report unresolved version/tag mappings.

### Mapping Policy

Use exact normalized-version matches first.

Potential tag forms:

```text
2.7.0
v2.7.0
release-2.7.0
```

Do not use fuzzy matching without recording a confidence score and rationale.

### Acceptance Criteria

- Most normal releases are mapped to a tag when an exact tag exists.
- Tag commit SHAs are stored.
- Changelog entries are split by release and category.
- Unresolved mappings are reported, not guessed.
- Re-running the parser produces identical output.

---

## 10. Phase 5 — Advisory Collection and Alias Resolution

### Objective

Collect vulnerability data and construct canonical advisory records.

### Tasks

- [x] Implement OSV package query.
- [ ] Implement GitHub advisory retrieval where available.
- [ ] Optionally implement NVD enrichment.
- [x] Store all raw advisory responses.
- [x] Extract identifiers and aliases.
- [x] Extract affected ranges.
- [x] Extract fixed versions.
- [x] Extract severity, CVSS, CWE, dates, references, and workaround.
- [x] Implement canonical ID selection.
- [x] Merge explicitly linked aliases.
- [x] Detect ambiguous alias clusters.
- [ ] Export `advisories.jsonl`.
- [x] Add source-conflict reporting.

### Canonical-ID Strategy

Recommended order:

1. Maintainer GitHub advisory ID when available.
2. CVE ID when no maintainer advisory exists.
3. OSV or PYSEC ID as fallback.

The canonical choice must remain stable after repeated crawls.

### Acceptance Criteria

- Aliases for the same vulnerability produce one normalized advisory.
- Source-specific values remain available in provenance or conflict records.
- At least two authoritative sources are used where practical.
- No advisory is merged only because its text looks similar.
- Every advisory has at least one source.

---

## 11. Phase 6 — Version-Range Resolution

### Objective

Determine exactly which known `urllib3` releases are affected.

### Tasks

- [ ] Parse ecosystem-specific ranges.
- [ ] Support introduced/fixed events.
- [ ] Support open-ended ranges.
- [ ] Resolve ranges against the PyPI version inventory.
- [ ] Preserve raw ranges.
- [ ] Export resolved affected-version lists.
- [ ] Verify fixed versions exist.
- [ ] Detect contradictory source ranges.
- [ ] Add range-resolution tests.
- [ ] Produce coverage metrics.

### Required Tests

```python
assert affected("2.6.0", ">=2.6.0,<2.7.0")
assert affected("2.6.3", ">=2.6.0,<2.7.0")
assert not affected("2.7.0", ">=2.6.0,<2.7.0")
assert Version("2.0.0a1") < Version("2.0.0")
```

Also test:

- Missing lower bound.
- Missing upper bound.
- Prerelease inclusion.
- Yanked release.
- Invalid range.
- Multiple disjoint ranges.

### Acceptance Criteria

- Every resolvable advisory has a deterministic affected-version list.
- Invalid or conflicting ranges are reported.
- Fixed versions are not inferred without evidence.
- Range-resolution coverage is included in `stats.json`.

---

## 12. Phase 7 — Patch and Regression-Test Enrichment

### Objective

Extract implementation-level evidence for selected high-value vulnerabilities.

### Scope

Prioritize at least three vulnerabilities that demonstrate different detection needs:

1. Version plus API.
2. Version plus API plus configuration.
3. Version plus API plus data-flow or runtime precondition.

### Tasks

- [ ] Extract commit references from advisories.
- [ ] Verify repository ownership.
- [ ] Fetch commit metadata.
- [ ] Fetch parent commit.
- [ ] Store raw diff.
- [ ] Extract changed files.
- [ ] Extract changed symbols.
- [ ] Identify added guards or limits.
- [ ] Find related regression tests.
- [ ] Map patch commit to release tags.
- [ ] Verify fixed-release claims.
- [ ] Export `patches.jsonl`.
- [ ] Record unresolved patch references.

### Manual Review Checkpoint

For the three selected vulnerabilities, manually verify:

- The affected range.
- The fixed version.
- The vulnerable API path.
- The patch behavior.
- The regression test.
- The negative conditions.
- The recommended mitigation.

The manual review should be recorded in the report.

### Acceptance Criteria

- At least three patch-enriched vulnerability records exist.
- At least one patch is verified inside a fixed release.
- Changed files and symbols are recorded.
- Regression-test evidence is linked where available.
- Unsupported inferences are labeled.

---

## 13. Phase 8 — Security-Semantic Extraction

### Objective

Convert advisory and patch evidence into SAST-oriented patterns.

### Tasks

- [ ] Build a rule-based semantic extractor.
- [ ] Extract vulnerable modules and symbols.
- [ ] Extract dangerous arguments.
- [ ] Extract required API sequences.
- [ ] Extract exploit preconditions.
- [ ] Extract data-flow requirements.
- [ ] Extract impact categories.
- [ ] Extract negative conditions.
- [ ] Extract remediation.
- [ ] Assign a detection type.
- [ ] Calculate confidence.
- [ ] Calculate SAST usefulness score.
- [ ] Export `security_patterns.jsonl`.

### Extraction Order

Use evidence in this order:

1. Structured affected/fixed fields.
2. Maintainer advisory description.
3. Patch diff.
4. Regression tests.
5. Release notes.
6. Maintainer discussions.
7. Optional LLM inference.
8. Third-party enrichment.

### LLM-Assisted Enrichment

Optional LLM output should be treated as a candidate draft.

Required process:

1. Supply only evidence-linked text.
2. Ask for structured fields.
3. Validate output.
4. Mark fields as inferred.
5. Preserve prompt and model version.
6. Require human review for high-impact fields.
7. Never let the LLM change authoritative ranges.

### Acceptance Criteria

Each of the three primary security patterns should include:

- Affected range.
- Fixed version.
- Vulnerable symbol or API path.
- At least one precondition.
- At least one negative condition.
- Impact.
- Remediation.
- Evidence.
- Confidence score.
- SAST usefulness score.

---

## 14. Phase 9 — KB Document Generation

### Objective

Generate retrieval-friendly documents without losing structured metadata.

### Document Types

For each high-value vulnerability, generate:

1. `vulnerability_overview`
2. `detection_guidance`
3. `negative_conditions`
4. `remediation_guidance`
5. `patch_evidence`

### Tasks

- [ ] Define chunk templates.
- [ ] Keep one topic per document.
- [ ] Attach structured metadata.
- [ ] Include package and version filters.
- [ ] Include symbol filters.
- [ ] Include advisory IDs.
- [ ] Include evidence references.
- [ ] Export `data/kb/documents.jsonl`.
- [ ] Validate maximum document size.
- [ ] Avoid duplicating identical content.

### Retrieval Metadata

Recommended metadata:

```json
{
  "package": "urllib3",
  "ecosystem": "PyPI",
  "document_type": "detection_guidance",
  "canonical_advisory_id": "<id>",
  "affected_range": "<range>",
  "fixed_versions": [],
  "symbols": [],
  "detection_type": "<type>",
  "confidence": 0.0
}
```

### Acceptance Criteria

- KB documents can be filtered by package, version, symbol, and document type.
- Each document links to a normalized source record.
- Documents contain no unsupported security claims.
- Duplicate document rate is reported.

---

## 15. Phase 10 — Validation and Statistics

### Objective

Provide measurable evidence that the crawler works correctly.

### Tasks

- [ ] Run JSON Schema validation.
- [ ] Run version validation.
- [ ] Run range validation.
- [ ] Run alias validation.
- [ ] Run duplicate validation.
- [ ] Run reference validation.
- [ ] Run provenance validation.
- [ ] Run patch/release consistency validation.
- [ ] Calculate quality metrics.
- [ ] Generate `manifest.json`.
- [ ] Generate `stats.json`.
- [ ] Produce a machine-readable error report.
- [ ] Produce a concise CLI summary.

### Required Metrics

```text
total_versions
total_prereleases
total_yanked_versions
total_advisories
total_aliases
total_patches
total_security_patterns
total_kb_documents
version_coverage
range_resolution_rate
alias_resolution_rate
patch_resolution_rate
fixed_release_verification_rate
provenance_coverage
schema_validation_rate
duplicate_rate
average_sast_usefulness_score
crawl_duration_seconds
cache_hit_rate
failed_request_count
```

### Acceptance Criteria

- Validation failures produce a non-zero exit code when configured as strict.
- Every failure includes a record ID and reason.
- Provenance coverage for normalized records is 100%.
- Duplicate canonical advisories are zero.
- Statistics are reproducible from output files.

---

## 16. Phase 11 — CLI and Query Demo

### Objective

Make the project easy to run and easy to demonstrate.

### Required Commands

```bash
python -m crawler crawl --config configs/urllib3.yaml
python -m crawler normalize --config configs/urllib3.yaml
python -m crawler enrich --config configs/urllib3.yaml
python -m crawler validate --config configs/urllib3.yaml
python -m crawler build-kb --config configs/urllib3.yaml
python -m crawler stats --config configs/urllib3.yaml
python -m crawler run --config configs/urllib3.yaml
```

### Optional Query Command

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.6.0 \
  --symbol HTTPResponse.drain_conn
```

### Query Output Should Include

```text
Package:
Version:
Affected:
Canonical advisory:
Detection type:
Relevant symbols:
Required preconditions:
Negative conditions:
Fixed version:
Recommended remediation:
Evidence:
Confidence:
```

### Acceptance Criteria

- The full pipeline runs with one command.
- Commands support `--help`.
- Errors are clear.
- Output paths are configurable.
- The query demo returns evidence-backed results.

---

## 17. Phase 12 — Tests and Reproducibility

### Objective

Ensure the submitted result can be rerun and trusted.

### Tasks

- [ ] Add unit tests for every normalizer and resolver.
- [ ] Add mocked HTTP tests.
- [ ] Add fixture-based integration test.
- [ ] Add deterministic-output test.
- [ ] Add corrupted-cache test.
- [ ] Add rate-limit test.
- [ ] Add source-conflict test.
- [ ] Add CLI smoke test.
- [ ] Add a clean-environment installation test.
- [ ] Freeze or lock dependencies.
- [ ] Document exact reproduction commands.

### Deterministic Output Test

Run the same fixture-based pipeline twice.

Compare hashes of:

```text
versions.jsonl
advisories.jsonl
patches.jsonl
security_patterns.jsonl
documents.jsonl
```

Exclude timestamps from deterministic content hashes.

### Acceptance Criteria

- Unit tests pass.
- Integration tests pass.
- Two fixture-based runs generate identical normalized outputs.
- Installation instructions work in a clean environment.
- No network access is required for fixture-based tests.

---

## 18. Phase 13 — Report Writing

### Objective

Explain the engineering decisions and demonstrate security value.

### Required Report Sections

1. Executive summary.
2. Problem statement.
3. Why `urllib3` was selected.
4. Scope and non-goals.
5. Knowledge requirements for SAST.
6. Data-source assessment.
7. Architecture.
8. Schema design.
9. Version and alias resolution.
10. Patch and test enrichment.
11. Security-pattern generation.
12. Validation methodology.
13. Crawl statistics.
14. Three detailed case studies.
15. Limitations.
16. Extension to another library.
17. Lessons learned.
18. Conclusion.

### Required Case-Study Format

For each case:

```text
Vulnerability:
Affected versions:
Fixed version:
Relevant API:
Required conditions:
Negative conditions:
Patch behavior:
Regression test:
SAST detection class:
Potential false positives:
Recommended verdict logic:
Evidence:
```

### Acceptance Criteria

- Every reported number is generated from data or clearly marked as manual.
- Every technical conclusion points to evidence.
- Limitations are explicit.
- The report explains how the KB reduces false positives.
- The report distinguishes SCA from SAST knowledge.

---

## 19. Suggested Execution Order

Use this order to reduce delivery risk:

```text
1. Bootstrap repository.
2. Define schemas.
3. Implement HTTP/cache layer.
4. Crawl PyPI versions.
5. Crawl one advisory source.
6. Resolve one affected range.
7. Produce one normalized advisory.
8. Enrich one patch.
9. Produce one security pattern.
10. Validate and export the first vertical slice.
11. Add the remaining advisory sources.
12. Expand to three case studies.
13. Generate KB documents.
14. Add statistics and query demo.
15. Finalize report and README.
```

Do not wait until the end to test the full pipeline.

---

## 20. Recommended Work Breakdown for a Short Deadline

### Block A — Foundation

- Repository structure.
- Configuration.
- Domain models.
- Schemas.
- HTTP/cache/retry.
- CLI skeleton.

### Block B — Version Inventory

- PyPI crawler.
- Version normalization.
- GitHub tag mapping.
- Changelog parser.
- Version validation.

### Block C — Vulnerability Inventory

- OSV/GHSA client.
- Alias resolver.
- Range resolver.
- Advisory exporter.
- Conflict reporting.

### Block D — High-Value Security Knowledge

- Select three vulnerabilities.
- Fetch patches.
- Extract symbols and conditions.
- Add negative knowledge.
- Add remediation.
- Build security patterns.

### Block E — Quality and Delivery

- Validation.
- Statistics.
- KB documents.
- Integration tests.
- README.
- Report.
- Demo commands.

When time is limited, complete all blocks at MVP depth rather than over-engineering
one connector.

---

## 21. Risk Register

### Risk: API rate limiting

Mitigation:

- Use caching.
- Use authenticated GitHub requests.
- Respect rate-limit headers.
- Avoid unnecessary repeated calls.

### Risk: Source disagreement

Mitigation:

- Preserve source-specific values.
- Apply source-priority policy.
- Report conflicts.
- Lower confidence.

### Risk: Incorrect version matching

Mitigation:

- Use PEP 440.
- Preserve raw ranges.
- Add range tests.
- Never compare strings.

### Risk: Advisory without patch reference

Mitigation:

- Keep the advisory.
- Mark patch evidence as unavailable.
- Avoid inventing a patch.
- Lower usefulness score.

### Risk: LLM hallucination

Mitigation:

- Use evidence-constrained prompts.
- Mark inferred fields.
- Validate structured output.
- Prevent LLM overrides of authoritative facts.

### Risk: Scope explosion

Mitigation:

- Keep `urllib3` as the only required library.
- Prioritize three representative vulnerabilities.
- Treat NVD, dashboards, and extra ecosystems as optional.

### Risk: Large or unsafe remote content

Mitigation:

- Apply response-size limits.
- Do not execute downloaded code.
- Validate paths.
- Store content as data only.

### Risk: Data looks large but has low SAST value

Mitigation:

- Calculate SAST usefulness score.
- Require API, precondition, negative condition, remediation, and evidence for selected
  case studies.
- Separate metadata records from verdict-guidance records.

---

## 22. Checkpoints

### Checkpoint 1 — First Vertical Slice

Demonstrate:

- One version record.
- One advisory.
- One resolved affected range.
- One patch.
- One security pattern.
- One validation report.

### Checkpoint 2 — Complete urllib3 Inventory

Demonstrate:

- Full version list.
- Advisory list.
- Alias deduplication.
- Range-resolution statistics.
- Git tag mapping statistics.

### Checkpoint 3 — SAST-Oriented Enrichment

Demonstrate:

- Three representative security patterns.
- Required and negative conditions.
- Patch and test evidence.
- Query by version and symbol.

### Checkpoint 4 — Final Submission

Demonstrate:

- Clean full-pipeline execution.
- Passing tests.
- Deterministic outputs.
- Final report.
- Known limitations.
- Extension plan.

---

## 23. Definition of Done Checklist

### Functionality

- [ ] `python -m crawler run --config configs/urllib3.yaml` works.
- [ ] PyPI versions are crawled.
- [ ] Releases and tags are processed.
- [ ] Changelog is parsed.
- [ ] Advisories are crawled.
- [ ] Aliases are deduplicated.
- [ ] Affected versions are resolved.
- [ ] Patches are enriched.
- [ ] Security patterns are generated.
- [ ] KB documents are generated.
- [ ] Validation completes.
- [ ] Statistics are generated.

### Data Quality

- [ ] All normalized records have provenance.
- [ ] All JSONL records pass schema validation.
- [ ] Canonical advisory duplicates are zero.
- [ ] Fixed versions have source evidence.
- [ ] Selected security patterns contain negative knowledge.
- [ ] Source conflicts are documented.
- [ ] Output ordering is deterministic.

### Testing

- [ ] Version tests pass.
- [ ] Range tests pass.
- [ ] Alias tests pass.
- [ ] Changelog tests pass.
- [ ] Cache and retry tests pass.
- [ ] Integration test passes.
- [ ] Deterministic-output test passes.

### Documentation

- [ ] README contains installation and usage.
- [ ] `context.md` is current.
- [ ] `implementation_plan.md` is current.
- [ ] `report.md` contains results and case studies.
- [ ] `.env.example` documents required variables.
- [ ] Limitations are explicit.

### Security

- [ ] No secrets are committed.
- [ ] Authorization headers are not logged.
- [ ] Remote code is never executed.
- [ ] File paths are validated.
- [ ] Response-size limits exist.
- [ ] Failures are not silently ignored.

---

## 24. Final Demo Script

A mentor-facing demonstration should follow this flow:

```bash
# 1. Install
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 2. Run the full pipeline
python -m crawler run --config configs/urllib3.yaml

# 3. Validate
python -m crawler validate --config configs/urllib3.yaml

# 4. Show statistics
python -m crawler stats --config configs/urllib3.yaml

# 5. Run tests
pytest

# 6. Query a version and symbol
python -m crawler query \
  --package urllib3 \
  --version 2.6.0 \
  --symbol HTTPResponse.drain_conn
```

During the demo, emphasize:

- Raw data is retained.
- Normalized records are deterministic.
- Aliases are deduplicated.
- Version ranges are resolved.
- Security patterns contain positive and negative conditions.
- Findings are backed by patch or advisory evidence.
- The architecture can be extended to another package through an adapter and config.

---

## 25. Submission Summary Template

Use the following structure in the final project summary:

```text
Implemented:
- Version-aware crawler for urllib3.
- PyPI, GitHub, advisory, and patch ingestion.
- PEP 440 version normalization.
- Advisory alias deduplication.
- Affected-range resolution.
- SAST-oriented security pattern generation.
- Provenance, validation, and statistics.

Generated:
- <N> version records.
- <N> normalized advisories.
- <N> patch records.
- <N> security patterns.
- <N> KB documents.

Quality:
- <X>% provenance coverage.
- <X>% affected-range resolution.
- <X>% schema validation.
- <X>% patch resolution.
- <X> duplicate canonical advisories.

Key result:
The generated KB distinguishes dependency exposure from actual vulnerable usage by
combining package version, API usage, configuration, data-flow preconditions, negative
conditions, remediation, and upstream evidence.
```
