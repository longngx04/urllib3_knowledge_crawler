# Project Context — Version-Aware Security Knowledge Crawler for urllib3

## 1. Project Overview

This project builds a reproducible crawler and normalization pipeline for collecting
**version-aware security knowledge** about the Python library `urllib3`.

The final knowledge base is intended to support an AI-assisted SAST system. The KB
must help the model determine not only whether a dependency version is vulnerable,
but also whether the scanned source code satisfies the API, configuration, control-flow,
and data-flow conditions required for exploitation.

The project is a pilot implementation. `urllib3` is the first supported library, but
the architecture should be reusable for other ecosystems and libraries such as Django,
Log4j, Requests, Jackson, Spring Security, or Apache Commons.

---

## 2. Problem Statement

A conventional vulnerability feed usually provides:

- A vulnerability identifier.
- A short description.
- An affected version range.
- A fixed version.
- A severity score.

That information is useful for Software Composition Analysis, but is not sufficient
for accurate SAST verdicts.

A SAST-oriented knowledge base must also capture:

- Which functions, classes, methods, arguments, and execution paths are relevant.
- Which runtime or configuration conditions are required.
- Whether attacker-controlled data reaches the vulnerable behavior.
- Which conditions make the code safe or not affected.
- How the upstream patch changed the vulnerable behavior.
- Which regression tests demonstrate the expected secure behavior.
- Which source provides the evidence for each conclusion.

The crawler must transform raw release and vulnerability information into structured,
traceable, and machine-consumable security knowledge.

---

## 3. Primary Objectives

The implementation must achieve the following objectives:

1. Discover all available `urllib3` versions and normalize them using PEP 440.
2. Collect release metadata, changelog entries, advisories, vulnerability identifiers,
   affected ranges, fixed versions, patches, and relevant tests.
3. Map package versions to Git tags and commit SHAs where possible.
4. Resolve aliases such as CVE, GHSA, PYSEC, and OSV into one canonical vulnerability.
5. Convert raw vulnerability information into SAST-oriented security patterns.
6. Preserve provenance so every normalized claim can be traced to its source.
7. Export deterministic JSONL data suitable for later indexing or RAG ingestion.
8. Validate data completeness, consistency, uniqueness, and security usefulness.
9. Produce a report and statistics explaining the crawl result and limitations.
10. Keep the implementation generic enough to support more packages later.

---

## 4. Non-Goals

The first implementation does not need to:

- Crawl every GitHub issue or pull request in the repository.
- Crawl arbitrary third-party blogs as an authoritative source.
- Clone and embed the entire `urllib3` source tree.
- Build a production vector database.
- Implement a complete SAST engine.
- Guarantee exploitability using only static analysis.
- Support every package ecosystem in the first iteration.
- Use an LLM to decide affected version ranges.
- Automatically generate executable exploits.

Third-party write-ups may be added later as enrichment data, but they must not override
maintainer advisories or structured official sources.

---

## 5. Target Users

The main consumers of the generated data are:

- AI agents that validate SAST findings.
- Retrieval systems that supply library-specific knowledge to an LLM.
- Security engineers reviewing dependency-related findings.
- Future benchmark and ablation-study pipelines.
- Developers extending the crawler to additional libraries.

---

## 6. Core Questions the KB Must Answer

For a given codebase and finding, the KB should help answer:

1. Which `urllib3` version is used?
2. Is that version inside an affected range?
3. Is the relevant vulnerable API called?
4. Are dangerous arguments or configurations present?
5. Does untrusted input reach the affected API?
6. Are redirects, decompression, proxy, TLS, or retry behaviors relevant?
7. Is a required exploit precondition missing?
8. Is there a negative condition that makes the finding not affected?
9. What is the likely impact?
10. Which fixed version or mitigation is recommended?
11. Which advisory, patch, test, or release note supports the verdict?
12. How confident should the system be in the conclusion?

---

## 7. Knowledge Taxonomy

The crawler must distinguish the following knowledge types.

### 7.1 Version Knowledge

Fields should include:

- Package name.
- Ecosystem.
- Raw version.
- Normalized version.
- Release date.
- Prerelease status.
- Yanked status.
- Python version requirement.
- Git tag.
- Commit SHA.
- Support branch.
- Support status.
- Source URLs or source identifiers.
- Retrieval timestamp and content hash.

### 7.2 Vulnerability Knowledge

Fields should include:

- Canonical vulnerability ID.
- Alias IDs.
- CWE.
- CVSS and severity.
- Summary.
- Detailed impact.
- Affected version ranges.
- Resolved affected versions.
- Fixed versions.
- Published and modified timestamps.
- Workaround.
- References.
- Patch commits.
- Source priority and confidence.

### 7.3 API Knowledge

Fields should include:

- Module.
- Class.
- Method or function.
- Parameters.
- Relevant constants.
- API availability by version.
- Security relevance.
- Deprecated or replacement API.
- Related vulnerability IDs.

### 7.4 Exploit-Condition Knowledge

Fields should include:

- Required API sequence.
- Required arguments.
- Required configuration.
- Required redirect or proxy behavior.
- Required input source.
- Required data-flow relationship.
- Required response type or content encoding.
- Required environment or runtime condition.
- Conditions that increase severity.

### 7.5 Negative Knowledge

Negative knowledge is mandatory because it helps reduce false positives.

Examples:

- The installed version is outside the affected range.
- Only a high-level safe API is used.
- Cross-origin redirects are disabled.
- Sensitive headers are absent.
- The dangerous argument remains at its secure default.
- Attacker-controlled data cannot reach the vulnerable call.
- A project-level mitigation is present.
- The vulnerable code path is unreachable.
- The upstream patch is already backported.

### 7.6 Patch Knowledge

Fields should include:

- Commit SHA.
- Parent SHA.
- Changed files.
- Changed symbols.
- Added or modified guards.
- Behavioral difference before and after the patch.
- Added regression tests.
- Fixed release.
- Evidence confidence.

### 7.7 Remediation Knowledge

Fields should include:

- Minimum safe version.
- Preferred upgrade target.
- Workaround.
- Secure API alternative.
- Configuration change.
- Compatibility concern.
- Whether the workaround is temporary or complete.

---

## 8. Source Priority

Use the following source priority.

### Tier 1 — Authoritative Sources

1. `urllib3` maintainer security advisories.
2. Official `urllib3` repository, tags, commits, tests, and changelog.
3. PyPI package metadata.
4. OSV structured vulnerability records.
5. GitHub Security Advisory structured data.
6. NVD structured vulnerability records.

### Tier 2 — Contextual Sources

- Security-related pull requests.
- Maintainer issue discussions.
- Release notes.
- Regression tests.
- Migration guides.

### Tier 3 — Enrichment Sources

- Security blogs.
- Public write-ups.
- Conference material.
- Exploit demonstrations.

Tier 3 data must be labeled as secondary and lower-confidence.

---

## 9. Source Conflict Policy

When sources disagree:

1. Prefer maintainer advisories for technical behavior and fixed versions.
2. Prefer repository patches and tests for implementation details.
3. Prefer PyPI for published package metadata.
4. Use OSV and GHSA for normalized aliases and ranges.
5. Use NVD for supplemental CWE and CVSS data.
6. Preserve conflicting values instead of silently overwriting them.
7. Record the selected value, rejected value, source, and resolution reason.
8. Lower the confidence score when the conflict cannot be resolved.

An LLM must never be the only authority for version ranges or fixed versions.

---

## 10. High-Level Architecture

```text
PyPI Metadata ───────────┐
GitHub Releases/Tags ────┤
Changelog ───────────────┤
Security Advisories ─────┤
OSV ─────────────────────┼──> Raw Store
NVD ─────────────────────┤        │
Patch Commits ───────────┤        ▼
Regression Tests ────────┘   Normalization
                                 │
                                 ▼
                          Alias and Version
                              Resolution
                                 │
                                 ▼
                         Security Enrichment
                                 │
                                 ▼
                           Validation Layer
                                 │
                 ┌───────────────┴──────────────┐
                 ▼                              ▼
          Normalized JSONL                  KB Documents
                 │                              │
                 └───────────────┬──────────────┘
                                 ▼
                            Statistics
```

---

## 11. Recommended Repository Structure

```text
.
├── context.md
├── implementation_plan.md
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── configs/
│   └── urllib3.yaml
├── crawler/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging_config.py
│   ├── models.py
│   ├── clients/
│   │   ├── pypi.py
│   │   ├── github.py
│   │   ├── osv.py
│   │   └── nvd.py
│   ├── extractors/
│   │   ├── changelog.py
│   │   ├── advisory.py
│   │   ├── patch_diff.py
│   │   ├── tests.py
│   │   └── security_semantics.py
│   ├── normalizers/
│   │   ├── versions.py
│   │   ├── identifiers.py
│   │   ├── ranges.py
│   │   └── records.py
│   ├── resolvers/
│   │   ├── aliases.py
│   │   ├── version_tag_commit.py
│   │   └── patch_release.py
│   ├── validators/
│   │   ├── schema.py
│   │   ├── versions.py
│   │   ├── ranges.py
│   │   ├── references.py
│   │   ├── provenance.py
│   │   └── duplicates.py
│   ├── exporters/
│   │   ├── jsonl.py
│   │   ├── manifest.py
│   │   └── stats.py
│   └── utils/
│       ├── cache.py
│       ├── retry.py
│       ├── hashing.py
│       ├── http.py
│       └── time.py
├── schemas/
│   ├── version.schema.json
│   ├── advisory.schema.json
│   ├── patch.schema.json
│   ├── security_pattern.schema.json
│   └── kb_document.schema.json
├── tests/
│   ├── fixtures/
│   ├── test_versions.py
│   ├── test_ranges.py
│   ├── test_aliases.py
│   ├── test_changelog.py
│   ├── test_validation.py
│   └── test_integration_urllib3.py
├── data/
│   ├── raw/
│   ├── normalized/
│   ├── kb/
│   ├── manifest.json
│   └── stats.json
└── report.md
```

---

## 12. Configuration Model

The `configs/urllib3.yaml` file should contain package-specific configuration.

```yaml
package:
  name: urllib3
  ecosystem: PyPI
  purl: pkg:pypi/urllib3
  repository: urllib3/urllib3
  version_scheme: pep440

sources:
  pypi: true
  github_releases: true
  github_tags: true
  changelog: true
  github_advisories: true
  osv: true
  nvd: optional
  patches: true
  regression_tests: true

repository:
  default_branch: main
  changelog_candidates:
    - CHANGES.rst
    - CHANGELOG.md
    - HISTORY.rst
  security_policy_candidates:
    - SECURITY.md
    - .github/SECURITY.md

output:
  directory: data
  deterministic: true
  include_raw: true
  include_kb_documents: true

crawl:
  timeout_seconds: 30
  max_retries: 4
  cache_enabled: true
  respect_rate_limits: true
```

Package-specific logic should remain in configuration whenever possible. Avoid
hardcoding `urllib3` names throughout the implementation.

---

## 13. Required Output Files

### Raw Data

```text
data/raw/pypi/
data/raw/github_releases/
data/raw/github_tags/
data/raw/changelog/
data/raw/advisories/
data/raw/osv/
data/raw/nvd/
data/raw/patches/
data/raw/tests/
```

### Normalized Data

```text
data/normalized/versions.jsonl
data/normalized/advisories.jsonl
data/normalized/patches.jsonl
data/normalized/api_changes.jsonl
data/normalized/security_patterns.jsonl
```

### KB Data

```text
data/kb/documents.jsonl
```

### Metadata

```text
data/manifest.json
data/stats.json
```

---

## 14. Normalized Record Requirements

Every normalized record must include:

```json
{
  "schema_version": "1.0",
  "record_type": "example",
  "record_id": "stable-identifier",
  "package": {
    "name": "urllib3",
    "ecosystem": "PyPI",
    "purl": "pkg:pypi/urllib3"
  },
  "provenance": [
    {
      "source_type": "source-name",
      "source_id": "source-specific-id",
      "retrieved_at": "ISO-8601 timestamp",
      "raw_sha256": "sha256",
      "extractor_version": "0.1.0"
    }
  ]
}
```

Requirements:

- `record_id` must be stable across repeated runs.
- Output ordering must be deterministic.
- Unknown values should be `null`, not invented.
- Empty arrays should be used where semantically appropriate.
- Dates should use ISO 8601.
- All text files must use UTF-8.
- Every JSONL line must be valid independent JSON.

---

## 15. Security Pattern Schema

A security pattern should be suitable for SAST retrieval and verdict support.

```json
{
  "schema_version": "1.0",
  "record_type": "library_security_pattern",
  "record_id": "urllib3:<canonical-advisory-id>",
  "package": {
    "name": "urllib3",
    "ecosystem": "PyPI",
    "purl": "pkg:pypi/urllib3"
  },
  "identifiers": {
    "primary": "<canonical-id>",
    "aliases": []
  },
  "version": {
    "affected_range_raw": "<raw-range>",
    "affected_events": [],
    "affected_versions_resolved": [],
    "fixed_versions": []
  },
  "classification": {
    "cwe": [],
    "severity": null,
    "cvss": null,
    "detection_type": "version_api_configuration_dataflow"
  },
  "vulnerable_usage": {
    "modules": [],
    "classes": [],
    "symbols": [],
    "arguments": {},
    "api_sequence": [],
    "preconditions": [],
    "sources": [],
    "sinks": [],
    "required_dataflow": []
  },
  "negative_conditions": [],
  "impact": {
    "categories": [],
    "description": null
  },
  "remediation": {
    "upgrade_to": null,
    "workarounds": [],
    "safe_alternatives": []
  },
  "patch_evidence": [],
  "test_evidence": [],
  "confidence": {
    "score": 0.0,
    "rationale": []
  },
  "provenance": []
}
```

---

## 16. Detection-Type Classification

Every security pattern should be assigned one of these detection types:

### `version_only`

The installed version is sufficient to flag exposure. This is mainly an SCA signal.

### `version_api`

The version and a relevant API call are required.

### `version_api_configuration`

The version, API, and dangerous argument or configuration are required.

### `version_api_dataflow`

The version, API, and attacker-controlled data-flow are required.

### `version_api_configuration_dataflow`

The most context-sensitive class. Version, API, configuration, and data-flow must
all be considered.

### `security_assumption_mismatch`

The code appears to apply a security control, but the library version does not enforce
the behavior as the developer expects.

---

## 17. Version Handling Rules

Use `packaging.version.Version` and `packaging.specifiers.SpecifierSet`.

Do not compare versions as strings.

The implementation must handle:

- Final releases.
- Prereleases.
- Development releases.
- Post releases.
- Yanked releases.
- Multiple maintained release lines.
- Open-ended introduced/fixed ranges.
- Missing lower or upper bounds.
- Versions that exist in tags but not on PyPI.
- Versions that exist on PyPI but have no GitHub release object.

Store both:

- The original range representation.
- A normalized event representation.
- The resolved list of known affected versions.

Never infer a fixed version only because it is the first version after an affected
version. A fixed version needs supporting source evidence.

---

## 18. Alias Resolution Rules

Potential aliases include:

- CVE.
- GHSA.
- PYSEC.
- OSV identifiers.
- Vendor-specific identifiers.

Rules:

1. Choose a stable canonical ID.
2. Preserve every alias.
3. Merge records only when a structured source explicitly links the aliases or when
   the evidence is otherwise strong and auditable.
4. Do not merge records based only on similar descriptions.
5. Record merge evidence.
6. Detect and report ambiguous alias clusters.

---

## 19. Patch Analysis Rules

For each advisory with a patch reference:

1. Verify the commit belongs to the official repository.
2. Fetch commit metadata and parent SHA.
3. Store the raw diff.
4. Extract changed files.
5. Extract changed Python symbols where possible.
6. Identify guards, bounds, condition changes, or header-handling changes.
7. Find added or modified regression tests.
8. Resolve which release tags contain the patch.
9. Compare the advisory fixed version with the release containing the commit.
10. Report inconsistencies instead of hiding them.

Patch analysis may initially use rule-based extraction. LLM enrichment is optional
and must be marked as inferred.

---

## 20. LLM Usage Policy

An LLM may be used to:

- Summarize a patch.
- Extract candidate preconditions.
- Suggest negative conditions.
- Convert prose into a structured draft.
- Classify a pattern by detection type.
- Produce a human-readable explanation.

An LLM must not be the sole source for:

- Affected version range.
- Fixed version.
- CVE/GHSA alias mapping.
- Commit identity.
- Severity or CVSS.
- Release date.
- Whether a patch is included in a tag.

Every LLM-derived field must include:

```json
{
  "inferred": true,
  "model": "<model-name>",
  "prompt_version": "<version>",
  "evidence_ids": [],
  "confidence": 0.0
}
```

---

## 21. Crawl Engineering Requirements

### Idempotency

Repeated runs with unchanged upstream data must generate identical normalized output,
except for explicitly non-deterministic metadata such as crawl timestamps.

### Caching

Cache raw HTTP responses using a key derived from:

```text
HTTP method + normalized URL + request body
```

Store the response body, status code, headers needed for caching, retrieval time,
and SHA256.

### Retry

Retry transient failures only:

- HTTP 429.
- HTTP 500.
- HTTP 502.
- HTTP 503.
- HTTP 504.
- Connection reset.
- Timeout.

Use exponential backoff with a retry limit.

### Rate Limits

- Respect `Retry-After`.
- Detect GitHub rate-limit headers.
- Support authenticated GitHub requests using `GITHUB_TOKEN`.
- Never commit credentials.
- Avoid aggressive concurrency.

### Logging

Logs should include:

- Stage.
- Source.
- Request identifier.
- Record identifier.
- Retry count.
- Error class.
- Duration.
- Cache hit or miss.

Avoid logging secrets and authorization headers.

### Determinism

- Sort records by stable keys.
- Sort aliases, versions, files, and references.
- Normalize whitespace.
- Use stable record IDs.
- Avoid embedding crawl timestamps in content hashes.

---

## 22. Validation Requirements

### Schema Validation

Validate every JSONL record against its JSON Schema.

### Version Validation

Check:

- Versions parse successfully.
- Fixed versions exist in known package versions when expected.
- Affected ranges can be evaluated.
- Introduced/fixed events are ordered correctly.
- Resolved versions satisfy the normalized range.

### Reference Validation

Check:

- Referenced commits exist.
- Patch repository matches the package repository.
- Source identifiers are present.
- Evidence records are reachable.
- URLs are syntactically valid.

### Duplicate Validation

Detect:

- Duplicate version records.
- Duplicate canonical advisories.
- Duplicate alias clusters.
- Duplicate patch records.
- Duplicate KB documents.

### Provenance Validation

Every normalized security claim must include at least one provenance record.

### Semantic Validation

Check where possible:

- A fixed release contains the patch commit.
- A regression test refers to the affected behavior.
- Vulnerable symbols appear in the relevant source or patch.
- Negative conditions do not contradict required preconditions.
- Remediation is compatible with fixed-version evidence.

---

## 23. Quality Metrics

The project must report at least:

```text
version_coverage
advisory_range_resolution_rate
advisory_alias_resolution_rate
patch_resolution_rate
fixed_release_verification_rate
provenance_coverage
schema_validation_rate
duplicate_rate
security_pattern_generation_rate
average_sast_usefulness_score
```

### SAST Usefulness Score

Score each security pattern using one point for each available component:

1. Affected range.
2. Fixed version.
3. Vulnerable symbol.
4. Required precondition.
5. Dangerous configuration or argument.
6. Negative condition.
7. Remediation.
8. Patch or regression-test evidence.

```text
sast_usefulness_score = available_components / 8
```

Records with low scores may still be retained, but they should be labeled as metadata
rather than high-confidence verdict guidance.

---

## 24. Required CLI

The preferred CLI interface is:

```bash
python -m crawler crawl --config configs/urllib3.yaml
python -m crawler normalize --config configs/urllib3.yaml
python -m crawler enrich --config configs/urllib3.yaml
python -m crawler validate --config configs/urllib3.yaml
python -m crawler build-kb --config configs/urllib3.yaml
python -m crawler stats --config configs/urllib3.yaml
```

A full pipeline command may also be provided:

```bash
python -m crawler run --config configs/urllib3.yaml
```

Optional query demo:

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.6.0 \
  --symbol HTTPResponse.drain_conn
```

Each command must:

- Return a non-zero exit code on unrecoverable failure.
- Print a concise summary.
- Write detailed logs.
- Avoid silently skipping failed records.

---

## 25. Testing Requirements

### Unit Tests

Minimum unit-test coverage should include:

- PEP 440 sorting.
- Prerelease handling.
- Range evaluation.
- Introduced/fixed events.
- Alias resolution.
- Stable record IDs.
- Changelog heading parsing.
- JSONL deterministic ordering.
- Duplicate detection.
- Confidence scoring.

### Integration Tests

At least one integration test must run the `urllib3` pipeline using fixtures or cached
responses and assert:

- Version records are generated.
- Advisories are generated.
- Affected ranges resolve.
- Alias records do not create duplicates.
- At least one patch is connected to a fixed release.
- Security patterns are generated.
- Validation completes with expected results.
- Output is deterministic between two runs.

### Failure Tests

Test:

- Rate limiting.
- Invalid JSON.
- Missing changelog.
- Missing Git tag.
- Advisory without a patch.
- Unknown version syntax.
- Conflicting fixed versions.
- Network timeout.
- Corrupted cache.

---

## 26. Security and Compliance Rules

- Do not store API tokens in the repository.
- Use `.env` or environment variables.
- Do not execute downloaded code.
- Treat remote data as untrusted input.
- Validate paths before writing files.
- Prevent path traversal from archive or repository metadata.
- Apply size limits to responses and diffs.
- Record source licenses where relevant.
- Avoid crawling prohibited or private content.
- Respect API terms, robots policies where applicable, and rate limits.
- Do not generate weaponized exploit code as part of the default pipeline.

---

## 27. Coding-Agent Rules

Any coding agent working in this repository must follow these rules:

1. Read `context.md` and `implementation_plan.md` before changing code.
2. Do not broaden the project scope without documenting the reason.
3. Prefer small, testable modules.
4. Keep package-specific behavior in configuration or adapters.
5. Do not hardcode vulnerability facts in application logic.
6. Do not invent missing version, alias, or patch information.
7. Preserve raw data before normalization.
8. Attach provenance to normalized claims.
9. Add or update tests for every behavior change.
10. Keep outputs deterministic.
11. Use typed Python where practical.
12. Validate external data at trust boundaries.
13. Handle errors explicitly.
14. Never silently swallow exceptions.
15. Avoid unnecessary dependencies.
16. Keep credentials out of logs and source control.
17. Maintain backward compatibility with existing output schemas unless the schema
    version is intentionally changed.
18. Update documentation when commands, schemas, or outputs change.
19. Do not use an LLM-derived value as an authoritative security fact.
20. Stop and report conflicts that could materially change a vulnerability verdict.

---

## 28. Definition of Done

The pilot is complete when:

- A clean environment can install the project.
- One command can run the full `urllib3` pipeline.
- Version metadata is collected and normalized.
- Advisories are collected from authoritative structured sources.
- CVE/GHSA/PYSEC/OSV aliases are deduplicated.
- Affected ranges and fixed versions are resolved.
- Raw and normalized data are stored separately.
- At least three SAST-oriented security patterns are produced.
- Each selected pattern includes version, API, precondition, negative condition,
  remediation, and evidence where available.
- At least one patch is mapped to a fixed release.
- Validation and statistics are generated.
- Unit and integration tests pass.
- The process is reproducible using documented commands.
- `report.md` explains architecture, results, limitations, and future extension.
- No secrets are committed.
- Known unresolved conflicts are documented.

---

## 29. Expected Mentor-Facing Message

The core project value should be communicated as follows:

> This project does not only crawl CVE descriptions or release notes. It converts
> version metadata, maintainer advisories, patch commits, and regression tests into
> structured security knowledge. Each high-value record describes the affected
> versions, vulnerable APIs, exploit preconditions, safe conditions, remediation,
> and evidence so that an AI-assisted SAST system can make more accurate verdicts
> and reduce false positives.
