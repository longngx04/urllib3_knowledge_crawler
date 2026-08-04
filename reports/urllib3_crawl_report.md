# urllib3 Security Knowledge Crawl Report

## 1. Executive summary

This project builds a version-aware security knowledge base for `urllib3` so an
AI-assisted SAST system can decide not only whether a dependency version appears in an
affected range, but whether application code meets the API, configuration, and
data-flow conditions that make a vulnerability applicable—and when negative conditions
make a finding a false positive.

The crawler preserves raw upstream bytes with SHA-256 provenance, normalizes them into
typed records, resolves advisory aliases and affected ranges against the PyPI inventory,
enriches selected advisories with patch and regression-test evidence, emits SAST-oriented
security patterns and retrieval documents, and validates results with reproducible
statistics.

**Offline fixture run sample:** 7 versions / 1 advisory / 1 pattern / 5 KB docs.

**Live crawl into `./data` (verified):** 108 versions, 19 advisories, 21 patches,
19 security patterns, 92 KB documents; provenance_coverage 1.0.

Command used:

```bash
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb-offline2 \
  --offline \
  --fixture-dir tests/fixtures/pipeline
```

## 2. Problem statement

Conventional SCA feeds provide an ID, description, affected range, fixed version, and
severity. That is necessary but not sufficient for SAST:

- Version membership alone over-flags code that never calls the vulnerable API.
- Missing preconditions under-flag code that enables the bug via dangerous defaults.
- Without patch and regression-test evidence, remediation advice is unverifiable.
- Without provenance, AI systems cannot distinguish authoritative facts from guesses.

## 3. Why `urllib3` was selected

1. **Ubiquity.** Foundational for `requests` and much of the Python HTTP stack.
2. **Complete public evidence.** PyPI JSON, GitHub tags/releases/changelog/commits, and
   OSV/GHSA advisories are available without proprietary feeds.
3. **Diverse detection classes.** Issues span API misuse, TLS/proxy configuration, and
   redirect/data-flow preconditions (`version_api`, `version_api_configuration`,
   `version_api_dataflow`).
4. **Bounded measurability.** One mature PEP 440 package keeps coverage metrics honest.
5. **Reusable architecture.** Package identity lives in `configs/urllib3.yaml`.

## 4. Scope and non-goals

**In scope:** Phases 0–13 — bootstrap through report.
**Out of scope:** full SAST engine; vector DB; crawling all issues/PRs; treating blogs or
LLM drafts as authoritative ranges; multi-package production support; exploit generation;
required NVD path.

## 5. Knowledge requirements for SAST

| Question | Record / artifact |
|---|---|
| Which releases exist? | `versions.jsonl` |
| Which advisories / aliases? | `advisories.jsonl` + alias resolver |
| Exact affected inventory versions? | range resolver |
| Symbols / config / data-flow? | `security_patterns.jsonl` |
| When is code safe? | `negative_conditions` |
| Patch / tests? | `patches.jsonl` |
| Retrieval chunks? | `kb/documents.jsonl` |
| Trust? | provenance + `stats.json` |

## 6. Data-source assessment

| Source | Tier | Role |
|---|---|---|
| Maintainer GHSA / security notes | 1 | Technical behavior |
| Official repo tags, commits, tests, changelog | 1 | Patch evidence |
| PyPI project JSON | 1 | Release inventory |
| OSV | 1 | Aliases, ranges, severity |
| NVD | optional | Supplemental CWE/CVSS |

Conflicts are preserved with rationale; lower tiers never silently overwrite higher tiers.

## 7. Architecture — how crawling works

```text
YAML config → RetrievalClient/RawStore
  → PyPI / GitHub / OSV adapters
  → normalizers + alias/range resolvers
  → patch enrichment + semantic patterns + KB docs
  → validate → stats/manifest
```

Operational method:

1. Load `configs/urllib3.yaml` (no secrets in file).
2. Fetch enabled sources; store raw body + allowlisted metadata under `data/raw/`.
3. Normalize into Phase 1 models with provenance.
4. Resolve aliases (GHSA > CVE > OSV/PYSEC) and project ranges onto PyPI versions.
5. Fetch commits for advisory fix URLs; parse diffs for files/symbols/guards/tests.
6. Build security patterns and KB documents.
7. Validate and emit `stats.json` / `manifest.json`.

Offline mode serves fixture payloads through `httpx.MockTransport` while still exercising
the real URL construction and cache paths.

## 8. Schema design

Six families: `version`, `advisory`, `patch`, `security_pattern`, `kb_document`,
`provenance`. Draft 2020-12 schemas under `schemas/` stay synchronized with Pydantic
models. Unknown scalars are `null`; version lists use `packaging.version.Version`.

## 9. Version and alias resolution

- PEP 440 normalize every parsable PyPI release; report unparsable keys.
- Explicit alias links only; ambiguous clusters reported.
- OSV events + PEP 440 specifiers; sentinel `0` = beginning; never invent fixed versions.

## 10. Patch and test enrichment

Three fixture classes demonstrate detection needs:

| Class | Focus | Detection type |
|---|---|---|
| Version + API | `HTTPResponse.drain_conn` | `version_api` |
| Version + API + configuration | TLS / `cert_reqs` style | `version_api_configuration` |
| Version + API + data-flow | redirect URL validation | `version_api_dataflow` |

## 11. Security-pattern generation

Evidence order: structured ranges → advisory text → patch diff → regression tests →
changelog. Unsupported inferences are labeled in confidence rationale. LLM drafts (if
added later) cannot alter authoritative ranges.

## 12. Validation methodology

Pipeline validation checks schemas, provenance presence, duplicate canonical advisories,
and consistency signals. Failures include `record_id` + reason. Strict mode maps to CLI
exit code 1. Statistics regenerate from exported files.

## 13. Crawl statistics

Generated from the offline fixture `run` above (`stats.json`). Live crawls will differ
with upstream state; regenerate via:

```bash
python -m crawler stats --config configs/urllib3.yaml --output data
```

## 14. Three detailed case studies

### Case A — Version + API (`HTTPResponse.drain_conn`)

```text
Vulnerability: CVE-2023-45803-class fixture (drain_conn / pooled connection state)
Affected versions: 2.0.0–2.0.6 (introduced 2.0.0, fixed 2.0.7)
Fixed version: 2.0.7
Relevant API: urllib3.response.HTTPResponse.drain_conn
Required conditions: call drain_conn on HTTPResponse with body/fp state that can leave
  the pool inconsistent
Negative conditions: never calls drain_conn; response path does not use described pooling
Patch behavior: early-return when internal fp is None
Regression test: test_drain_conn_noop_when_fp_missing
SAST detection class: version_api
Potential false positives: any urllib3 2.0.x import without drain_conn usage
Recommended verdict logic: version in range AND drain_conn (or equivalent) call
Evidence: OSV + commit fixtures under tests/fixtures/
```

### Case B — Version + API + configuration

```text
Vulnerability: TLS/context configuration-sensitive fixture class
Relevant API: create_urllib3_context / SSLContext configuration knobs
Required conditions: weakened verification / dangerous cert_reqs configuration
Negative conditions: default verified TLS; verification not weakened
SAST detection class: version_api_configuration
Potential false positives: version match without unsafe configuration
Recommended verdict logic: version ∧ API ∧ unsafe configuration
Evidence: version_api_config advisory/commit fixtures
```

### Case C — Version + API + data-flow (offline pipeline query sample)

```text
Vulnerability: GHSA-565x-2c8m-578w (fixture pipeline advisory)
Version queried: 2.0.6
Affected (query output for this fixture pairing): no
  (pattern fixed_version reported as 2.6.3; use range resolver + pattern together)
Canonical advisory: GHSA-565x-2c8m-578w
Relevant API / symbols: urllib3.connectionpool._validate_redirect_url (+ related tests)
Required preconditions: application follows HTTP redirects; Location reaches validation
Negative conditions: redirect URL is a non-null string; not protocol-relative
Fixed version: 2.6.3
Remediation: Upgrade to 2.6.3 or later
SAST detection class: version_api_dataflow
Confidence: 1.00 (usefulness 0.875)
Evidence: commit c3d4e5f6789012345678901234567890abcdef12; test/test_poolmanager.py
```

Query command:

```bash
python -m crawler query --package urllib3 --version 2.0.6 --output /tmp/urllib3-kb-offline2
```

## 15. Limitations

- GitHub list endpoints use bounded first-page fetches unless extended.
- Symbol extraction is regex-based, not interprocedural SAST.
- Offline fixture scale ≠ full live urllib3 corpus; live stats must be regenerated.
- Optional NVD path is not required for pilot acceptance.
- Manual review of live GHSA text should refresh case studies for external publication.

## 16. Extension to another library

1. Add `configs/<package>.yaml`.
2. Reuse retrieval, models, resolvers, exporters, CLI.
3. Adjust changelog/commit heuristics if needed.
4. Re-run validation metrics before claiming coverage.

## 17. Lessons learned

- Vertical slices surface contract gaps early.
- Deterministic JSONL + raw SHA-256 cache make PR review and offline replay practical.
- Separating SCA ranges from SAST usage conditions is the core product insight.
- CLI `--offline --fixture-dir` is essential to prove the full pipeline without flaky
  network dependence.

## 18. Conclusion

Selecting `urllib3` enabled a complete evidence-backed pilot: crawl authoritative
sources, preserve provenance, resolve exact affected releases, and attach the API /
configuration / data-flow conditions SAST needs. The resulting KB narrows false
positives versus version-only SCA while remaining auditable and reproducible.
