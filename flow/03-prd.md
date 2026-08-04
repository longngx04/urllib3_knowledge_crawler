# Stage 03 — PRD

1-2 pages max. Test: could a stranger build v1 from this without asking you anything?

## Gate — check ALL before `/flow next`
- [x] Every section below is filled from MY scope decision (stage 02), not re-expanded
- [x] Success metric is a NUMBER, not vibes ("save time" fails; "first response < 2h" passes)
- [x] Each feature names the user action and the observable result, tagged with a stable `FRn:` id
- [x] Pain & gain is a MAPPING TABLE: every pain cites evidence (a stage-01 quote or a named observation), and names the v1 feature that kills it; every v1 feature kills at least one pain
- [x] A stranger could build v1 from this without asking me anything
- [x] No FILL placeholders remain in this file

## Context

VinSOC is starting an internal Python CLI that will convert authoritative urllib3 release and vulnerability sources into version-aware security knowledge for AI-assisted SAST. Existing SCA tools provide useful dependency and advisory data but do not supply the API, configuration, data-flow, negative-condition, patch, and test evidence needed for application-specific verdicts. Phase 0 establishes only the repository, package, configuration, command, documentation, and quality seams needed by later phases. No network crawling or vulnerability facts are implemented in this phase.

Phase 1 adds the shared data-contract layer only. It does not contact remote sources,
resolve advisory aliases or version ranges, or claim any real urllib3 vulnerability fact.

Phase 2 adds reusable retrieval infrastructure. It is exercised only with offline mock
transports in default tests and does not yet implement a PyPI, GitHub, OSV, or NVD crawler.

Phase 3 adds the first source-specific vertical slice: authoritative PyPI project JSON
is preserved as raw evidence, normalized into PEP 440 version records, validated, and
exported deterministically. It does not add GitHub correlation, advisories, ranges, or
new CLI pipeline commands.

## Target users

- VinSOC AppSec/SAST analysts who need evidence-backed applicability verdicts.
- Detection-content and AI/RAG engineers who will consume stable normalized records.
- Python maintainers who will extend and operate the crawler through documented CLI commands.

## Pain & gain (mapping table — the traceability spine of the PRD)

Every row: a concrete pain, the evidence it's real, what people do about it today, the
ONE v1 feature that kills it, and the observable gain. If a feature kills no pain, cut
it; if a pain has no feature, it goes to the "not addressed" list — honestly.

| # | Persona | Pain (concrete) | Evidence (stage-01 quote/source or named observation) | Today's workaround | V1 feature that kills it | Observable gain |
|---|---|---|---|---|---|---|
| P1 | Python maintainer | A fresh checkout has no installable package or declared dependency boundary. | Phase 0 checklist in `.agents/implementation_plan.md`. | Ad-hoc commands and global packages. | FR1 | Editable install succeeds in an isolated environment. |
| P2 | Python maintainer | Planned clients, extractors, normalizers, resolvers, validators, exporters, schemas, tests, and data outputs have no stable repository locations. | Architecture in `.agents/context.md`. | Create paths opportunistically during later tasks. | FR2 | All planned boundaries exist before feature work begins. |
| P3 | Crawler operator | There is no stable command seam to discover or invoke. | Phase 0 acceptance criterion in `.agents/implementation_plan.md`. | Read implementation files or wait for later commands. | FR3 | `python -m crawler --help` exits 0 and lists the program purpose/version option. |
| P4 | Security engineer | Package-specific source and crawl behavior risks being hardcoded, and token handling is undocumented. | Configuration and credential rules in `.agents/context.md` and `.agents/rules.md`. | Modify code and pass credentials inconsistently. | FR4 | A committed urllib3 config and secret-free environment template expose the intended settings. |
| P5 | Maintainer | Changes have no repeatable bootstrap quality gate. | Testing requirements in `.agents/implementation_plan.md`. | Manual inspection only. | FR5 | Offline tests, Ruff, and Mypy return success for the bootstrap. |
| P6 | New contributor | Setup, scope, commands, and source-trust rules are spread across planning documents. | Internal adoption path identified in stage 01. | Ask maintainers or rediscover commands. | FR6 | README provides one reproducible setup and verification path. |
| P7 | Repository owner | Environments, caches, tokens, and generated crawl output could be committed accidentally. | Security rules in `.agents/context.md` and `.agents/rules.md`. | Manually inspect every commit. | FR7 | Ignore rules exclude local secrets, tooling state, and generated data while preserving directory structure. |
| P8 | Detection-content engineer | Producers and consumers have no typed definition of version, advisory, patch, security-pattern, KB-document, or provenance records. | Phase 1 checklist and normalized-record contract in `.agents/implementation_plan.md` and `.agents/context.md`. | Infer shapes from prose independently. | FR8 | All six record types import and reject fields outside their declared contracts. |
| P9 | Non-Python consumer | There is no language-neutral validation artifact for normalized records. | Phase 1 JSON Schema acceptance criteria in `.agents/implementation_plan.md`. | Reimplement Pydantic assumptions in each consumer. | FR9 | Every example serializes to JSON and validates against its checked-in matching schema. |
| P10 | Pipeline maintainer | Reprocessing identical evidence can create unstable identifiers or list ordering. | Determinism requirements in `.agents/context.md`. | Ad-hoc hashes and source-order preservation. | FR10, FR11 | Identical identity inputs yield identical IDs and set-like fields serialize in deterministic order. |
| P11 | Security analyst | Missing source facts can be silently replaced by guessed defaults, obscuring evidence quality. | Unknown-value and provenance requirements in `.agents/context.md`. | Read raw sources manually to distinguish facts from assumptions. | FR11, FR12 | Unknown optional facts remain null, empty collections remain empty, and every top-level record carries source provenance. |
| P12 | Source-adapter maintainer | Each future connector could implement different timeout, retry, and error behavior. | Phase 2 checklist and crawl engineering requirements in `.agents/implementation_plan.md` and `.agents/context.md`. | Duplicate ad-hoc HTTP calls. | FR13, FR14 | One configured client classifies failures and retries only approved transient conditions. |
| P13 | Pipeline operator | A repeated crawl currently cannot reuse preserved bytes or run offline. | Cache/idempotency requirements in `.agents/context.md`. | Contact the provider again. | FR15 | The second identical request is served from verified local raw storage without transport access. |
| P14 | Repository owner | Tokens, authorization headers, cookies, or unbounded bodies could leak into files/logs or exhaust disk/memory. | Security rules in `.agents/rules.md`. | Manual review after every request. | FR16 | Sensitive headers/query credentials are rejected or scoped, persisted headers are allowlisted, and oversized bodies fail before storage. |
| P15 | Detection-content engineer | There is no authoritative machine-readable inventory of urllib3 releases and distributions. | Phase 3 checklist in `.agents/implementation_plan.md`. | Inspect PyPI manually or compare version strings incorrectly. | FR17, FR18 | One preserved PyPI response produces provenance-backed PEP 440 records for every parsable release and distribution. |
| P16 | Pipeline maintainer | Malformed, duplicate-normalized, or wrong-project PyPI metadata could silently corrupt later range resolution. | Version validation and untrusted-input rules in `.agents/context.md` and `.agents/rules.md`. | Trust provider JSON without semantic checks. | FR19 | Invalid project identity, artifacts, digests, dates, or normalized collisions fail with actionable typed errors before export. |
| P17 | Crawler operator | Unparsable versions and inventory coverage are invisible, and output ordering can vary by source order. | Phase 3 statistics/determinism requirements in `.agents/implementation_plan.md`. | Count and sort releases manually. | FR20 | Deterministic JSONL plus explicit totals and unparsable-version reporting are available from the inventory result. |

### Pains NOT addressed in v1 (deliberate — tie to the scope cut list)

- Analysts still perform manual vulnerability applicability analysis → deferred because models, source clients, range resolution, and security-semantic enrichment belong to Phases 1–9.
- Maintainers still lack automated CI and a published artifact → deferred until local bootstrap behavior is stable and a delivery platform is selected.

## Problem statement

The repository cannot safely begin crawler implementation until it has an installable, typed, testable, documented CLI skeleton with explicit configuration and architectural boundaries. Phase 0 must provide that foundation without inventing domain contracts or contacting remote sources.

## Features (user-centric — action → observable result)

Tag each v1 feature with a stable id `FRn:` (functional requirement) — the traceability
anchor. Every `FRn` must later be claimed by a card (`implements: FRn`) and served by an
interface in the contract (`FRn →`); `/flow consistency` checks this mechanically.

- FR1: As a maintainer, I install the project in an isolated Python environment, and the package plus declared runtime/development dependencies install successfully.
- FR2: As a maintainer, I inspect the repository, and I see the planned package, schema, test, fixture, raw-data, normalized-data, and KB boundaries without premature feature implementations.
- FR3: As an operator, I run `python -m crawler --help` or `python -m crawler --version`, and I receive concise output with exit code 0.
- FR4: As a maintainer, I open `configs/urllib3.yaml` and `.env.example`, and I see package/source/output/crawl settings plus credential names without secret values.
- FR5: As a contributor, I run the configured tests, formatter/linter, and type checker, and each returns exit code 0 for the bootstrap code.
- FR6: As a new contributor, I follow the README, and I can create the environment, install the project, invoke the CLI, and run quality checks without undocumented steps.
- FR7: As a repository owner, I inspect Git status after local setup or generated output, and environments, caches, secrets, logs, and generated crawl artifacts remain untracked while intentional directory markers remain versioned.
- FR8: As a Python producer or consumer, I import the six typed Phase 1 records plus source-priority, detection-type, confidence, package, identifier, version-range, and provenance shapes, and invalid or undeclared fields are rejected.
- FR9: As a non-Python consumer, I validate serialized records using checked-in Draft 2020-12 JSON Schemas, and each schema accepts the matching model output while schema drift is detected by tests.
- FR10: As a pipeline maintainer, I derive a record ID from a record type and explicit identity data, and identical semantic input produces an identical SHA-256-based identifier regardless of mapping/set ordering.
- FR11: As a downstream consumer, I serialize records and receive UTF-8-compatible JSON values, timezone-aware ISO-8601 timestamps, explicit nulls for unknown scalar facts, empty arrays for known-empty collections, and deterministic ordering for set-like lists without altering ordered event/API sequences.
- FR12: As a maintainer, I read the data-contract decision document and see the canonical advisory-ID policy, date format, null/empty rules, ordering, version-range representation, provenance structure, and schema-versioning policy before source adapters are implemented.
- FR13: As a source-adapter maintainer, I load typed crawl settings and fetch an HTTPS resource through one synchronous HTTPX client with explicit timeout, maximum response size, deterministic request identity, and actionable typed errors.
- FR14: As an operator, I encounter a timeout, connection reset, HTTP 429/500/502/503/504, or GitHub rate-limit response, and the client performs only bounded exponential retries while respecting valid bounded `Retry-After` or reset delays.
- FR15: As a pipeline maintainer, I repeat an identical method/normalized-URL/body request, and the client returns the SHA-256-verified cached bytes plus raw request/response metadata without a network call while logging cache hit/miss state.
- FR16: As a security engineer, I provide `GITHUB_TOKEN` through the environment, and it is sent only as an authorization header to `api.github.com`; credentials, cookies, authorization headers, and response bodies never appear in cache metadata or logs, and unsafe URLs/headers/oversized responses are rejected.
- FR17: As a crawler operator, I request a configured project through the PyPI adapter, and the adapter fetches exactly `https://pypi.org/pypi/<canonical-project>/json` through the shared retrieval client so the authoritative response is retained in the raw store.
- FR18: As a detection-content engineer, I normalize a retrieved PyPI response, and I receive one provenance-backed `VersionRecord` per unique parsable PEP 440 release with every distribution artifact, release date, Python requirement, prerelease state, and yanked evidence preserved without invented values.
- FR19: As a pipeline maintainer, I process untrusted PyPI metadata, and wrong-project responses, unsafe artifact paths/URLs, malformed digests/dates/types, and duplicate normalized versions fail explicitly before deterministic JSONL is written atomically.
- FR20: As a crawler operator, I inspect a version inventory and its exported JSONL, and records are PEP 440 sorted while totals for versions, prereleases, yanked releases, artifacts, and detected unparsable release keys are deterministic.

## Non-functional requirements

- Support CPython 3.11 and newer; verify Phase 0 on CPython 3.12.
- Use UTF-8 text, deterministic configuration, and no network access in default tests.
- Keep secrets absent from tracked files and logs; `.env.example` contains names and documentation only.
- Use typed public Python functions and strict-enough Ruff/Mypy settings suitable for incremental adoption.
- Keep the CLI import side-effect free and return non-zero codes for future unrecoverable failures.
- Generate record IDs locally with SHA-256 over canonical JSON; never include credentials or unbounded source bodies in identity input.
- Reject timezone-naive timestamps, malformed SHA-256 digests, and unknown fields.
- Keep schema generation deterministic and make tests fail when checked-in schemas drift from model definitions.
- Permit HTTPS only, reject userinfo and credential-like query parameters, and never follow redirects implicitly in the shared retrieval layer.
- Bound retries, retry delays, configuration size, response bytes, and persisted metadata; verify cached body hashes on every read.
- Keep clocks, sleepers, and HTTP transports injectable so default tests remain offline and deterministic.

## Tech stack

- Runtime: Python `>=3.11`, Typer/Rich for the CLI, HTTPX for bounded synchronous retrieval, Pydantic/PyYAML for typed configuration, and existing Packaging/JSON Schema support. The retry loop is explicit so provider delays and injected clocks are testable.
- Development: pytest, pytest-cov, respx, Ruff, and Mypy.
- Packaging: PEP 517/621 `pyproject.toml` with an editable install and a `crawler` package; no database, frontend, or deployment target in Phase 0.
- Configuration: YAML package config and environment-variable names for credentials; no `.env` loading or remote client behavior yet.

## Success metric (numbers only)

2 Phase 0 acceptance commands continue to return exit code 0; 6 Phase 1 model families
retain schema agreement; 1 repeated Phase 2 request produces exactly 1 transport call;
1 authoritative PyPI response produces a duplicate-free PEP 440-sorted inventory; 100%
of fixture releases are either exported or explicitly reported unparsable; 100% of
tests pass; and 0 secret values occur in persisted metadata or captured logs.
