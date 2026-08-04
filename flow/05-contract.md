# Stage 05 — Interface Contract (the seam)

The contract is whatever sits between your core and its consumer. For a web app that's
API endpoints (the table below). For a CLI it's commands + flags + output shapes; for a
plugin it's hooks + filters; for a pipeline it's input/output file schemas. Keep the
table's SPIRIT — every feature maps to an interface, every interface has its shapes
written before code — and adapt the columns to your project's shape.

Written BEFORE any code. Backend cards build TO this table; UI cards consume FROM it.
The #1 AI-build failure is producer/consumer drift — backend ships one shape, UI assumes
another, both look green. This file is the cheap fix.

## Gate — check ALL before `/flow next`
- [x] Every PRD feature maps to at least one INTERFACE below (web: endpoint · cli: command · library: public function · skill: command/file)
- [x] Every interface has its INPUT and OUTPUT shapes written (web: request+response · cli: flags+output/exit code · library: args+return)
- [x] Access/effects column filled for every interface (web: public/token/admin · non-web: writes/side-effects, or "none")
- [x] No FILL placeholders remain in this file

## OpenAPI / Swagger rule  (web only — N/A for cli/library/skill)

For non-web types there is no served spec; the equivalent "no producer/consumer drift" check
is the per-type done-evidence (the command runs / the API imports / the skill installs+runs).
For `web`:

This table is the PLANNING source of truth. If the framework serves a spec (FastAPI →
`/openapi.json` + `/docs`), the served spec is the RUNTIME artifact of this same contract:
- Path/method/shapes here and in the served spec must agree — the contract-test card
  asserts every endpoint in this table exists in the live `/openapi.json` with matching
  request/response shapes.
- Change flows ONE way: amend this file first, then the code, then the spec follows.
- **Docs land with the API, not after**: the served spec is live from the vertical-slice
  card onward, and every backend card's verify checks its endpoints appear in the live
  `/docs` with correct schemas. The contract-test card later asserts full agreement —
  but by then the docs have been growing card by card, never a catch-up task.
- Keep `/docs` enabled at least until v1 ships — it's the free human-readable contract.

## Interfaces  (web: endpoints · cli: commands · library: functions · skill: commands)

Adapt the columns to your project type. Web: Method/Path/Access(=auth: public/token/admin)/
Request/Response. CLI: Command/Flags/Access(=side-effects)/Input/Output+exit. Library:
Function/—/Access(=none)/Args/Return. The shared column below is "Access/Effects".

| Method/Interface | Path/Name | Access/Effects | Input shape | Output shape |
|---|---|---|---|---|
| Install command | `python -m pip install -e ".[dev]"` | Writes packages into the active isolated environment; no repository data writes | CPython `>=3.11`; repository root containing `pyproject.toml`; optional `dev` extra | Exit `0`; `import crawler` succeeds; console script `urllib3-kb` is installed. Installation failure returns non-zero with packaging diagnostics. |
| CLI command | `python -m crawler --help` / `urllib3-kb --help` | Read-only; no network, config, data, or credential access | No positional arguments; standard `--help` flag | Exit `0`; text contains usage, the version-aware urllib3 security-crawler purpose, `--help`, and `--version`. |
| CLI command | `python -m crawler --version` / `urllib3-kb --version` | Read-only; no network, config, data, or credential access | Standard `--version` flag with no value | Exit `0`; exactly `urllib3-knowledge-crawler 0.1.0` plus a newline. Invalid CLI usage exits `2`. |
| Configuration file | `configs/urllib3.yaml` | Read-only contract in Phase 0; later commands may read it | UTF-8 YAML with the shared `Urllib3Config` shape below | A committed configuration containing package, source, repository, output, and crawl settings; no secrets or environment-specific absolute paths. |
| Environment template | `.env.example` | Read-only documentation; copying it creates a local untracked `.env` | Empty `GITHUB_TOKEN` and `NVD_API_KEY` assignments with comments | Documents credential names without values; neither file nor CLI logs a credential. |
| Quality commands | `pytest`, `ruff check .`, `ruff format --check .`, `mypy crawler` | Read source/test files; pytest may write ignored local caches | Installed `dev` extra from repository root | Each returns exit `0`; pytest is offline and reports all bootstrap tests passed. |
| Package/layout surface | `crawler`, `schemas`, `tests/fixtures`, `data/raw`, `data/normalized`, `data/kb` | Importing `crawler` is read-only; later pipeline stages write only below configured `data` root | Repository checkout or installed `crawler` package | Planned module boundaries import without side effects; tracked markers preserve empty non-package directories. |
| Documentation surface | `README.md` | Read-only | UTF-8 Markdown | Contains project purpose, scope/non-goals, Python requirement, install, CLI, quality commands, configuration, data layout, and source-trust summary. |
| Repository hygiene | `.gitignore` | Controls Git tracking only | Local virtualenvs, `.env`, Python/tool caches, logs, build artifacts, IDE files, and generated data | Those local/generated paths remain untracked; `.env.example`, source, tests, configs, docs, and explicit data-directory markers remain trackable. |
| Library models | `crawler.models` | Import and validation are read-only; no network or filesystem effects | Keyword data for `VersionRecord`, `AdvisoryRecord`, `PatchRecord`, `SecurityPatternRecord`, `KBDocumentRecord`, or `ProvenanceRecord`; strict nested shared shapes | Frozen Pydantic model; undeclared fields, naive timestamps, malformed digests, and invalid enums raise validation errors; `model_dump(mode="json")` yields JSON-compatible values. |
| Stable-ID function | `crawler.utils.hashing.stable_record_id` | Pure; no I/O, randomness, clock, or environment access | `record_type: str`; `identity: Mapping[str, object]` containing bounded, explicit identity values | `<record-type>:<64 lowercase hex SHA-256>` computed from canonical UTF-8 JSON; mapping key order and set/frozenset iteration order do not affect the result; unsupported/non-finite values raise `TypeError`/`ValueError`. |
| Schema exporter | `crawler.exporters.schemas.export_json_schemas` | Writes only the named output directory; creates it if absent | `output_directory: pathlib.Path` | Mapping from six schema filenames to written paths; UTF-8, sorted, indented Draft 2020-12 schemas generated from the six public models. Existing matching files are deterministically replaced. |
| Checked-in schemas | `schemas/*.schema.json` | Read-only for consumers | Serialized JSON object for the matching model | Six Draft 2020-12 schemas (`version`, `advisory`, `patch`, `security_pattern`, `kb_document`, `provenance`) that validate matching model output. |
| Data-contract documentation | `docs/data_contracts.md` | Read-only | UTF-8 Markdown | Records canonical advisory identity, dates, null/empty behavior, list ordering, version ranges, provenance, schema compatibility, and ID derivation policy. |
| Retrieval configuration | `crawler.config.load_http_client_config` | Reads one bounded local UTF-8 YAML file; no environment/network access | `path: Path`; top-level mapping with a `crawl` object | Frozen `HttpClientConfig`; invalid/missing/oversized configuration raises `ConfigurationError` with no secret content. |
| Request identity | `crawler.utils.cache.build_request_identity` | Pure; no I/O | HTTPS method/URL and optional body bytes | `RequestIdentity(method, url, body_sha256, cache_key)`; method uppercase, query pairs deterministically sorted, fragment removed; userinfo/credential-like query keys/unsupported schemes raise `UnsafeRequestError`. |
| Raw response store | `crawler.utils.cache.RawResponseStore` | Atomic writes below its resolved root only; reads and verifies cached bytes | `root: Path`; `load(cache_key)`; `store(identity, status_code, headers, retrieved_at, body)` | `StoredResponse | None`; metadata contains request identity, status/content type/time/body SHA and allowlisted cache/rate headers only; corruption/path violations raise typed errors. |
| Retrieval client | `crawler.utils.http.RetrievalClient.fetch` | Cache read/write and optional HTTPS request; no redirects; auth only for GitHub API | `method`, `url`, optional `content`, non-sensitive `headers`; typed config/store; optional `GITHUB_TOKEN` | `RetrievedResponse(status_code, url, headers, content, retrieved_at, body_sha256, cache_key, from_cache, attempts)`; approved transient failures retry boundedly; permanent/oversized/exhausted failures raise typed actionable errors. |

## Shared shapes (objects used by multiple interfaces)

```text
CLIExit:
  0 = requested help/version command completed successfully
  1 = reserved for a future unrecoverable pipeline failure
  2 = command-line usage error

VersionOutput:
  "urllib3-knowledge-crawler 0.1.0\n"

Urllib3Config:
  package:
    name: "urllib3"
    ecosystem: "PyPI"
    purl: "pkg:pypi/urllib3"
    repository: "urllib3/urllib3"
    version_scheme: "pep440"
  sources:
    pypi: bool
    github_releases: bool
    github_tags: bool
    changelog: bool
    github_advisories: bool
    osv: bool
    nvd: "optional"
    patches: bool
    regression_tests: bool
  repository:
    default_branch: "main"
    changelog_candidates: list[str]
    security_policy_candidates: list[str]
  output:
    directory: "data"
    deterministic: true
    include_raw: true
    include_kb_documents: true
  crawl:
    timeout_seconds: 30
    max_retries: 4
    cache_enabled: true
    respect_rate_limits: true

NormalizedRecordBase:
  schema_version: "1.0"
  record_type: enum fixed by concrete model
  record_id: non-empty stable identifier
  package: {name: str, ecosystem: str, purl: str}
  provenance: non-empty list[ProvenanceRecord]

ProvenanceRecord:
  source_type: non-empty str
  source_id: non-empty str
  retrieved_at: timezone-aware datetime serialized as ISO-8601
  raw_sha256: 64 lowercase hexadecimal characters
  extractor_version: non-empty str

VersionRange:
  raw: str | null
  events: ordered list[{introduced|fixed|last_affected|limit: str}]
  resolved: sorted unique list[str]

Confidence:
  score: float in [0, 1]
  rationale: sorted unique list[str]

SourcePriority:
  tier_1_authoritative | tier_2_contextual | tier_3_enrichment

DetectionType:
  version_only | version_api | version_api_configuration |
  version_api_dataflow | version_api_configuration_dataflow |
  security_assumption_mismatch

HttpClientConfig:
  timeout_seconds: float > 0 and <= 300
  max_retries: int >= 0 and <= 10
  cache_enabled: bool
  respect_rate_limits: bool
  max_response_bytes: int > 0 and <= 104857600
  initial_backoff_seconds: float >= 0
  max_retry_delay_seconds: float > 0 and <= 3600

RawResponseMetadata:
  request: {method: str, url: str, body_sha256: str | null}
  response:
    status_code: int
    content_type: str | null
    retrieved_at: timezone-aware ISO-8601
    body_sha256: 64 lowercase hex
    headers: allowlisted cache/rate-limit header mapping
```

## Feature → interface map

Reference each PRD feature by its `FRn` id so the mapping is machine-checkable
(`/flow consistency` flags any `FRn` with no interface here).

- FR1 → install command and package/layout surface.
- FR2 → package/layout surface.
- FR3 → CLI help and version commands.
- FR4 → configuration file and environment template.
- FR5 → quality commands.
- FR6 → documentation surface plus the install, CLI, configuration, and quality interfaces it documents.
- FR7 → repository hygiene, environment template, and package/layout surface.
- FR8 → library models and shared shapes.
- FR9 → schema exporter and checked-in schemas.
- FR10 → stable-ID function.
- FR11 → library models, stable-ID function, and checked-in schemas.
- FR12 → data-contract documentation.
- FR13 → retrieval configuration, request identity, and retrieval client.
- FR14 → retrieval client and `HttpClientConfig` retry fields.
- FR15 → request identity, raw response store, and retrieval client cache path.
- FR16 → retrieval configuration, request identity, raw response store, and retrieval client security rules.
