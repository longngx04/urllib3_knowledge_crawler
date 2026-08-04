# urllib3 Knowledge Crawler

`urllib3-knowledge-crawler` is an internal Python CLI for building version-aware,
evidence-backed security knowledge about `urllib3` for AI-assisted SAST. The eventual
pipeline will connect package versions and authoritative advisories to relevant APIs,
configuration, data-flow conditions, negative conditions, patches, and regression
tests.

## Current scope (Phases 0–12)

Phase 0 provides an installable typed package, discoverable CLI seam, package-specific
configuration, repository boundaries, offline tests, and local quality tooling. Phase 1
adds strict domain records, deterministic record identifiers, and checked-in JSON
Schemas. The data-contract decisions are documented in
[`docs/data_contracts.md`](docs/data_contracts.md).

Phase 2 adds a security-bounded HTTPS retrieval client, transient/rate-limit retry,
scoped GitHub authentication, and a SHA-256-verified raw response cache. Its safety and
replay contract is documented in [`docs/retrieval.md`](docs/retrieval.md).

Phase 3 adds the first source-specific vertical slice: public PyPI project metadata is
preserved, normalized into PEP 440-sorted version records, semantically validated, and
atomically exported as deterministic JSONL. Its usage and aggregation rules are
documented in [`docs/pypi_versions.md`](docs/pypi_versions.md).

Phase 4 correlates GitHub releases/tags and changelog entries with the version
inventory. Phase 5 collects OSV advisories and merges explicitly linked alias clusters.
Phase 6 resolves advisory ranges against the PyPI inventory into deterministic affected-
version lists; see [`docs/range_resolution.md`](docs/range_resolution.md). Phase 7
enriches advisories with official commit diff evidence and regression-test paths; see
[`docs/patch_enrichment.md`](docs/patch_enrichment.md). Phase 8 extracts SAST-oriented
security patterns from advisories and patch evidence; see
[`docs/security_patterns.md`](docs/security_patterns.md). Phase 9 generates
retrieval-oriented KB documents from security patterns; see
[`docs/kb_documents.md`](docs/kb_documents.md). Phase 10 validates normalized
inventories and exports reproducible `stats.json`, `manifest.json`, and
`validation_errors.json`; see [`docs/validation_stats.md`](docs/validation_stats.md).
Phase 11 wires the full pipeline and query demo through the CLI; see
[`docs/cli.md`](docs/cli.md) and [`docs/running.md`](docs/running.md). Phase 12 adds
deterministic fixture tests, dependency locking, and reproducibility documentation; see
[`docs/reproducibility.md`](docs/reproducibility.md).

Default tests remain offline. Live network access is required only for operator crawls
without `--offline` / fixture mode.

## Reproducibility

Phase 12 locks development dependencies in [`requirements.lock`](requirements.lock)
and documents exact offline verification commands in
[`docs/reproducibility.md`](docs/reproducibility.md). Run the deterministic fixture
test module directly:

```bash
pytest tests/test_deterministic_pipeline.py
```

Fresh output directories produce semantically identical normalized JSONL once volatile
`retrieved_at` provenance timestamps are excluded; reusing the same `--output` path
yields byte-identical exports via the verified raw cache.

Python 3.11 or newer is required. Phase 0 is verified with Python 3.12.

## Setup

From a fresh checkout, create an isolated environment and install the project with
its development tools:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The editable install provides both the module entry point and the `urllib3-kb`
console script.

## Commands

```bash
python -m crawler --help
python -m crawler --version
urllib3-kb --help
urllib3-kb --version
```

The exact version output is:

```text
urllib3-knowledge-crawler 0.1.0
```

### Pipeline (Phase 11)

Run the full offline fixture pipeline (no network):

```bash
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb \
  --offline \
  --fixture-dir tests/fixtures/pipeline
```

Individual stages:

```bash
python -m crawler crawl --config configs/urllib3.yaml
python -m crawler normalize --config configs/urllib3.yaml
python -m crawler enrich --config configs/urllib3.yaml
python -m crawler validate --config configs/urllib3.yaml
python -m crawler build-kb --config configs/urllib3.yaml
python -m crawler stats --config configs/urllib3.yaml
```

Query demo (after normalize + enrich or `run`):

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.6.0 \
  --output /tmp/urllib3-kb
```

Use `--output` to override `output.directory` from the YAML config. See
[`docs/cli.md`](docs/cli.md) for exit codes, offline mode, and options.

## Quality checks

All bootstrap tests are offline. Run the complete local gate from the repository
root:

```bash
pytest
ruff check .
ruff format --check .
mypy crawler
```

## PyPI version inventory

Phase 3 exposes composable library APIs rather than a new pipeline command. A caller
constructs the shared `RetrievalClient`, fetches project JSON with
`PyPIClient.fetch_project`, normalizes it with `normalize_pypi_versions`, and writes the
validated inventory with `export_version_inventory`.

The committed configuration produces the planned paths `data/raw/pypi/` and
`data/normalized/versions.jsonl`. Generated source and normalized data stay ignored by
Git. See `docs/pypi_versions.md` for a complete example and the exact validation rules.

## Configuration and credentials

[`configs/urllib3.yaml`](configs/urllib3.yaml) is the package-specific configuration
contract. It records the target package, authoritative sources, repository metadata,
deterministic output settings, and conservative crawl defaults. The shared retrieval
loader consumes its bounded `crawl` section; callers pass the package identity to the
Phase 3 normalizer explicitly.

Optional upstream credential names are documented in `.env.example`. Copy it to an
ignored local `.env` only when a later phase requires authenticated source access:

```bash
cp .env.example .env
```

Never commit token values. Credentials must come from environment variables and must
not be printed, logged, cached, or persisted by the crawler.

## Repository layout

```text
crawler/
  clients/       # Remote-source adapters, currently PyPI
  extractors/    # Raw evidence extraction (later phase)
  normalizers/   # Deterministic source normalization
  resolvers/     # Alias/version/patch resolution (later phase)
  resolvers/     # Alias clustering and version-range resolution
  validators/    # Schema, inventory, and pipeline validation
  exporters/     # JSON Schema, JSONL, stats, and manifest output
  utils/         # Shared hashing, retrieval, cache, and retry helpers
schemas/         # Checked-in Phase 1 JSON Schema contracts
tests/fixtures/  # Offline test inputs
data/raw/        # Preserved source responses
data/normalized/ # Deterministic normalized JSONL
data/kb/         # Retrieval-oriented documents
```

Generated content under `data/` is ignored; explicit `.gitkeep` markers preserve the
intended boundaries.

## Source trust and security

Maintainer advisories and the official `urllib3` repository have highest priority,
followed by PyPI and structured OSV/GHSA/NVD records. Later implementations must
preserve raw evidence and provenance, report source conflicts, and never invent
affected ranges, fixed versions, aliases, severity, dates, or patch identity.

All remote content is untrusted data. It must be bounded and validated, must never be
executed, and must never control an unchecked filesystem path. The project does not
generate exploits, persist authorization headers, or treat LLM inference as an
authoritative security fact.
