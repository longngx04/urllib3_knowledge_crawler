# urllib3 Knowledge Crawler

`urllib3-knowledge-crawler` is a Python CLI that builds **version-aware, evidence-backed
security knowledge** about [`urllib3`](https://github.com/urllib3/urllib3) for
**AI-assisted SAST**.

It does more than SCA version matching. The pipeline preserves authoritative raw
sources, resolves exact affected releases, attaches API / configuration / data-flow
conditions, links patch and regression-test evidence, and exports retrieval-ready
documents with full provenance.

Engineering report: [`reports/urllib3_crawl_report.md`](reports/urllib3_crawl_report.md).

## Why this exists

SCA feeds answer “is package version V listed as affected?”
SAST still needs:

- which symbols and call paths matter
- which configuration enables the bug
- which data-flow preconditions are required
- which negative conditions make the finding a false positive
- which patch and tests prove the fix

This crawler turns public urllib3 evidence into that structured knowledge.

## Current scope (Phases 0–13)

| Phase | Capability | Docs |
|---|---|---|
| 0 | Installable CLI bootstrap | this README |
| 1 | Typed records + JSON Schemas | [`docs/data_contracts.md`](docs/data_contracts.md) |
| 2 | Secure HTTP / cache / retry | [`docs/retrieval.md`](docs/retrieval.md) |
| 3 | PyPI version inventory | [`docs/pypi_versions.md`](docs/pypi_versions.md) |
| 4 | GitHub releases / tags / changelog | (release normalizers) |
| 5 | OSV advisories + alias merge | [`docs/advisory_collection.md`](docs/advisory_collection.md) |
| 6 | Affected-range resolution | [`docs/range_resolution.md`](docs/range_resolution.md) |
| 7 | Patch + regression enrichment | [`docs/patch_enrichment.md`](docs/patch_enrichment.md) |
| 8 | SAST security patterns | [`docs/security_patterns.md`](docs/security_patterns.md) |
| 9 | KB documents | [`docs/kb_documents.md`](docs/kb_documents.md) |
| 10 | Validation + stats/manifest | [`docs/validation_stats.md`](docs/validation_stats.md) |
| 11 | Full CLI pipeline + query | [`docs/cli.md`](docs/cli.md), [`docs/running.md`](docs/running.md) |
| 12 | Reproducibility / locks | [`docs/reproducibility.md`](docs/reproducibility.md) |
| 13 | Report + operator README | [`reports/urllib3_crawl_report.md`](reports/urllib3_crawl_report.md) |

Optional NVD enrichment remains out of the default path.

## Quick start (clone → first successful run)

```bash
git clone https://github.com/longngx04/urllib3_knowledge_crawler.git
cd urllib3_knowledge_crawler
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

# 1) Prove the install offline (no network, no token)
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb-offline \
  --offline \
  --fixture-dir tests/fixtures/pipeline

# 2) Optional live crawl into ./data (network required)
cp .env.example .env
# edit .env and set GITHUB_TOKEN=ghp_...  (recommended; never commit .env)
python -m crawler run --config configs/urllib3.yaml --output data
ls data/kb/documents.jsonl data/normalized/*.jsonl data/stats.json
```

The CLI automatically loads allowlisted keys from a local `.env`
(`GITHUB_TOKEN`, `NVD_API_KEY`, `CRAWLER_OFFLINE`). You do **not** need to
`export` them manually if they are present in `.env`. Shell exports still win
over `.env` values.

## Requirements

- CPython **3.11+** (verified on **3.12**)
- Network only for live crawls (PyPI, GitHub, OSV)
- Optional `GITHUB_TOKEN` for higher GitHub API rate limits (strongly recommended
  for live runs; unauthenticated GitHub allows only 60 requests/hour)

## Install

```bash
git clone https://github.com/longngx04/urllib3_knowledge_crawler.git
cd urllib3_knowledge_crawler
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
# optional pinned set:
# python -m pip install -r requirements.lock
```

Verify:

```bash
python -m crawler --help
python -m crawler --version
# expected: urllib3-knowledge-crawler 0.1.0
pytest -q
```

## Configuration

Package identity and crawl toggles: [`configs/urllib3.yaml`](configs/urllib3.yaml).

```bash
cp .env.example .env
# put the token in .env — the CLI loads it automatically:
# GITHUB_TOKEN=ghp_...
```

Rules:

- secrets only in environment / ignored `.env` (never commit `.env`)
- never log, cache, or persist authorization headers
- `NVD_API_KEY` is reserved for optional later enrichment
- generated trees under `data/` are gitignored (only `.gitkeep` markers are tracked)

## How to run (detailed)

### A. Offline fixture pipeline (recommended first run)

No live network. Uses `tests/fixtures/pipeline` via MockTransport:

```bash
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb \
  --offline \
  --fixture-dir tests/fixtures/pipeline
```

Expected summary line (fixture scale):

```text
run complete: 7 versions, 1 advisories, 1 patterns -> /tmp/urllib3-kb
```

Outputs:

```text
/tmp/urllib3-kb/
  raw/                         # SHA-256 preserved responses
  normalized/
    versions.jsonl
    advisories.jsonl
    patches.jsonl
    security_patterns.jsonl
  kb/
    documents.jsonl
  stats.json
  manifest.json
```

### B. Stage-by-stage

```bash
OUT=/tmp/urllib3-kb
CFG=configs/urllib3.yaml
FIX=tests/fixtures/pipeline

python -m crawler crawl     --config $CFG --output $OUT --offline --fixture-dir $FIX
python -m crawler normalize --config $CFG --output $OUT --offline --fixture-dir $FIX
python -m crawler enrich    --config $CFG --output $OUT --offline --fixture-dir $FIX
python -m crawler validate  --config $CFG --output $OUT
python -m crawler build-kb  --config $CFG --output $OUT
python -m crawler stats     --config $CFG --output $OUT
```

Exit codes: `0` success, `1` validation failure (strict), `2` usage error.

### C. Query demo

After `run` / enrich:

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.0.6 \
  --output /tmp/urllib3-kb
```

Optional symbol filter:

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.0.6 \
  --symbol _validate_redirect_url \
  --output /tmp/urllib3-kb
```

Printed fields include package, version, affected flag, canonical advisory, detection
type, symbols, preconditions, negative conditions, fixed version, remediation,
evidence, and confidence.

### D. Live crawl (operator)

Requires network. Put `GITHUB_TOKEN` in `.env` (auto-loaded) or export it.

```bash
cp .env.example .env
# GITHUB_TOKEN=ghp_...   # edit .env; recommended for rate limits
python -m crawler run --config configs/urllib3.yaml --output data
ls data/kb/documents.jsonl data/normalized/*.jsonl data/stats.json
```

Re-run with cache hits (no new network if raw cache is warm):

```bash
python -m crawler run --config configs/urllib3.yaml --output data --skip-crawl
```

Do **not** commit generated `data/` trees (they are gitignored).

### Troubleshooting

| Symptom | Fix |
|---|---|
| `GITHUB_TOKEN` ignored after editing `.env` | Run from the repo root so `.env` is discovered; or `export GITHUB_TOKEN=...`. Confirm with a non-printing check: `python -c "from crawler.utils.envfile import load_default_env_files; import os; load_default_env_files(); print(bool(os.getenv('GITHUB_TOKEN')))"` |
| GitHub HTTP 403 / rate limit | Set a PAT in `.env`; wait for reset; reuse `--skip-crawl` / warm `data/raw` |
| Duplicate tag errors historically | Fixed: tags like `v2.0.5` and `2.0.5` now keep the preferred `v`-prefix tag |
| OSV `fixed` is a commit SHA | Fixed: commit boundaries go to `patch_commits`, not `fixed_versions` |
| `data/kb` empty | You only ran Phase-3 version export, or wrote outputs under `/tmp/...`. Use `--output data` and a full `run` |
| `pytest` wants network | Default tests are offline; do not set `CRAWLER_OFFLINE` incorrectly for unit tests |

## Quality gate

```bash
pytest
pytest tests/test_deterministic_pipeline.py
ruff check .
ruff format --check .
mypy crawler
```

Current offline suite: **244 passed** (after live-crawl hardening).

## What gets crawled (and how)

```text
configs/urllib3.yaml
        │
        ▼
RetrievalClient + RawResponseStore
  (HTTPS, timeouts, retries, rate limits, SHA-256 cache)
        │
        ├── PyPI JSON          → versions.jsonl
        ├── GitHub releases/tags/changelog/commits
        └── OSV query/vulns    → advisories → aliases → ranges
                                      │
                                      ▼
                               patches → security patterns → KB docs
                                      │
                                      ▼
                               validate → stats.json / manifest.json
```

Source trust (highest first): maintainer advisories / official repo → PyPI → OSV/GHSA →
optional NVD. Conflicts are preserved; fixed versions and ranges are never invented.

## Repository layout

```text
crawler/
  clients/      # PyPI, GitHub, OSV adapters
  extractors/   # changelog, patch_diff, semantics
  normalizers/  # versions, advisories, releases, patches, patterns, kb
  resolvers/    # aliases, ranges
  validators/   # inventory + pipeline validation
  exporters/    # JSONL, schemas, stats, manifest
  pipeline.py   # stage orchestration
  cli.py        # Typer commands
configs/urllib3.yaml
schemas/        # Draft 2020-12 contracts
tests/fixtures/ # offline payloads (incl. pipeline/)
docs/           # phase contracts and operator guides
reports/        # crawl / design report
data/           # local crawl output (gitignored)
```

## Reproducibility

See [`docs/reproducibility.md`](docs/reproducibility.md) and
[`requirements.lock`](requirements.lock). Offline double-runs must produce matching
normalized JSONL once volatile `retrieved_at` values are excluded; reusing the same
output directory yields byte-identical exports via the raw cache.

## Security notes

- Treat all remote content as untrusted data
- Never execute downloaded code
- Never commit `.env`, tokens, or `data/` artifacts
- Authorization is injected only for `api.github.com`
- Default tests must not require the network
