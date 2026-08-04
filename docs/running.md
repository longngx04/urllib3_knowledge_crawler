# Running the urllib3 knowledge crawler

This guide explains how to install, configure, and run the pipeline. Phase 11 provides
the full CLI surface:

```bash
python -m crawler crawl --config configs/urllib3.yaml
python -m crawler normalize --config configs/urllib3.yaml
python -m crawler enrich --config configs/urllib3.yaml
python -m crawler validate --config configs/urllib3.yaml
python -m crawler build-kb --config configs/urllib3.yaml
python -m crawler stats --config configs/urllib3.yaml
python -m crawler run --config configs/urllib3.yaml
python -m crawler query --package urllib3 --version 2.6.0 --symbol HTTPConnectionPool.urlopen
```

Library APIs remain available for programmatic use (see module docs under `docs/`).

## 1. Prerequisites

- CPython 3.11+ (verified on 3.12)
- Network access only for live crawls (PyPI, GitHub, OSV)
- Optional: `GITHUB_TOKEN` for higher GitHub API rate limits

## 2. Install

```bash
git clone https://github.com/longngx04/urllib3_knowledge_crawler.git
cd urllib3_knowledge_crawler
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

Verify:

```bash
python -m crawler --help
python -m crawler --version
pytest -q
ruff check .
mypy crawler
```

## 3. Configuration

Package-specific settings live in `configs/urllib3.yaml`:

- `package.*` — name, ecosystem, purl, repository
- `sources.*` — enable/disable PyPI, GitHub, OSV, patches, etc.
- `output.directory` — default `data`
- `crawl.*` — timeouts, retries, max response bytes, cache

Credentials (never commit):

```bash
cp .env.example .env
# edit .env
export GITHUB_TOKEN=...   # optional
# NVD_API_KEY is reserved for optional later enrichment
```

Load secrets via your shell environment. The crawler must not print tokens.

## 4. Output layout

```text
data/
  raw/           # preserved HTTP bodies + metadata (gitignored)
  normalized/    # versions.jsonl advisories.jsonl patches.jsonl security_patterns.jsonl
  kb/            # documents.jsonl
```

Raw responses are SHA-256 addressed and reused on cache hits.

## 5. Offline / fixture development

Default tests never need the network:

```bash
pytest --cov=crawler
```

Use fixtures under `tests/fixtures/` for PyPI, GitHub, OSV, and commit payloads.

## 6. Live crawl (operator)

Example library-level sequence (equivalent to `run` once CLI exists):

1. Build `RetrievalClient` + `RawResponseStore` under `data/raw`
2. `PyPIClient.fetch_project("urllib3")` → `normalize_pypi_versions` → `export_version_inventory`
3. `GitHubClient` releases/tags/changelog → release normalizer
4. `OSVClient.query_package` → `normalize_osv_vulnerability` → `AliasResolver` → `resolve_advisory_ranges`
5. For selected advisories with commit SHAs: `fetch_commit` → patch normalizer → export
6. Semantic extractor → security patterns → KB documents
7. Validate + write `stats.json` / `manifest.json`

Always inspect unresolved mappings, alias conflicts, and range issues before trusting
counts in a report.

## 7. Query demo intent

Given package + version + optional symbol, print:

- whether the version is affected
- canonical advisory
- detection type
- symbols / preconditions / negative conditions
- fixed version and remediation
- evidence pointers and confidence

## 8. Safety notes

- Treat all remote content as untrusted data
- Do not execute downloaded code
- Do not commit `data/` or `.env`
- Prefer cached raw bodies for reproducibility
