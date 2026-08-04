# Reproducibility

Phase 12 hardens offline verification so reviewers can rerun the fixture pipeline and
trust the normalized outputs without live network access.

## Locked dependencies

[`requirements.lock`](../requirements.lock) captures the exact versions installed in the
reference development environment (CPython 3.12). Regenerate it after dependency
changes:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pip freeze | grep -v '^-e' | sort > requirements.lock
```

Recreate the environment from the lock file:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
python -m pip install -e .
```

Runtime dependencies are declared in [`pyproject.toml`](../pyproject.toml) with
compatible ranges; the lock file pins the versions used for CI and local gates.

## Quality gate (offline)

From the repository root:

```bash
pytest
ruff check .
ruff format --check .
mypy crawler
```

Skip the optional slow editable-install smoke test:

```bash
pytest -m "not slow"
```

## Deterministic fixture pipeline

Run the full offline pipeline twice and compare normalized inventories:

```bash
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb-run1 \
  --offline \
  --fixture-dir tests/fixtures/pipeline

python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb-run2 \
  --offline \
  --fixture-dir tests/fixtures/pipeline
```

Automated coverage lives in [`tests/test_deterministic_pipeline.py`](../tests/test_deterministic_pipeline.py).

### Timestamp behavior

Fresh output directories receive new `retrieved_at` provenance timestamps on the first
crawl because the retrieval client records wall-clock time when storing raw responses.
Reusing the same `--output` directory replays SHA-256-verified cache entries, so byte-
identical JSONL exports are expected on the second run.

For cross-directory comparison, strip volatile `retrieved_at` fields before hashing
JSONL records. The deterministic test helper `normalized_jsonl_digest()` implements this
for:

- `normalized/versions.jsonl`
- `normalized/advisories.jsonl`
- `normalized/patches.jsonl`
- `normalized/security_patterns.jsonl`
- `kb/documents.jsonl`

Semantic content (record IDs, version ranges, pattern fields, document bodies) must
match across runs once timestamps are removed.

## Related offline tests

| Concern | Test module |
| --- | --- |
| Corrupted raw cache | `tests/test_cache.py`, `tests/test_http.py` |
| Rate limits and retries | `tests/test_http.py`, `tests/test_retry.py` |
| Source alias conflicts | `tests/test_alias_resolver.py` |
| CLI smoke / pipeline help | `tests/test_cli.py`, `tests/test_cli_pipeline.py` |
| Clean install metadata | `tests/test_clean_install.py` |
| Validation statistics | `tests/test_validation.py` |

## Clean install verification

Lightweight checks validate `pyproject.toml` metadata and import the installed package
without network access. An optional slow test creates an isolated venv and runs
`pip install --no-deps -e .` to confirm the package layout.

See also [`docs/running.md`](running.md) for operator-oriented pipeline commands.
