# CLI Reference (Phase 11)

Phase 11 exposes the full urllib3 knowledge pipeline through Typer subcommands on
`python -m crawler` and the `urllib3-kb` console script.

## Commands

```bash
python -m crawler crawl --config configs/urllib3.yaml
python -m crawler normalize --config configs/urllib3.yaml
python -m crawler enrich --config configs/urllib3.yaml
python -m crawler validate --config configs/urllib3.yaml
python -m crawler build-kb --config configs/urllib3.yaml
python -m crawler stats --config configs/urllib3.yaml
python -m crawler run --config configs/urllib3.yaml
python -m crawler query --package urllib3 --version 2.6.0 [--symbol SYM]
```

Every command supports `--help`.

## Shared options

| Option | Purpose |
| --- | --- |
| `--config PATH` | Required for all pipeline stages except bare `query` |
| `--output PATH` | Override `output.directory` from the YAML config |
| `--offline` | Avoid live network access |
| `--fixture-dir PATH` | Serve HTTP fixtures for offline crawl/enrich |
| `-v` / `--verbose` | Debug logging |

Set `CRAWLER_OFFLINE=1` to force offline mode when `--fixture-dir` is omitted.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Pipeline or strict validation failure |
| `2` | Usage or configuration error |

## Offline fixture workflow

Default tests use `tests/fixtures/pipeline/`:

```bash
python -m crawler run \
  --config configs/urllib3.yaml \
  --output /tmp/urllib3-kb \
  --offline \
  --fixture-dir tests/fixtures/pipeline
```

This produces deterministic JSONL exports under `/tmp/urllib3-kb/normalized/` plus
`stats.json`, `manifest.json`, and optional KB documents.

## Query demo

After running normalize + enrich (or `run`), query one installed version:

```bash
python -m crawler query \
  --package urllib3 \
  --version 2.6.0 \
  --output /tmp/urllib3-kb
```

Optional `--symbol` filters patterns whose vulnerable symbols match.

Printed fields:

- Package, Version, Affected
- Canonical advisory, Detection type
- Relevant symbols, Required preconditions, Negative conditions
- Fixed version, Recommended remediation
- Evidence, Confidence

## Output layout

```text
<output.directory>/
  raw/
  normalized/
    versions.jsonl
    advisories.jsonl
    patches.jsonl
    security_patterns.jsonl
  kb/documents.jsonl
  stats.json
  manifest.json
  validation_errors.json   # when validation finds issues
```

See also [`running.md`](running.md) for installation and operator notes.
