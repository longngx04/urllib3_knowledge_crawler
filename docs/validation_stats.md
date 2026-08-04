# Validation and statistics (Phase 10)

Phase 10 validates normalized inventory bundles and computes reproducible quality
metrics from exported records. Library APIs are composable; pipeline CLI commands
remain a later phase.

## Validation flow

```python
from crawler.validators.pipeline import (
    InventoryBundle,
    ValidationOptions,
    export_validation_errors,
    validate_inventory_bundle,
)
from crawler.exporters.stats import (
    compute_pipeline_stats,
    export_manifest,
    export_stats,
)

validation = validate_inventory_bundle(
    bundle,
    options=ValidationOptions(
        strict=False,
        include_range_issues=True,
        include_patch_release_checks=True,
    ),
)
export_validation_errors(validation.findings, output_directory)

stats = compute_pipeline_stats(bundle, validation=validation)
export_stats(stats, output_directory)
export_manifest({"stats.json": "<sha256>"}, output_directory)
```

## Checks performed

| Check | Severity | Description |
|---|---|---|
| `schema` | error | Draft 2020-12 JSON Schema validation per `record_type` |
| `version` | error | PEP 440 inventory invariants via `validate_version_inventory` |
| `provenance` | error | Every normalized record must include provenance |
| `duplicate` | error | Duplicate `record_id` or canonical advisory identifiers |
| `alias` | error | One alias mapping to multiple canonical advisories |
| `range` | error (optional) | Range-resolution issues surfaced when configured |
| `reference` | error | Advisory/patch URLs must be syntactically valid |
| `patch_release` | soft | Claimed fixed versions should exist in the version inventory |

Each finding includes `record_id`, `check`, and `reason`. Strict mode raises
`PipelineValidationError` so callers can map failures to exit code 1.

## Machine-readable errors

`export_validation_errors` writes `validation_errors.json`:

```json
{
  "error_count": 1,
  "findings": [
    {
      "record_id": "advisory:…",
      "check": "patch_release",
      "reason": "claimed fixed version is absent from version inventory: 88.0.0"
    }
  ]
}
```

## Required metrics (`stats.json`)

All metrics are computed from the inventory bundle and optional validation result:

| Metric | Source |
|---|---|
| `total_versions`, `total_prereleases`, `total_yanked_versions` | Version records |
| `total_advisories`, `total_aliases`, `total_patches` | Record counts |
| `total_security_patterns`, `total_kb_documents` | Record counts |
| `version_coverage` | Versions with git tag or commit SHA / total versions |
| `range_resolution_rate` | Resolvable advisories / total (or supplied range stats) |
| `alias_resolution_rate` | Advisories without alias/duplicate findings |
| `patch_resolution_rate` | Patches whose fixed versions exist in inventory |
| `fixed_release_verification_rate` | Verified fixed-version claims / total claims |
| `provenance_coverage` | Records without provenance findings / total records |
| `schema_validation_rate` | Records without schema findings / total records |
| `duplicate_rate` | Duplicate findings / total records |
| `average_sast_usefulness_score` | Mean `compute_sast_usefulness_score` over patterns |
| `crawl_duration_seconds` | `null` when derived from files only |
| `cache_hit_rate` | `null` when retrieval metrics were not supplied |
| `failed_request_count` | `0` when retrieval metrics were not supplied |

The `_notes` object documents why runtime metrics may be null or zero.

## Manifest

`export_manifest` writes sorted `{path, sha256}` entries for every exported artifact.
Use `sha256_file` to digest on-disk JSONL or metadata files before manifest export.

## Limitations

- Validation operates on in-memory bundles or serialized records; it does not yet
  load JSONL from disk automatically.
- Reference validation checks URL syntax only, not reachability.
- Patch/release checks are soft: they report missing inventory matches but do not
  verify commit inclusion in a release tag.
- Runtime crawl metrics require a future retrieval instrumentation pass.
