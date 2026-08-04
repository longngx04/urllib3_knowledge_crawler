# Security pattern extraction (Phase 8)

Phase 8 converts normalized advisories and optional patch evidence into
`SecurityPatternRecord` objects suitable for AI-assisted SAST verdicts.

## Library flow

```python
from crawler.normalizers.advisories import normalize_osv_vulnerability
from crawler.normalizers.patches import normalize_github_commit
from crawler.normalizers.patterns import (
    build_security_pattern_inventory,
    normalize_security_pattern,
)
from crawler.exporters.jsonl import export_security_pattern_inventory

pattern = normalize_security_pattern(
    advisory,
    patch=patch_record,
    changelog_text=optional_release_notes,
)
inventory = build_security_pattern_inventory(
    package=advisory.package,
    records=[pattern],
)
export_security_pattern_inventory(inventory, output_directory)
```

## Extraction order

The rule-based extractor consults evidence in this order:

1. Structured affected/fixed fields on the advisory (copied verbatim; never invented).
2. Maintainer advisory summary and impact text.
3. Patch diff symbols, modules, and added guards.
4. Optional changelog or release-note text supplied by the caller.
5. Unsupported gaps are recorded in `confidence.rationale` as explicit
   `unsupported inference:` entries.

LLM inference is **not** used in Phase 8.

## Detection types

Each pattern receives one `DetectionType` based on extracted evidence:

| Type | Requires |
|---|---|
| `version_api` | affected version + vulnerable symbol/API |
| `version_api_configuration` | above + dangerous argument/configuration |
| `version_api_dataflow` | above + attacker-controlled data-flow hint |
| `version_api_configuration_dataflow` | configuration and data-flow both present |

## SAST usefulness score

`compute_sast_usefulness_score` counts eight components (affected range, fixed
version, vulnerable symbol, precondition, dangerous configuration, negative
condition, remediation, patch or test evidence) and returns
`available_components / 8` as a float in `[0, 1]`. The score is appended to
`confidence.rationale` on each exported record as `sast_usefulness_score=…`.

## Output

Successful export writes `data/normalized/security_patterns.jsonl` using the same
atomic replace pattern as `versions.jsonl` and `patches.jsonl`. Generated data
remains git-ignored.

## Limitations

- Symbol qualification uses patch path heuristics; cross-file call chains are not
  reconstructed.
- Data-flow hints depend on advisory/changelog keywords and redirect-related
  symbols; full taint analysis is out of scope.
- Only the primary advisory range is copied when multiple ranges exist.
- Changelog text must be supplied by a future release/changelog integration; absence
  is marked as an unsupported inference.
