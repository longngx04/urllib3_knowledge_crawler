# Version-Range Resolution (Phase 6)

## Overview

Phase 6 resolves advisory version ranges against the authoritative PyPI inventory
produced in Phase 3:

1. **Event evaluation**: OSV-style `introduced` / `fixed` / `last_affected` / `limit`
   boundaries are walked as a state machine. The OSV beginning sentinel `0` means
   “from the first release”.
2. **Specifier evaluation**: when a range has no events but `raw` is a PEP 440
   specifier (for example `>=2.6.0,<2.7.0`), matching uses `packaging.specifiers.SpecifierSet`
   with prereleases enabled.
3. **Inventory projection**: matching releases are written to `VersionRange.resolved`
   and unioned into `AdvisoryRecord.affected_versions`, preserving source order of
   events and the original `raw` string.
4. **Fixed-version verification**: claimed fixed releases are checked against the
   inventory. Missing values are reported; fixed versions are never invented.
5. **Conflict reporting**: fixed versions that also appear in the resolved affected
   set, invalid boundaries, and advisories with no remaining resolvable evidence are
   surfaced as typed issues with coverage metrics.

## Usage Example

```python
from crawler.resolvers.ranges import resolve_advisory_ranges

result = resolve_advisory_ranges(merged_advisories, version_inventory)
for advisory in result.advisories:
    print(advisory.identifiers.canonical, advisory.affected_versions)
print(result.stats.coverage_ratio, len(result.issues))
```

## Non-goals

Phase 6 does not fetch patches, enrich security semantics, call NVD, export
`advisories.jsonl`, or add pipeline CLI commands.
