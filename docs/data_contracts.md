# Phase 1 data contracts

Phase 1 defines the wire format shared by crawlers, normalizers, validators, exporters,
and SAST consumers. These contracts describe evidence; they do not resolve aliases or
version ranges and do not add facts missing from upstream sources.

## Record families

`crawler.models` exposes `VersionRecord`, `AdvisoryRecord`, `PatchRecord`,
`SecurityPatternRecord`, `KBDocumentRecord`, and `ProvenanceRecord`. Every top-level
record except the nested provenance object includes:

- `schema_version` fixed to `1.0`;
- a fixed `record_type` for the concrete model;
- a stable `record_id`;
- package name, ecosystem, and purl;
- at least one provenance entry.

Models are frozen and reject unknown fields. Optional unknown scalar facts are serialized
as `null`; known-empty collections are serialized as `[]`. Producers must not replace an
unknown upstream value with an empty string, sentinel date, guessed severity, inferred
alias, or invented version boundary.

## Canonical advisory identity

Canonical advisory IDs use this priority:

1. a maintainer-published GHSA;
2. a CVE explicitly linked by an authoritative source;
3. an OSV/PYSEC identifier when neither authoritative identifier exists.

Observed identifiers are retained in `identifiers.aliases`. Phase 1 provides the shape
but deliberately does not infer alias relationships. A later resolver must preserve
conflicts and evidence rather than silently choosing a link.

## Dates and unknown values

All timestamps are timezone-aware ISO-8601 values. UTC may serialize with the `Z` suffix.
Timezone-naive datetimes are invalid. An unknown timestamp remains `null`; `1970-01-01`,
the current time, and empty strings are not valid substitutes.

## Ordering and normalization

Set-like lists such as aliases, CWE IDs, versions, files, symbols, references,
workarounds, source-record IDs, and confidence rationale are deduplicated and sorted.
Version lists are parsed, normalized, and ordered with `packaging.version.Version`; raw
string comparison is forbidden.

Order-bearing lists remain in source/semantic order. In particular, version events,
API call sequences, and required data-flow steps are never sorted. Provenance and
evidence entries use explicit deterministic sort keys.

## Version ranges

A `VersionRange` contains:

- `raw`: the exact source expression when one exists, otherwise `null`;
- `events`: ordered boundary objects containing exactly one of `introduced`, `fixed`,
  `last_affected`, or `limit`;
- `resolved`: deterministically ordered versions only after a resolver has evidence;
- `fixed_versions`: explicitly supported fixed releases.

Phase 1 does not calculate affected versions. Producers leave `resolved` empty until a
later range resolver performs PEP 440-aware matching against the version inventory.

## Provenance

Every top-level record carries one or more provenance entries with `source_type`,
`source_id`, timezone-aware `retrieved_at`, the full lowercase SHA-256 of the preserved
raw response, and `extractor_version`. Retrieval time is evidence metadata and is not
normally part of a record's identity.

## Stable record IDs

`stable_record_id(record_type, identity)` hashes only explicit identity fields. It
canonicalizes mapping keys and set members, emits UTF-8 JSON without insignificant
whitespace, and returns `<record-type>:<full-lowercase-sha256>`. Ordered lists keep their
order. Callers must not include credentials, raw response bodies, confidence, retrieval
time, or other volatile metadata unless those values genuinely define identity.

Recommended identity inputs are the normalized version for a version record, canonical
advisory ID for an advisory/security-pattern record, commit SHA for a patch record, and
source-record ID plus document type for a KB document.

## JSON Schemas and compatibility

The six files under `schemas/` are deterministic Draft 2020-12 schemas generated from
the Pydantic serialization contracts. Tests compare generated and checked-in files
byte-for-byte and validate representative serialized records.

Schema version `1.0` follows these compatibility rules:

- clarifications and compatible optional additions may retain the current major version;
- removing/renaming fields, tightening accepted existing values, or changing field
  semantics requires a new major schema version;
- application package versions and schema versions evolve independently;
- schema changes land with model changes, regenerated files, migration notes, and tests
  in the same commit.

Phase 3 makes a compatible optional addition to `DistributionArtifact`: package type,
Python tag, per-file `requires_python`, upload timestamp, and yanked state/reason. These
fields preserve PyPI's file-level evidence when a release contains distributions with
different metadata. Existing producers remain valid because the new scalar fields are
optional and `is_yanked` defaults to `false`; the checked-in version schema is regenerated
with the implementation and serialization tests.

To regenerate schemas intentionally:

```bash
python -c 'from pathlib import Path; from crawler.exporters.schemas import export_json_schemas; export_json_schemas(Path("schemas"))'
```
