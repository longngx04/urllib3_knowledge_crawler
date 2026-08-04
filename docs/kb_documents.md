# KB document generation (Phase 9)

Phase 9 converts normalized security patterns (and optional advisory or patch records)
into retrieval-oriented `KBDocumentRecord` objects for RAG or vector indexing.

## Library flow

```python
from crawler.normalizers.patterns import normalize_security_pattern
from crawler.normalizers.kb_documents import generate_kb_documents_from_patterns
from crawler.exporters.jsonl import export_kb_document_inventory

result = generate_kb_documents_from_patterns(
    package=pattern.package,
    patterns=[pattern],
    advisories=[advisory],
    patches=[patch],
)
export_kb_document_inventory(result.inventory, output_directory)
print(result.stats.duplicate_rate)
```

## Topic mapping

Each high-value security pattern yields one document per topic. Plan topics are
encoded in the document title and stable record identity; the wire schema keeps the
existing four `KBDocumentType` values:

| Plan topic | `KBDocumentType` | Title prefix |
|---|---|---|
| `vulnerability_overview` | `advisory` | Vulnerability overview |
| `detection_guidance` | `security_pattern` | Detection guidance |
| `negative_conditions` | `security_pattern` | Negative conditions |
| `remediation_guidance` | `security_pattern` | Remediation guidance |
| `patch_evidence` | `patch` | Patch evidence |

## Metadata filters

Every document attaches `KBDocumentMetadata` with:

- `package_name`
- `advisory_ids` (canonical plus aliases)
- `affected_versions` and `fixed_versions` from pattern version evidence
- `symbols` from vulnerable usage
- `detection_type` and `confidence` copied from the pattern

`source_record_ids` links back to the security pattern and, when supplied, the
advisory or patch record used to enrich overview or patch-evidence documents.

## Content limits and deduplication

- Maximum content size: **32 KiB** UTF-8 (`MAX_CONTENT_BYTES`).
- Identical `content` values are skipped when building an inventory; `duplicate_rate`
  reports `duplicates_skipped / documents_attempted`.

## Export path

`export_kb_document_inventory` writes atomically to:

```text
<output_directory>/kb/documents.jsonl
```

Records are sorted deterministically by primary advisory id, title, and record id.

## Non-goals (Phase 9)

- Pipeline CLI `build-kb` command (Phase 11).
- Global `stats.json` duplicate metrics (Phase 10).
- LLM summarization or chunk splitting.
