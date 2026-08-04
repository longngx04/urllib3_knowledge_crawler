# Advisory Collection & Alias Resolution (Phase 5)

## Overview

Phase 5 builds the vulnerability collection and alias normalization pipeline for `urllib3`:

1. **Raw Storage & Client Boundary**: `OSVClient` queries OSV API (`POST /v1/query` and `GET /v1/vulns/{id}`) via the security-bounded `RetrievalClient`. Responses are integrity-hashed and cached locally in `data/raw/osv/`.
2. **Advisory Normalization**: `normalize_osv_vulnerability` extracts identifiers, aliases, CWEs, CVSS metrics, severity, affected PEP 440 ranges and version events, fixed versions, references, and patch commit SHAs.
3. **Canonical Identifier Strategy**:
   - Priority 1: Maintainer `GHSA` ID (e.g. `GHSA-565x-2c8m-578w`)
   - Priority 2: `CVE` ID (e.g. `CVE-2023-45803`)
   - Priority 3: `PYSEC` or `OSV` ID fallback
4. **Transitive Alias Resolution**: `AliasResolver` groups advisories linked by shared aliases into connected components, merges them deterministically, and flags potential source conflicts (e.g., merging multiple distinct GHSA advisories).
5. **Schema & Model Invariants**: Every record is validated against `AdvisoryRecord` and `schemas/advisory.schema.json`.

## Usage Example

```python
from crawler.clients.osv import OSVClient
from crawler.normalizers.advisories import normalize_osv_vulnerability
from crawler.resolvers.aliases import AliasResolver

# 1. Fetch raw query response
osv_client = OSVClient(retrieval_client)
response = osv_client.query_package("urllib3", ecosystem="PyPI")

# 2. Normalize vulnerabilities
advisories = [
    normalize_osv_vulnerability(vuln_data, provenance=prov)
    for vuln_data in response_json["vulns"]
]

# 3. Resolve and merge alias clusters
resolver = AliasResolver()
merged_advisories, conflicts = resolver.resolve_advisories(advisories)
```
