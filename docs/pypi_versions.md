# PyPI version inventory

Phase 3 implements the first authoritative source-to-normalized-output slice. It keeps
network retrieval, untrusted JSON normalization, semantic validation, and file export
as separate public boundaries.

## Usage

Run this from an installed checkout with Python 3.11 or newer:

```python
from pathlib import Path

from crawler.clients.pypi import PyPIClient
from crawler.config import load_http_client_config
from crawler.exporters.jsonl import export_version_inventory
from crawler.models import PackageRecord
from crawler.normalizers.versions import normalize_pypi_versions
from crawler.utils.cache import RawResponseStore
from crawler.utils.http import RetrievalClient

config = load_http_client_config(Path("configs/urllib3.yaml"))
store = RawResponseStore(Path("data/raw/pypi"))
package = PackageRecord(
    name="urllib3",
    ecosystem="PyPI",
    purl="pkg:pypi/urllib3",
)

with RetrievalClient(config=config, store=store) as retrieval:
    response = PyPIClient(retrieval).fetch_project(package.name)

inventory = normalize_pypi_versions(response, package)
result = export_version_inventory(inventory, Path("data/normalized"))
print(result.path, result.record_count, result.sha256)
print(inventory.stats)
```

The first request writes exact response bytes and bounded request/response metadata to
`data/raw/pypi`. An identical later request uses the verified cache. The exporter writes
UTF-8 `data/normalized/versions.jsonl` atomically; every line is an independent
`VersionRecord` JSON object.

## Normalization policy

- Project names are canonicalized with the Python packaging name rules, and the
  response `info.name` must match the expected package.
- Release keys are parsed and sorted with `packaging.version.Version`, never as text.
- Distinct keys that are equal under PEP 440 fail as a normalization conflict instead
  of being silently merged. Invalid release keys are reported in
  `inventory.unparsable_versions` and excluded from normalized records.
- A release date is the earliest known distribution upload timestamp. Empty releases
  keep it as `null`.
- A release is yanked only when it has at least one artifact and every artifact is
  yanked. Mixed file-level states remain available on each artifact.
- Release-level `requires_python` is set only when every non-null artifact requirement
  agrees. Otherwise it remains `null`, while each source value stays on its artifact.
- Artifact names must identify the expected project. Artifact URLs must use HTTPS on
  `files.pythonhosted.org`, contain no credentials/query/fragment, and end in the exact
  declared filename.
- Missing optional facts remain `null`; malformed types, timestamps, digests, paths,
  URLs, and inconsistent yanked reasons fail explicitly.

Inventory statistics report total versions, prereleases, yanked releases, artifacts,
and unparsable release keys. Generated crawl data is intentionally excluded from Git;
the preserved raw SHA-256 in each record's provenance makes the source auditable.
