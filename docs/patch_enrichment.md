# Patch and Regression-Test Enrichment (Phase 7)

## Overview

Phase 7 extracts implementation-level evidence from official `urllib3/urllib3` commit
payloads and links it to advisory identifiers:

1. **Commit retrieval**: `GitHubClient.fetch_commit` calls
   `GET https://api.github.com/repos/{owner}/{repo}/commits/{sha}` with
   `Accept: application/vnd.github+json`, validating owner/repo/SHA and rejecting
   non-200 or non-JSON responses like other GitHub adapters.
2. **Diff extraction**: `extract_patch_diff_from_commit` parses GitHub `files[]`
   payloads to collect changed files, Python symbols (`def`/`class` from diff lines),
   added guards (`if`/`raise`/`assert` on added lines), and regression-test paths
   (`test_*.py` under `test/` or `tests/`).
3. **Patch normalization**: `normalize_github_commit` builds provenance-backed
   `PatchRecord` objects, verifies the repository matches configuration
   (`urllib3/urllib3` by default), resolves `fixed_versions` only from advisory or
   explicit commit-to-tag maps, and reports unresolved patch references separately.
4. **Export**: `export_patch_inventory` atomically writes deterministic
   `patches.jsonl` using the same safety pattern as version export.

## Usage Example

```python
from crawler.clients.github import GitHubClient
from crawler.exporters.jsonl import export_patch_inventory
from crawler.models import PackageRecord
from crawler.normalizers.patches import (
    PatchNormalizationError,
    UnresolvedPatchRef,
    build_patch_inventory,
    normalize_github_commit_response,
)

package = PackageRecord(name="urllib3", ecosystem="PyPI", purl="pkg:pypi/urllib3")
github = GitHubClient(retrieval_client)

response = github.fetch_commit("urllib3", "urllib3", commit_sha)
try:
    patch = normalize_github_commit_response(
        response,
        advisory_ids=["CVE-2023-45803"],
        package=package,
        owner="urllib3",
        repo="urllib3",
        advisory_fixed_versions=["2.0.7"],
        commit_tag_map={commit_sha: "2.0.7"},
    )
except PatchNormalizationError as error:
    unresolved = UnresolvedPatchRef(commit_sha=commit_sha, reason=str(error))
else:
    inventory = build_patch_inventory(package=package, records=[patch])
    export_patch_inventory(inventory, output_directory)
```

## Detection-class fixtures

Offline fixtures under `tests/fixtures/` model three SAST detection needs:

| Fixture | Detection need | Primary symbol area |
| --- | --- | --- |
| `github_commit_version_api.json` | Version + API | `HTTPResponse.drain_conn` |
| `github_commit_version_api_config.json` | Version + API + configuration | `create_urllib3_context(cert_reqs=...)` |
| `github_commit_version_api_dataflow.json` | Version + API + runtime precondition | redirect URL validation |

## Limitations

- Symbol extraction is rule-based and filename-local; it does not perform AST parsing.
- `behavioral_differences` remain empty until Phase 8 semantic enrichment.
- Fixed versions are never inferred from commit order; only advisory or tag-map evidence
  is accepted.
