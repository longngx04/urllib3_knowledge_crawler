# Phase 2 retrieval boundary

Phase 2 supplies shared infrastructure for future PyPI, GitHub, OSV, and NVD adapters.
It does not make a live crawl or interpret upstream facts.

## Safety model

- Requests must use HTTPS, contain no URL userinfo, and contain no credential-like query
  parameter. Redirects are not followed implicitly.
- `GITHUB_TOKEN` is read from the environment and sent only to `api.github.com` as an
  authorization header. Callers cannot provide authorization or cookie headers.
- Responses are streamed and stopped when their declared or observed size exceeds
  `max_response_bytes`.
- Retry is limited to timeouts/network errors, HTTP 429/500/502/503/504, and GitHub 403
  responses that report zero remaining requests. Invalid permanent responses are returned
  to the adapter; exhausted transient responses raise a typed error.
- Valid `Retry-After` and GitHub reset delays are honored only within the configured
  maximum. A longer provider delay raises `RateLimitError` instead of retrying early.

## Raw storage and replay

`build_request_identity` normalizes the method and credential-free URL, sorts query
pairs, removes fragments, and includes an optional request-body SHA-256. Its canonical
JSON is hashed to obtain the cache key.

`RawResponseStore` writes exact response bytes to `<key>.body` and deterministic JSON
metadata to `<key>.json` under a two-character SHA shard. Both files use atomic replace
and owner-only permissions. Metadata retains only request identity, response status,
content type, retrieval time, body SHA-256, and an allowlist of cache/rate-limit headers.
Authorization, cookies, full response headers, and response bodies never enter metadata
or logs.

Every cache read rejects symlinks, checks the body size before reading it, and recomputes
the request key and response-body SHA-256. Missing sidecars, invalid JSON, unexpected
fields, key mismatch, size mismatch, or body mismatch raises
`CacheCorruptionError`; corruption is never treated as a cache miss.

## Configuration

`load_http_client_config(Path("configs/urllib3.yaml"))` safely loads the bounded `crawl`
mapping into a frozen `HttpClientConfig`. The public retrieval client accepts injected
HTTPX transports, clocks, and sleepers so default tests and fixture reprocessing remain
offline and deterministic.
