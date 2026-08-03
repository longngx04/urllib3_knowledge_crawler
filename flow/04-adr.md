# Stage 04 — ADR (architecture decisions)

Short. The most valuable section is what you are NOT doing and why.

## Gate — check ALL before `/flow next`
- [x] Each decision has a one-line "why" and a one-line "what I rejected"
- [x] The NOT-doing list is written
- [x] Decisions cover: data storage, auth approach, deploy target
- [x] No FILL placeholders remain in this file

## Decisions

| # | Decision | Why | Rejected alternative |
|---|---|---|---|
| 1 | Store raw responses and normalized outputs as filesystem JSON/JSONL under `data/`; Phase 0 tracks only safe directory markers. | The required outputs are reproducible artifacts that need transparent provenance, deterministic hashing, offline fixture reuse, and simple review. | PostgreSQL or a vector database, because either adds operations and non-deterministic indexing before the file contracts are validated. |
| 2 | The CLI has no user authentication; optional upstream credentials are read from environment variables and are never persisted or logged. | This is a local/internal tool whose authorization boundary is the executing user and host, while source APIs may benefit from scoped tokens. | Custom account/session authentication and committed `.env` files, because neither protects a local CLI and both enlarge the credential attack surface. |
| 3 | Deliver as an installable Python CLI for local machines and CI; Phase 0 has no hosted deployment target. | The acceptance surface is a real isolated install plus command exit codes, and later crawling must remain reproducible offline from cached raw data. | A web service, container platform, or scheduled cloud deployment, because no network service contract or operational owner exists yet. |
| 4 | Use one typed `crawler` package with clients, extractors, normalizers, resolvers, validators, exporters, and utilities as separate subpackages. | These boundaries mirror the evidence pipeline and keep package-specific adapters separate from generic domain logic. | A single script, because mixed I/O and normalization would make provenance, testing, and extension to other packages brittle. |
| 5 | Use PEP 621 packaging, Python `>=3.11`, Typer/Rich for the command seam, YAML for package configuration, and pytest/Ruff/Mypy for quality gates. | These are established typed-Python tools that support the Phase 0 contract with minimal custom infrastructure. | A custom argument parser/config format/toolchain, because standard tools reduce maintenance and security-sensitive parsing code. |

## NOT doing in v1 (and why it's safe to skip)

- No database, vector index, web UI, HTTP service, scheduler, or cloud deployment; the file-based CLI contract is sufficient for the pilot.
- No live source client, cache, retry, model, schema, normalization, enrichment, validation, statistics, or query implementation; each belongs to a later documented phase.
- No custom authentication, secret file loader, or credential persistence; environment variables are the only planned credential seam.
- No executable remote code, package archives, exploit generation, or unrestricted concurrency; remote content remains untrusted data.
- No multi-package abstraction beyond configuration and package boundaries until the urllib3 vertical slice proves the design.
