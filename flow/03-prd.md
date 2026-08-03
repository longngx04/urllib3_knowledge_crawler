# Stage 03 — PRD

1-2 pages max. Test: could a stranger build v1 from this without asking you anything?

## Gate — check ALL before `/flow next`
- [x] Every section below is filled from MY scope decision (stage 02), not re-expanded
- [x] Success metric is a NUMBER, not vibes ("save time" fails; "first response < 2h" passes)
- [x] Each feature names the user action and the observable result, tagged with a stable `FRn:` id
- [x] Pain & gain is a MAPPING TABLE: every pain cites evidence (a stage-01 quote or a named observation), and names the v1 feature that kills it; every v1 feature kills at least one pain
- [x] A stranger could build v1 from this without asking me anything
- [x] No FILL placeholders remain in this file

## Context

VinSOC is starting an internal Python CLI that will convert authoritative urllib3 release and vulnerability sources into version-aware security knowledge for AI-assisted SAST. Existing SCA tools provide useful dependency and advisory data but do not supply the API, configuration, data-flow, negative-condition, patch, and test evidence needed for application-specific verdicts. Phase 0 establishes only the repository, package, configuration, command, documentation, and quality seams needed by later phases. No network crawling or vulnerability facts are implemented in this phase.

## Target users

- VinSOC AppSec/SAST analysts who need evidence-backed applicability verdicts.
- Detection-content and AI/RAG engineers who will consume stable normalized records.
- Python maintainers who will extend and operate the crawler through documented CLI commands.

## Pain & gain (mapping table — the traceability spine of the PRD)

Every row: a concrete pain, the evidence it's real, what people do about it today, the
ONE v1 feature that kills it, and the observable gain. If a feature kills no pain, cut
it; if a pain has no feature, it goes to the "not addressed" list — honestly.

| # | Persona | Pain (concrete) | Evidence (stage-01 quote/source or named observation) | Today's workaround | V1 feature that kills it | Observable gain |
|---|---|---|---|---|---|---|
| P1 | Python maintainer | A fresh checkout has no installable package or declared dependency boundary. | Phase 0 checklist in `.agents/implementation_plan.md`. | Ad-hoc commands and global packages. | FR1 | Editable install succeeds in an isolated environment. |
| P2 | Python maintainer | Planned clients, extractors, normalizers, resolvers, validators, exporters, schemas, tests, and data outputs have no stable repository locations. | Architecture in `.agents/context.md`. | Create paths opportunistically during later tasks. | FR2 | All planned boundaries exist before feature work begins. |
| P3 | Crawler operator | There is no stable command seam to discover or invoke. | Phase 0 acceptance criterion in `.agents/implementation_plan.md`. | Read implementation files or wait for later commands. | FR3 | `python -m crawler --help` exits 0 and lists the program purpose/version option. |
| P4 | Security engineer | Package-specific source and crawl behavior risks being hardcoded, and token handling is undocumented. | Configuration and credential rules in `.agents/context.md` and `.agents/rules.md`. | Modify code and pass credentials inconsistently. | FR4 | A committed urllib3 config and secret-free environment template expose the intended settings. |
| P5 | Maintainer | Changes have no repeatable bootstrap quality gate. | Testing requirements in `.agents/implementation_plan.md`. | Manual inspection only. | FR5 | Offline tests, Ruff, and Mypy return success for the bootstrap. |
| P6 | New contributor | Setup, scope, commands, and source-trust rules are spread across planning documents. | Internal adoption path identified in stage 01. | Ask maintainers or rediscover commands. | FR6 | README provides one reproducible setup and verification path. |
| P7 | Repository owner | Environments, caches, tokens, and generated crawl output could be committed accidentally. | Security rules in `.agents/context.md` and `.agents/rules.md`. | Manually inspect every commit. | FR7 | Ignore rules exclude local secrets, tooling state, and generated data while preserving directory structure. |

### Pains NOT addressed in v1 (deliberate — tie to the scope cut list)

- Analysts still perform manual vulnerability applicability analysis → deferred because models, source clients, range resolution, and security-semantic enrichment belong to Phases 1–9.
- Maintainers still lack automated CI and a published artifact → deferred until local bootstrap behavior is stable and a delivery platform is selected.

## Problem statement

The repository cannot safely begin crawler implementation until it has an installable, typed, testable, documented CLI skeleton with explicit configuration and architectural boundaries. Phase 0 must provide that foundation without inventing domain contracts or contacting remote sources.

## Features (user-centric — action → observable result)

Tag each v1 feature with a stable id `FRn:` (functional requirement) — the traceability
anchor. Every `FRn` must later be claimed by a card (`implements: FRn`) and served by an
interface in the contract (`FRn →`); `/flow consistency` checks this mechanically.

- FR1: As a maintainer, I install the project in an isolated Python environment, and the package plus declared runtime/development dependencies install successfully.
- FR2: As a maintainer, I inspect the repository, and I see the planned package, schema, test, fixture, raw-data, normalized-data, and KB boundaries without premature feature implementations.
- FR3: As an operator, I run `python -m crawler --help` or `python -m crawler --version`, and I receive concise output with exit code 0.
- FR4: As a maintainer, I open `configs/urllib3.yaml` and `.env.example`, and I see package/source/output/crawl settings plus credential names without secret values.
- FR5: As a contributor, I run the configured tests, formatter/linter, and type checker, and each returns exit code 0 for the bootstrap code.
- FR6: As a new contributor, I follow the README, and I can create the environment, install the project, invoke the CLI, and run quality checks without undocumented steps.
- FR7: As a repository owner, I inspect Git status after local setup or generated output, and environments, caches, secrets, logs, and generated crawl artifacts remain untracked while intentional directory markers remain versioned.

## Non-functional requirements

- Support CPython 3.11 and newer; verify Phase 0 on CPython 3.12.
- Use UTF-8 text, deterministic configuration, and no network access in default tests.
- Keep secrets absent from tracked files and logs; `.env.example` contains names and documentation only.
- Use typed public Python functions and strict-enough Ruff/Mypy settings suitable for incremental adoption.
- Keep the CLI import side-effect free and return non-zero codes for future unrecoverable failures.

## Tech stack

- Runtime: Python `>=3.11`, Typer and Rich for the CLI; HTTPX, Pydantic, Packaging, PyYAML, Tenacity, and JSON Schema declared for the planned P0/P1 foundation.
- Development: pytest, pytest-cov, respx, Ruff, and Mypy.
- Packaging: PEP 517/621 `pyproject.toml` with an editable install and a `crawler` package; no database, frontend, or deployment target in Phase 0.
- Configuration: YAML package config and environment-variable names for credentials; no `.env` loading or remote client behavior yet.

## Success metric (numbers only)

2 required acceptance commands return exit code 0 (`python -m crawler --help` and `pytest`), 100% of bootstrap tests pass, and 0 secrets or generated crawl records are tracked.
