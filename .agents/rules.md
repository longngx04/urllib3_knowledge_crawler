# Agent Rules

These rules apply to every agent working in this repository. They supplement
`context.md` and `implementation_plan.md`. If instructions conflict, follow the
user's latest explicit request first, then these rules, then the project plan.

## 1. Mandatory Context Loading

1. Before executing any user request, list and read every file in `.agents/` in
   full, including this file. Do this before planning, editing, running project
   commands, or delegating work.
2. Re-read changed `.agents/` files if they are modified during a task.
3. Confirm the requested work is within the scope and priorities defined by
   `context.md` and `implementation_plan.md`.
4. Do not broaden scope silently. Document necessary scope changes and ask for
   direction when they materially affect architecture, delivery, or security.

## 2. Task Execution Workflow

1. Inspect the current repository state before making changes: relevant files,
   Git status, existing tests, configuration, and nearby patterns.
2. Define a small, testable outcome and its acceptance criteria before coding.
3. Prefer the vertical-slice order in `implementation_plan.md`: deliver a usable
   end-to-end path before expanding connector or feature breadth.
4. Prioritize P0 work over P1 and P2. Optional work must not delay required work.
5. Reuse existing abstractions and dependencies when suitable. Add a dependency
   only when its value outweighs its maintenance and security cost.
6. Keep changes focused. Do not mix unrelated refactors, formatting, generated
   data, or cleanup into the same task.
7. Use parallel, independent work only when it does not create conflicting edits
   or complicate verification. Keep dependency-ordered work sequential.
8. Prefer deterministic, cacheable, idempotent operations. Avoid repeated network
   requests when verified raw or cached data is available.
9. Surface blockers, conflicts, incomplete evidence, and failed records explicitly.
   Never hide or silently skip them.
10. Finish each task by reviewing the diff, running proportionate checks, and
    reporting what changed, what was verified, and any remaining limitations.

## 3. Coding Best Practices

1. Target the Python version and toolchain declared in `pyproject.toml` once it
   exists. Use typed Python for public APIs and security-sensitive logic.
2. Keep modules small and cohesive. Separate clients, extraction, normalization,
   resolution, validation, export, and presentation concerns.
3. Prefer pure functions for parsing, normalization, range evaluation, record-ID
   generation, and scoring. Isolate I/O behind clear interfaces.
4. Use explicit data models at trust boundaries. Validate external and cached data
   before it enters domain logic.
5. Handle expected failures with specific exceptions and actionable messages.
   Never use broad exception handling that suppresses errors.
6. Avoid mutable global state, hidden side effects, duplicated logic, magic values,
   and premature abstraction.
7. Keep package-specific behavior in configuration or adapters. Do not hardcode
   `urllib3` vulnerability facts in generic application logic.
8. Preserve backward compatibility for published schemas and CLI behavior unless
   a deliberate, documented version change is required.
9. Update documentation, schemas, fixtures, and examples when behavior or public
   contracts change.

## 4. Naming Conventions

1. Use `snake_case` for Python modules, functions, methods, local variables, and
   configuration keys.
2. Use `PascalCase` for classes, enums, exceptions, and Pydantic models.
3. Use `UPPER_SNAKE_CASE` for constants.
4. Prefix internal-only attributes or helpers with a single underscore when it
   improves API clarity.
5. Choose precise, domain-oriented names such as `affected_versions`,
   `canonical_advisory_id`, and `raw_sha256`. Avoid vague names such as `data`,
   `item`, `obj`, or `tmp` outside narrow local scopes.
6. Name tests after observable behavior, using the pattern
   `test_<unit>_<condition>_<expected_result>` where practical.
7. Use stable, documented names for record types, fields, CLI commands, output
   files, and configuration keys. Do not introduce synonyms for existing concepts.

## 5. Data and Security-Knowledge Correctness

1. Preserve raw source data before normalization and attach provenance to every
   normalized security claim.
2. Keep raw values alongside normalized values when required by the schemas.
3. Use `packaging.version.Version` and `SpecifierSet`; never compare package
   versions as strings.
4. Never invent affected ranges, fixed versions, aliases, commit identities,
   severity, dates, or patch inclusion. Unsupported values must remain unknown.
5. Follow the source-priority and conflict policies in `context.md`. Preserve
   conflicting claims with their sources and resolution rationale.
6. An LLM-derived value is an inference, never an authoritative security fact.
   Mark it with model, prompt version, evidence, and confidence metadata.
7. Keep normalized outputs deterministically ordered. Stable input must produce
   stable record IDs and content, excluding explicitly non-deterministic metadata.
8. Include negative conditions and evidence wherever available so the knowledge
   base supports SAST verdicts rather than version-only exposure checks.

## 6. Security Best Practices

1. Treat all remote responses, archives, diffs, metadata, configuration, cache
   entries, and generated files as untrusted input.
2. Validate URLs, identifiers, content types, schemas, sizes, encodings, and paths
   at trust boundaries. Prevent path traversal and writes outside configured roots.
3. Never execute downloaded code or commands derived from untrusted content.
4. Apply explicit timeouts, response-size limits, bounded retries, exponential
   backoff, and rate-limit handling to network operations.
5. Retry only transient failures. Respect `Retry-After`, provider terms, and API
   limits; avoid aggressive concurrency.
6. Keep secrets in environment variables or approved secret stores. Never commit,
   print, cache, serialize, or log tokens, credentials, cookies, or authorization
   headers.
7. Redact sensitive values from errors and diagnostic output. Ensure cache keys and
   raw metadata cannot leak credentials.
8. Use safe serialization and parsing APIs. Do not use `eval`, `exec`, unsafe YAML
   loaders, or unsafe archive extraction.
9. Pin or constrain dependencies appropriately, minimize dependency surface, and
   review security-sensitive dependency changes.
10. Do not generate weaponized exploit code in the default pipeline.

## 7. Testing and Verification

1. Add or update tests for every behavior change and bug fix.
2. Cover success, boundary, malformed-input, conflict, timeout, rate-limit, and
   corrupted-cache paths where relevant.
3. Prefer unit tests for pure domain logic, mocked HTTP tests for clients, and
   fixture-based integration tests for the pipeline.
4. Tests must not depend on live network access unless explicitly marked as live
   integration tests. Default test runs must be reproducible offline.
5. Verify deterministic output by running equivalent fixture inputs more than once
   and comparing normalized content hashes where relevant.
6. Run the narrowest useful checks during development, then the broader relevant
   suite before committing. Run formatting, linting, typing, schema validation, and
   tests when those tools exist and the change affects them.
7. Do not claim a check passed unless it was run successfully. Report skipped or
   unavailable checks and the reason.

## 8. Git and Branch Workflow

1. Inspect `git status` before editing. Preserve user changes and never overwrite,
   reset, reformat, or commit unrelated work.
2. Create a new branch for a substantial feature, risky change, schema migration,
   multi-file refactor, or work intended for review. Use a concise name such as
   `feat/osv-client`, `fix/range-resolution`, or `docs/report`.
3. A branch is optional for a small, isolated documentation or maintenance task
   when the user has not requested one and the current branch is appropriate.
4. Commit after each completed feature or task once its relevant checks pass. Do
   not combine multiple independent features in one commit.
5. Use focused Conventional Commit messages, for example:
   `feat: add PyPI version crawler`, `fix: handle open-ended OSV ranges`, or
   `docs: add agent rules`.
6. Stage only files belonging to the task. Review the staged diff before committing.
7. Do not amend, rebase, force-push, delete branches, or rewrite shared history
   unless the user explicitly requests it.
8. After every completed-task commit, run a final secret/status check and push the
   current branch to the configured GitHub remote. If the remote or authentication is
   unavailable, report the blocker instead of claiming the task is fully published.
9. When work is performed on a new branch, push that branch with its upstream tracking
   reference (for example, `git push -u origin <branch>`). Push only: do not merge it
   into `main` or any other branch unless the user explicitly requests the merge.
10. Do not force-push or open a pull request unless the user explicitly requests it.

## 9. Definition of Task Completion

A task is complete only when:

- The requested behavior or artifact exists and stays within project scope.
- Relevant acceptance criteria are satisfied.
- Tests and validation proportional to the change have passed.
- Security, provenance, determinism, and compatibility impacts were reviewed.
- Documentation is updated when public behavior changed.
- The diff contains no secrets or unrelated changes.
- The completed task is committed with a focused message.
- The commit is pushed to GitHub on the current branch without implicitly merging it.
- Any limitations, unresolved evidence conflicts, or skipped checks are reported.
