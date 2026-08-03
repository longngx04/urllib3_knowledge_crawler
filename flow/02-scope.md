# Stage 02 — Scope (go/no-go)

Scope = features chosen by IMPACT × COST, inside your time budget.
KILL here is cheap and smart. Killing a weak idea at this gate is a SUCCESS outcome.

## Impact rubric (business value — score BEFORE looking at cost)

| Impact | Meaning |
|---|---|
| H | moves money or the core promise: gets users in (acquisition), gets them paying (revenue), or delivers the one job they came for |
| M | keeps users / saves real time weekly (retention, operations) |
| L | nice-to-have; nobody would pay for or switch over it |

Decision matrix: **H-impact features justify B/C cost** (via the C-paths below).
**L-impact features must be grade A or they're cut** — and even grade-A L-features are
cut when the budget is tight. The classic failure is a v1 full of A-grade L-impact
features: cheap to build, worthless to sell.

## AI coding grade rubric

| Grade | Meaning | Examples |
|---|---|---|
| A | cheap for AI | CRUD, forms, dashboards, content sites, API wrappers |
| B | moderate | file processing, 3rd-party integrations, auth via library, single LLM call, HITL AI drafts |
| C | expensive | realtime, payments from scratch, custom auth, autonomous agentic AI pipelines, heavy concurrency |

**Grade is a COST estimate, not a permission.** The gate is fit(grades, budget), not "no C allowed."
When a C feature is the real need, three honest paths:
1. **The C feature IS the product** → invert the cut: C goes FIRST (riskiest assumption first),
   everything else is minimized to serve it, and the budget is renegotiated against reality.
   But: one C proves the value prop — its siblings are v2 cards, not v1 scope.
2. **Re-architect C down to B** (highest-leverage move): multi-step agent → single LLM call;
   auto-send → human-approves-draft; custom pipeline → managed service / library.
   Same user value, one grade cheaper.
3. **Irreducible C that doesn't fit the budget** → KILL or re-budget. Both are honest.

## Gate — check ALL before `/flow next`
- [x] Every feature below has an IMPACT (H/M/L with the business reason) AND a grade (A/B/C)
- [x] No L-impact feature above grade A survives in v1
- [x] The suggested-features section was actually considered (each suggestion has an in/out decision)
- [x] fit(grades, budget) holds — every C in scope is justified as path 1, 2, or 3 above (written next to the feature)
- [x] If the product IS a C feature: it is FIRST in build order, and its sibling C features are on the cut list
- [x] The cut list is written (what I am NOT building in v1)
- [x] GO / KILL decision is written below
- [x] No FILL placeholders remain in this file

## Time budget

One focused implementation session for Phase 0; no unverified delivery-hour estimate is assumed for later phases.

## Features in v1 (each with impact AND grade)

- Installable typed Python package with declared runtime and development dependencies — impact H (foundation required for every crawler capability and clean-environment reproduction) — grade A (standard packaging configuration).
- Package and data-directory skeleton aligned with the planned client/extractor/normalizer/resolver/validator/exporter boundaries — impact H (prevents architectural drift before feature work) — grade A (directories and package markers only).
- Package-specific `configs/urllib3.yaml` plus a safe `.env.example` — impact H (keeps urllib3 behavior configurable and secrets out of source) — grade A (documented static configuration).
- Minimal `python -m crawler` CLI with useful help and version output — impact H (proves the install and command seam used by every later phase) — grade A (Typer command shell without crawler behavior).
- Offline bootstrap tests plus Ruff and Mypy configuration — impact H (provides the acceptance gate and protects later deterministic/security-sensitive work) — grade A (standard tooling and smoke tests).
- Initial README with setup, commands, project boundaries, source priorities, and development checks — impact M (reduces onboarding and operational ambiguity) — grade A (documentation).
- Repository hygiene via `.gitignore` and tracked empty output-directory markers — impact M (prevents credentials, environments, caches, and generated crawl data from leaking into commits) — grade A (configuration).

## Suggested features (impact-first — proposed, not decided)

Up to 3 features NOT in the original idea, each chosen for business impact (how does this
get users in / get money in / keep users?). Grounded in the stage-01 GTM findings — e.g.
the first-10-users channel often implies a share/invite/referral surface; the pricing
research often implies an upsell or a paid tier. Default is OUT; each needs an explicit
decision.

- Hosted CI workflow — impact M (makes quality visible to internal adopters) — grade A — OUT because Phase 0 acceptance can be proven locally and no CI platform requirement was requested.
- Docker/devcontainer setup — impact L (environment convenience) — grade A — OUT because `uv`/venv already provides a clean reproducible bootstrap and containers are not required.
- Example security query/demo — impact H (shows the eventual SAST value) — grade B — OUT because it depends on models, crawled data, and query behavior assigned to later phases.

## Cut list (NOT in v1 — deferred, not deleted)

- Domain models and JSON Schemas — deferred to Phase 1 so contracts are designed deliberately rather than hidden in bootstrap code.
- HTTP, cache, retry, and raw storage — deferred to Phase 2.
- Live PyPI, GitHub, OSV, GHSA, and NVD crawling — deferred to Phases 3–5.
- Range and alias resolution, patch/test enrichment, security patterns, KB documents, statistics, and real query behavior — deferred to Phases 6–13.
- CI, containerization, deployment, dashboard, vector database, multi-package support, and LLM enrichment — deferred until a validated vertical slice justifies them.

## Decision

GO — Phase 0 is a bounded all-A bootstrap that establishes the install, command, configuration, test, and repository seams required by every later phase without implementing crawler semantics early.
