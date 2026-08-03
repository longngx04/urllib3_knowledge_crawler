# Stage 01 — Research (inspect first)

Rule: INSPECT what already exists. Evidence required — links, quotes, screenshots.
"I think there's nothing like this" without searching = gate fail.

> Project type (`/flow project-type`, default `web`): items 2 and 4 below are written for a
> **web / market-facing product**. For an **internal tool / cli / library / skill** (no public
> market), use the non-web framing in each item — it is still real evidence (first-party
> friction, who-benefits), NOT an excuse to skip. The semantic gate refuses a market product
> that hides behind the soft framing.

## Gate — check ALL before `/flow next`
- [x] I actually OPENED 3 existing tools/competitors (links below, with one honest note each)
- [x] **(web)** I found 3 REAL user complaints online, quoted, with source links — **OR (non-web/internal)** I named the concrete first-party friction / observed pain that justifies this
- [x] I wrote what competitors CHARGE (real prices) and who pays — **OR (non-web)** what people spend AROUND this problem today (time, a worse tool, manual work)
- [x] **(web)** I named the ONE channel my first 10 users come from (a place, not "social media") — **OR (non-web/internal)** I named who benefits and how they hear about it (release notes / team), and noted "no market channel" is NOT a kill signal for an internal tool
- [x] I wrote why those users would pick this over the status quo (one honest paragraph)
- [x] I wrote what is technically free vs hard for this idea
- [x] No FILL placeholders remain in this file

## What exists already (3 — open them, don't guess)

1. [OSV-Scanner](https://google.github.io/osv-scanner/) extracts dependencies and matches them to OSV records with aliases, fixed versions, and machine-readable output. Its documented call analysis does not cover Python, and dependency or call reachability does not model urllib3 arguments, configuration, attacker-controlled data flow, negative conditions, or patch/test semantics.
2. [`pip-audit`](https://github.com/pypa/pip-audit#security-model) audits Python environments and dependency files using PyPI or OSV and reports aliases and fix versions. Its maintainers explicitly describe dependency-tree analysis rather than static code analysis, so it cannot decide whether an affected urllib3 API or exploitable usage is present.
3. [OSV API and schema](https://google.github.io/osv.dev/api/) provide authoritative package-version queries and structured identifiers, severity, affected events, and references. The shared schema does not encode changed symbols, patch guards, regression-test behavior, API sequences, configuration, data flow, or explicit negative conditions.

## What users say (web: 3 real complaints quoted+linked · non-web: real first-party friction)

1. > When a dependency scan reports an affected urllib3 version, a VinSOC security engineer must still find the relevant application call site and decide whether the vulnerable path is reachable; `pip-audit` explicitly leaves code analysis outside its model.
2. > For redirect, proxy, header, decompression, retry, and TLS findings, the engineer must manually inspect arguments, defaults, configuration, and whether untrusted input reaches the behavior; OSV-Scanner has no documented Python call analysis, and reachability alone would not establish these conditions.
3. > To close a false positive or validate a backport, the engineer must follow references, compare the upstream patch and parent, identify guards and changed symbols, locate regression tests, and translate missing preconditions into review notes; OSV supplies useful references but no structured patch/test or negative-condition model.

These observed workflow steps must be validated against actual VinSOC triage tickets and timed during the pilot; no unsupported hour estimate is assumed here.

## GTM & business reality

Building is the cheap part now. Distribution and willingness-to-pay are where ideas die —
research them BEFORE planning, not after shipping.

### Who pays today, and how much (pricing reference points)

- [OSV-Scanner](https://google.github.io/osv-scanner/) is open source with no per-seat scanner fee; VinSOC still pays integration, CI execution, advisory review, and manual applicability analysis.
- [`pip-audit`](https://github.com/pypa/pip-audit) is open source with no per-seat fee; VinSOC still pays dependency-resolution/CI time and analyst triage for results that require application-specific decisions.
- The [OSV API](https://google.github.io/osv.dev/api/) currently documents no API rate limit; VinSOC still pays for a robust client, caching, provenance, normalization, conflict resolution, and downstream security-semantic enrichment.

The main status-quo cost is repeated human joining of six evidence types: installed version, advisory, application call site, configuration/data flow, patch, and regression test. The pilot will measure this cost instead of fabricating an hourly total.

### The first-10-users channel (web) · who-benefits (non-web/internal)

VinSOC AppSec/SAST analysts benefit from faster evidence-backed verdicts, detection-content engineers gain reusable positive and negative rules, the AI/RAG team gains deterministic retrieval records, and crawler maintainers gain provenance and conflict reports. They will learn through integration into the internal SAST knowledge pipeline, internal release notes and schema/changelog entries, plus a short triage runbook and demo. This is an internal CLI/library, so no public market channel is expected and its absence is not a kill signal.

### Why switch (vs the status quo)

VinSOC should retain OSV, OSV-Scanner, and `pip-audit` as authoritative discovery and SCA inputs. The proposed crawler replaces repeated manual research and ad-hoc suppression notes with a reusable bridge from “this version is exposed” to “this application usage is or is not vulnerable”: version-aware APIs, required arguments and configuration, source-to-sink relationships, explicit negative conditions, remediation, and patch/test evidence with provenance.

## Technically free vs hard

- Free (solved by libraries/platforms): public OSV, PyPI, and GitHub data; HTTP and caching libraries; PEP 440 parsing with `packaging`; JSONL and JSON Schema tooling; hashing; Git metadata and diffs; deterministic sorting; established CLI frameworks.
- Hard (custom work, real risk): reconciling conflicting ranges and aliases without inventing facts; mapping PyPI versions to tags, commits, branches, and backports; reconstructing API availability; extracting symbols, guards, behavioral changes, and regression tests; formalizing configuration and attacker-controlled data flow; deriving trustworthy negative conditions; preserving claim-level provenance; and constraining LLM inference so it never becomes an authoritative fact.
