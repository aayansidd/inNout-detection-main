---
epic: 1
title: "Foundation"
status: "Done"
updated: 2026-11-20
---

# Epic 1: Foundation

A reproducible, safe, tested repository: scaffold, configuration and secrets, the event contract, and CI.

**Status:** Done  
**FRs covered:** FR-43  
**Stories:** 5 · **Owners:** M3, M4, M5  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 1.1: Repository scaffold, safety rules and conventions

As a team member,  
I want a repo with written safety rules, ignore rules and a one-command quality check,  
So that anyone can clone it, run it and not leak secrets or run unsafe code.

**Status:** Done · **Owner:** M5 · **Covers:** FR-43 · **Course week:** 1 · **Architecture:** AD-13, AD-17

**Acceptance Criteria:**

**Given** a fresh clone and the steps in `qa_demo/README.md`  
**When** I generate the payloads, install and run the checks  
**Then** all 139 test cases pass, `ruff` is clean and the strict TypeScript build passes  
*Verified by:* fresh-clone run recorded in PR #1, the full `pytest` suite

**Given** `CLAUDE.md`  
**When** a contributor reads it  
**Then** the hard safety rules are stated: never execute scanned files, hash-only intel, inert payloads, quarantine copies  
**And** a test fails the build if certificate checking is disabled or a sample-download call appears  
*Verified by:* CLAUDE.md, `test_source_never_disables_tls_verification_or_downloads_samples`

**Given** `.gitignore`  
**When** secrets, keys, data and virtual environments exist locally  
**Then** they are never committed  
*Verified by:* artifact: .gitignore, manual: secret-value scan before every commit

---

### Story 1.2: Configuration and secrets through one settings object

As an operator,  
I want all settings to come from `AEGIS_*` variables and a git-ignored `.env`, validated at start-up,  
So that a bad setting stops the program early and secrets never sit in code.

**Status:** Done · **Owner:** M3 · **Covers:** FR-43 · **Course week:** 8 · **Architecture:** AD-13

**Acceptance Criteria:**

**Given** `AEGIS_VAULT_CIPHER` is `3des`  
**When** settings load  
**Then** start-up is refused with a clear reason  
*Verified by:* `test_unknown_cipher_refused_and_default_ok`

**Given** `AEGIS_EXTRA_ORIGINS` lists extra browser origins  
**When** settings load  
**Then** they are added to the allowed origins  
*Verified by:* `test_extra_origins_can_be_allowed_by_config`

**Given** the test suite  
**When** any test runs  
**Then** every API key is blanked, intel is forced offline and the test gets its own data directory  
**And** no test reaches a real service even though `backend/.env` holds real keys  
*Verified by:* qa_demo/conftest.py (isolated_env fixture), `test_offline_mode_makes_no_network_calls_but_local_ioc_works`

---

### Story 1.3: Event contract mirrored in TypeScript

As a developer,  
I want the backend event models and the frontend types to be checked against each other,  
So that the two halves cannot drift apart silently.

**Status:** Done · **Owner:** M3 · **Covers:** FR-24 · **Course week:** 1 · **Architecture:** AD-3

> Counted under Epic 3 for FR-24; this story delivers the contract half.

**Acceptance Criteria:**

**Given** every model in `schemas.CONTRACT_MODELS`  
**When** its fields are compared with the interface in `telemetry.ts`  
**Then** the field sets are identical  
*Verified by:* `test_pydantic_models_match_telemetry_ts_field_for_field`

**Given** the `FILE_SCANNED` contract example from the specification  
**When** the model is inspected  
**Then** all contract fields exist and extra fields are allowed  
*Verified by:* `test_file_scanned_contract_example_fields`

---

### Story 1.4: Continuous integration quality gates

As a team member,  
I want lint, tests and the strict build to run on every push and pull request,  
So that regressions are caught before they reach `main`.

**Status:** Done · **Owner:** M5 · **Covers:** NFR-1 · **Course week:** 1 · **Architecture:** AD-17

**Acceptance Criteria:**

**Given** a push or pull request  
**When** GitHub Actions runs  
**Then** `ruff check`, `pytest` and `npm ci && npm run build` all execute (Ubuntu, Python 3.12, Node 22)  
*Verified by:* artifact: .github/workflows/ci.yml

**Given** pull request #1  
**When** its checks finish  
**Then** both the backend and frontend jobs are green  
*Verified by:* GitHub checks on PR #1 and on `main` (merge commit and later pushes)

---

### Story 1.5: Dashboard scaffold with a backend proxy

As a developer,  
I want a strict-TypeScript React app that talks to the API through a configurable proxy,  
So that the dashboard runs on any port the API uses.

**Status:** Done · **Owner:** M4 · **Covers:** NFR-8, NFR-9 · **Course week:** 1 · **Architecture:** AD-15, AD-12

**Acceptance Criteria:**

**Given** the frontend sources  
**When** `npm run build` runs  
**Then** strict TypeScript compiles and Vite builds  
*Verified by:* npm run build (also run in CI)

**Given** `VITE_BACKEND_PORT=8011` and the API on 8011  
**When** the dev server starts  
**Then** `/api` and `/ws` are proxied to that port and Vite refuses to start on another dashboard port  
*Verified by:* artifact: frontend/vite.config.ts, manual: fresh-clone run on port 8011

