---
epic: 6
title: "Hardening and rehearsal"
status: "In progress (as built): 3 Done, 4 Backlog, 1 Won't do"
updated: 2026-11-20
---

# Epic 6: Hardening and rehearsal

The system is safe to demo and rehearsed; what is not yet validated is stated, not implied.

**Status:** In progress (as built): 3 Done, 4 Backlog, 1 Won't do  
**FRs covered:** FR-22, FR-42, FR-49, FR-51, FR-53  
**Stories:** 8 · **Owners:** M1, M2, M3, M5  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 6.1: Cross-site request protection

As an operator,  
I want the local API to ignore requests from other websites,  
So that a web page cannot trigger scans, quarantine or tampering.

**Status:** Done · **Owner:** M3 · **Covers:** FR-42 · **Course week:** 15 · **Architecture:** AD-12

**Acceptance Criteria:**

**Given** a state-changing request with a foreign `Origin`  
**When** it is sent  
**Then** 403, while reads and requests with no `Origin` still work  
*Verified by:* `test_foreign_origin_cannot_trigger_state_changing_requests`

**Given** a WebSocket handshake with a foreign `Origin`  
**When** it is attempted  
**Then** it is closed with code 1008; an allowed origin gets a `SNAPSHOT`  
*Verified by:* `test_foreign_origin_cannot_open_the_websocket`

**Given** `AEGIS_EXTRA_ORIGINS`  
**When** it lists another origin  
**Then** that origin is allowed  
*Verified by:* `test_extra_origins_can_be_allowed_by_config`, `test_cors_allows_vite_origin`

---

### Story 6.2: Warm the intel cache before a demo

As an operator,  
I want a command that pre-fills the cache with the demo hashes,  
So that VirusTotal answers are instant on stage.

**Status:** Done · **Owner:** M2 · **Covers:** FR-22 · **Course week:** cross-cutting · **Architecture:** AD-8, AD-14

**Acceptance Criteria:**

**Given** `python -m app warm_cache`  
**When** it runs with providers mocked  
**Then** the live pipeline then makes zero network calls for the demo files  
*Verified by:* `test_warm_cache_then_live_pipeline_makes_zero_network_calls`

**Given** a second run  
**When** it executes  
**Then** it makes no hash lookups  
*Verified by:* `test_warm_cache_second_run_is_all_cache`

**Given** the requests  
**When** they are inspected  
**Then** they contain hashes only, no filenames  
*Verified by:* `test_warm_cache_sends_only_hashes`

**Given** offline mode or no demo drive  
**When** it runs  
**Then** it exits with a clear message instead of a traceback  
*Verified by:* `test_warm_cache_refuses_offline_mode_and_missing_drive`, `test_cli_warm_cache_reports_clean_errors_instead_of_tracebacks`

**Given** live services  
**When** it was run once  
**Then** 96 s, 30 answers, 0 errors  
*Verified by:* recorded live run: Phase 6 hand-off

---

### Story 6.3: Fresh-clone demo rehearsal

As a team member,  
I want to prove the committed code runs end to end on a clean machine,  
So that there are no surprises on presentation day.

**Status:** Done · **Owner:** M5 · **Covers:** NFR-1, SM-1, SM-2, SM-3 · **Course week:** 1 · **Architecture:** AD-17

**Acceptance Criteria:**

**Given** a fresh clone of the repository  
**When** the runbook is followed  
**Then** 12 of 12 files land in their expected Tier, the chain verifies, reports sign and verify with all three algorithms and a tampered copy is rejected  
*Verified by:* fresh-clone run recorded in PR #1

**Given** the same clone  
**When** tests, lint and build run  
**Then** 139 cases pass, `ruff` is clean and the strict build passes  
*Verified by:* fresh-clone run, GitHub Actions

---

### Story 6.4: Validate on a real USB stick, Windows and Linux

As an operator,  
I want detection proven on real hardware on the demo OS,  
So that the platform claims are earned, not assumed.

**Status:** Backlog · **Owner:** M1 · **Covers:** FR-53, FR-1 · **Course week:** 1 · **Architecture:** AD-18

**Acceptance Criteria:**

**⚠ Not met** · **Given** a real USB stick on Windows 10/11  
**When** it is plugged in  
**Then** `USB_CONNECTED` appears within 2 s  
**And** unplugging mid-scan cancels cleanly  
*Verified by:* NOT DONE: manual checklist from MASTER_PROMPT §10

**⚠ Not met** · **Given** a real stick on Linux and macOS  
**When** it is plugged in  
**Then** it is detected and `/mnt` is not treated as removable  
*Verified by:* NOT DONE

---

### Story 6.5: Performance on a 2-5 GB stick

As an operator,  
I want scan time and memory measured on a large drive,  
So that I can state a real throughput.

**Status:** Backlog · **Owner:** M2 · **Covers:** FR-53, NFR-2 · **Course week:** 1 · **Architecture:** AD-2, AD-9

**Acceptance Criteria:**

**⚠ Not met** · **Given** a 2-5 GB drive with many files  
**When** it is scanned  
**Then** scan time and memory are recorded and compared with a budget  
*Verified by:* NOT DONE: no budget set; only 12 demo files (about 0.1 s) were measured

---

### Story 6.6: Presentation slides

As a team member,  
I want a slide deck for the presentation,  
So that the demo is framed for the examiner.

**Status:** Backlog · **Owner:** M5 · **Covers:** - · **Course week:** all · **Architecture:** n/a

> Not an FR; included because the original Epic 6 lists it.

**Acceptance Criteria:**

**⚠ Not met** · **Given** the talk  
**When** it is prepared  
**Then** slides exist that follow the demo script  
*Verified by:* NOT DONE: slides not started

---

### Story 6.7: API authentication

As an operator,  
I want a login or per-run token on the local API,  
So that other local processes cannot drive it.

**Status:** Backlog · **Owner:** M3 · **Covers:** FR-51 · **Course week:** 8 · **Architecture:** AD-12

**Acceptance Criteria:**

**⚠ Not met** · **Given** a local process without the token  
**When** it calls the API  
**Then** it is refused  
*Verified by:* NOT DONE: mitigated only by localhost binding, CORS and the Origin check

---

### Story 6.8: Sandbox / dynamic analysis

As an operator,  
I want suspicious files to be run in an isolated sandbox,  
So that behaviour, not just content, is judged.

**Status:** Won't do · **Owner:** M2 · **Covers:** FR-49 · **Course week:** 2 · **Architecture:** n/a

**Acceptance Criteria:**

**⚠ Not met** · **Given** a suspicious file  
**When** it is analysed  
**Then** it runs in a sandbox  
*Verified by:* OUT OF SCOPE: excluded by MASTER_PROMPT §4; kept for traceability

