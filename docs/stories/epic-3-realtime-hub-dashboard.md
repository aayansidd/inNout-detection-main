---
epic: 3
title: "Realtime hub and dashboard MVP"
status: "Done"
updated: 2026-11-20
---

# Epic 3: Realtime hub and dashboard MVP

An operator sees scan results live in a dashboard and can run the whole thing with no USB stick. (Demo-able checkpoint.)

**Status:** Done  
**FRs covered:** FR-5, FR-24, FR-25, FR-26, FR-27, FR-28  
**Stories:** 4 · **Owners:** M3, M4  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 3.1: Realtime event hub with a SNAPSHOT on connect

As an operator,  
I want the dashboard to show everything that happened, even after a refresh,  
So that I never lose results or see duplicates.

**Status:** Done · **Owner:** M3 · **Covers:** FR-24 · **Course week:** 1 · **Architecture:** AD-2, AD-3, AD-4

**Acceptance Criteria:**

**Given** a client that connects  
**When** the WebSocket opens  
**Then** the first message is a `SNAPSHOT`  
**And** after Simulate it receives `USB_CONNECTED`, 12 `FILE_SCANNED` and `SCAN_COMPLETE` with matching counts  
*Verified by:* `test_websocket_snapshot_first_then_simulate`

**Given** a quarantine request  
**When** the route looks up the chained event  
**Then** the SQLite read runs off the event loop (AD-2)  
*Verified by:* `test_quarantine_audit_lookup_runs_off_the_event_loop`

**Given** a finished scan  
**When** a new client connects  
**Then** its `SNAPSHOT` holds all 12 results, correct stats and no duplicate `event_id`  
*Verified by:* `test_reconnect_snapshot_repopulates_without_duplicates`

**Given** a client whose queue overflows  
**When** events keep arriving  
**Then** that client alone is dropped and the others are unaffected  
*Verified by:* artifact: Client.offer in api/ws_manager.py (no automated test)

---

### Story 3.2: Health, stats, history and the Simulated Drive

As an operator,  
I want to run a full scan without a USB stick and to see service health,  
So that I can demo and check the system anywhere.

**Status:** Done · **Owner:** M3 · **Covers:** FR-5, FR-25 · **Course week:** 1 · **Architecture:** AD-12

**Acceptance Criteria:**

**Given** a fresh server  
**When** `/api/health`, `/api/stats` and `/api/history` are called  
**Then** health reports 6 YARA rules and 0 clients; stats are zero; history is empty  
*Verified by:* `test_health_and_empty_state`

**Given** a simulated drive that finished  
**When** I eject and simulate again  
**Then** eject succeeds once and a second simulate works  
*Verified by:* `test_eject_and_resimulate`

**Given** the demo folder is missing  
**When** I simulate  
**Then** the server answers 409 with a hint  
*Verified by:* `test_simulate_without_drive_is_409`

**Given** `AEGIS_DEMO_MODE=false`  
**When** I simulate or eject  
**Then** the server answers 403  
*Verified by:* `test_demo_mode_off_blocks_demo_endpoints`, `test_reset_is_demo_only_and_refused_mid_scan`

**Given** the dashboard origin `localhost:5173`  
**When** it sends a CORS preflight  
**Then** it is allowed  
*Verified by:* `test_cors_allows_vite_origin`

---

### Story 3.3: Live tab: counters, entropy chart, scan queue and threat log

As an operator,  
I want a live view of tiers, entropy, the scan feed and a filterable log,  
So that I can judge a drive at a glance.

**Status:** Done · **Owner:** M4 · **Covers:** FR-26, FR-28 · **Course week:** 2, 11-13 · **Architecture:** AD-15, AD-3

> No automated browser tests exist; verification is the strict build plus manual runs.

**Acceptance Criteria:**

**Given** a finished Simulate  
**When** the Live tab is viewed  
**Then** counters read 12 / 3 / 2 / 7, the entropy chart fills its card height and shows the 7.2 line, the risk matrix and scan queue are filled  
*Verified by:* manual: fresh-clone click-through, artifact: docs/images/dashboard.jpg

**Given** a CRITICAL result and a completed scan  
**When** the events arrive  
**Then** the red CRITICAL toast (bottom-left, never covering the header) and the scan toast appear and then expire on schedule  
*Verified by:* manual: click-through, artifact: commit 611c5d5 (stable dismiss callbacks)

**Given** demo mode and a finished scan  
**When** the operator clicks Reset stats  
**Then** counters, history, scan queue and risk matrix clear on every connected dashboard (a fresh SNAPSHOT is pushed), the audit chain is kept, and the button is hidden when demo mode is off and refused while a scan runs  
*Verified by:* `test_reset_clears_stats_history_and_pushes_a_fresh_snapshot`, `test_reset_is_demo_only_and_refused_mid_scan`, manual: Chrome click-through

**Given** the socket drops  
**When** the API returns  
**Then** the dashboard reconnects with back-off and jitter and repopulates from `SNAPSHOT`  
*Verified by:* artifact: hooks/useAegisSocket.ts, manual: restart test

---

### Story 3.4: Forensic drawer

As an operator,  
I want to open any file and see exactly why it got its verdict,  
So that I can explain and act on the result.

**Status:** Done · **Owner:** M4 · **Covers:** FR-27 · **Course week:** 2, 6 · **Architecture:** AD-15

**Acceptance Criteria:**

**Given** a scanned file  
**When** its row is clicked  
**Then** the drawer shows full SHA-256 with copy, legacy hashes, magic hex versus claimed extension, entropy with chi-square and a plain note, YARA hits, Authenticode, XOR key, MITRE links, intel verdicts and chain index  
*Verified by:* manual: fresh-clone click-through

**Given** the Escape key  
**When** it is pressed with the drawer open  
**Then** the drawer closes  
*Verified by:* manual

