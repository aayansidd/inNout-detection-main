# Stories: AEGIS USB (as built)

Brownfield story set for the six epics in [`MASTER_PROMPT.md`](../MASTER_PROMPT.md) §11, derived from [`prd.md`](../prd.md) (FR-1 to FR-53) and [`architecture.md`](../architecture.md) (AD-1 to AD-18). **Nothing here is a plan to build**: the stories describe what exists, and every acceptance criterion cites the real test in `qa_demo/` or names the artifact or manual check that proves it. Gaps are shown as **Partial**, **Backlog** or **Won't do**, never as Done.

## Status board

**47 stories:** 35 Done · 4 Partial · 7 Backlog · 1 Won't do. All **106** test functions in `qa_demo/` are cited by at least one acceptance criterion (139 collected cases once parametrization is counted).

| Epic | Stories | Status |
|---|---|---|
| [Epic 1: Foundation](epic-1-foundation.md) | 5 | Done |
| [Epic 2: Detection core](epic-2-detection-core.md) | 8 | In progress (as built): 7 Done, 1 Partial |
| [Epic 3: Realtime hub and dashboard MVP](epic-3-realtime-hub-dashboard.md) | 4 | Done |
| [Epic 4: Course-depth features](epic-4-course-depth.md) | 15 | In progress (as built): 11 Done, 2 Partial, 2 Backlog |
| [Epic 5: GRC and documentation](epic-5-grc-documentation.md) | 7 | In progress (as built): 5 Done, 1 Partial, 1 Backlog |
| [Epic 6: Hardening and rehearsal](epic-6-hardening-rehearsal.md) | 8 | In progress (as built): 3 Done, 4 Backlog, 1 Won't do |

**Legend.** *Done*: all criteria met and evidenced. *Partial*: built part verified, at least one criterion open (marked **⚠ Not met**). *Backlog*: not built, kept so the gap is visible. *Won't do*: excluded by the specification. *Verified by* lists test functions in backticks; anything else is a named artifact or a manual check (no automated browser tests exist, so UI criteria are manual plus the strict build).

## All stories

| Story | Title | Owner | Status | FRs | Tests cited |
|---|---|---|---|---|---|
| [1.1](epic-1-foundation.md) | Repository scaffold, safety rules and conventions | M5 | **Done** | FR-43 | 1 |
| [1.2](epic-1-foundation.md) | Configuration and secrets through one settings object | M3 | **Done** | FR-43 | 3 |
| [1.3](epic-1-foundation.md) | Event contract mirrored in TypeScript | M3 | **Done** | FR-24 | 2 |
| [1.4](epic-1-foundation.md) | Continuous integration quality gates | M5 | **Done** | NFR-1 | 0 |
| [1.5](epic-1-foundation.md) | Dashboard scaffold with a backend proxy | M4 | **Done** | NFR-8, NFR-9 | 0 |
| [2.1](epic-2-detection-core.md) | Inert demo payloads with expected verdicts | M5 | **Done** | SM-1 | 1 |
| [2.2](epic-2-detection-core.md) | Detect removable drives per operating system | M1 | **Partial** | FR-1 | 3 |
| [2.3](epic-2-detection-core.md) | Safe traversal, cancel on removal and size cap | M1 | **Done** | FR-2, FR-3, FR-4 | 4 |
| [2.4](epic-2-detection-core.md) | Single-pass fingerprint and entropy | M2 | **Done** | FR-6, FR-7 | 3 |
| [2.5](epic-2-detection-core.md) | Magic bytes, extension mismatch and filename tricks | M2 | **Done** | FR-8, FR-9, FR-13 | 4 |
| [2.6](epic-2-detection-core.md) | YARA rules for known bad patterns | M2 | **Done** | FR-11 | 3 |
| [2.7](epic-2-detection-core.md) | Find XOR-hidden executables | M2 | **Done** | FR-10 | 2 |
| [2.8](epic-2-detection-core.md) | Explained tiers, risk score and MITRE IDs | M2 | **Done** | FR-14 | 3 |
| [3.1](epic-3-realtime-hub-dashboard.md) | Realtime event hub with a SNAPSHOT on connect | M3 | **Done** | FR-24 | 2 |
| [3.2](epic-3-realtime-hub-dashboard.md) | Health, stats, history and the Simulated Drive | M3 | **Done** | FR-5, FR-25 | 5 |
| [3.3](epic-3-realtime-hub-dashboard.md) | Live tab: counters, entropy chart, scan queue and threat log | M4 | **Done** | FR-26, FR-28 | 0 |
| [3.4](epic-3-realtime-hub-dashboard.md) | Forensic drawer | M4 | **Done** | FR-27 | 0 |
| [4.1](epic-4-course-depth.md) | Authenticode presence check | M2 | **Partial** | FR-12 | 1 |
| [4.2](epic-4-course-depth.md) | Hash-only threat-intel providers | M2 | **Done** | FR-16, FR-17 | 7 |
| [4.3](epic-4-course-depth.md) | Rate limits, cache and offline mode | M2 | **Done** | FR-18, FR-19 | 11 |
| [4.4](epic-4-course-depth.md) | Intel verdicts change the Tier | M2 | **Done** | FR-20 | 9 |
| [4.5](epic-4-course-depth.md) | Latest-malware feed and manual hash lookup | M2 | **Done** | FR-21, FR-23 | 3 |
| [4.6](epic-4-course-depth.md) | Risk matrix and score in the dashboard | M4 | **Done** | FR-15 | 1 |
| [4.7](epic-4-course-depth.md) | Tamper-evident audit chain | M3 | **Done** | FR-30, FR-31, FR-32 | 8 |
| [4.8](epic-4-course-depth.md) | Station keys and signed reports | M3 | **Done** | FR-33, FR-34 | 7 |
| [4.9](epic-4-course-depth.md) | Offline verification and key pinning | M3 | **Done** | FR-35 | 3 |
| [4.10](epic-4-course-depth.md) | Filename redaction in signed reports | M3 | **Partial** | FR-36 | 1 |
| [4.11](epic-4-course-depth.md) | AES-256-GCM quarantine vault | M1 | **Done** | FR-37, FR-38, FR-39 | 8 |
| [4.12](epic-4-course-depth.md) | Refuse legacy ciphers and measure the alternative | M1 | **Done** | FR-40, FR-41 | 3 |
| [4.13](epic-4-course-depth.md) | Intel and Integrity panels | M4 | **Done** | FR-23, FR-30, FR-31, FR-34 | 0 |
| [4.14](epic-4-course-depth.md) | BadUSB keyboard-appearance alert | M1 | **Backlog** | FR-48 | 0 |
| [4.15](epic-4-course-depth.md) | Authenticode chain and digest validation | M2 | **Backlog** | FR-50 | 0 |
| [5.1](epic-5-grc-documentation.md) | Research, threat model and cryptographic design documents | M5 | **Done** | FR-44 | 2 |
| [5.2](epic-5-grc-documentation.md) | Risk register with NIST CSF and ISO 27001 mapping | M5 | **Done** | FR-46 | 1 |
| [5.3](epic-5-grc-documentation.md) | Privacy document and intel-cache retention | M5 | **Partial** | FR-47 | 1 |
| [5.4](epic-5-grc-documentation.md) | Viva Q&A | M5 | **Done** | FR-44 | 1 |
| [5.5](epic-5-grc-documentation.md) | Course Map, generated mapping document and About tab | M4 | **Done** | FR-29, FR-45 | 4 |
| [5.6](epic-5-grc-documentation.md) | Runbook and five-minute demo script | M5 | **Done** | UJ-2, SM-6 | 0 |
| [5.7](epic-5-grc-documentation.md) | Retention for the audit log and vault | M3 | **Backlog** | FR-52 | 0 |
| [6.1](epic-6-hardening-rehearsal.md) | Cross-site request protection | M3 | **Done** | FR-42 | 4 |
| [6.2](epic-6-hardening-rehearsal.md) | Warm the intel cache before a demo | M2 | **Done** | FR-22 | 5 |
| [6.3](epic-6-hardening-rehearsal.md) | Fresh-clone demo rehearsal | M5 | **Done** | NFR-1, SM-1, SM-2, SM-3 | 0 |
| [6.4](epic-6-hardening-rehearsal.md) | Validate on a real USB stick, Windows and Linux | M1 | **Backlog** | FR-53, FR-1 | 0 |
| [6.5](epic-6-hardening-rehearsal.md) | Performance on a 2-5 GB stick | M2 | **Backlog** | FR-53 | 0 |
| [6.6](epic-6-hardening-rehearsal.md) | Presentation slides | M5 | **Backlog** | - | 0 |
| [6.7](epic-6-hardening-rehearsal.md) | API authentication | M3 | **Backlog** | FR-51 | 0 |
| [6.8](epic-6-hardening-rehearsal.md) | Sandbox / dynamic analysis | M2 | **Won't do** | FR-49 | 0 |

## FR coverage

Every PRD requirement maps to a story in its epic; an FR can also appear in other stories (for example the contract half of FR-24 is Story 1.3, the hub itself is Story 3.1).

| FR | Requirement | PRD status | Epic | Stories |
|---|---|---|---|---|
| FR-1 | Detect removable Drives per OS | Partial | Epic 2 | [2.2](epic-2-detection-core.md) (Partial), [6.4](epic-6-hardening-rehearsal.md) (Backlog) |
| FR-2 | Traverse a Drive safely | Implemented | Epic 2 | [2.3](epic-2-detection-core.md) (Done) |
| FR-3 | Cancel a Scan when the Drive is removed | Implemented | Epic 2 | [2.3](epic-2-detection-core.md) (Done) |
| FR-4 | Cap work on large files | Implemented | Epic 2 | [2.3](epic-2-detection-core.md) (Done) |
| FR-5 | Present the demo folder as a Simulated Drive | Implemented | Epic 3 | [3.2](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-6 | Fingerprint files with SHA-256 | Implemented | Epic 2 | [2.4](epic-2-detection-core.md) (Done) |
| FR-7 | Measure entropy and chi-square | Implemented | Epic 2 | [2.4](epic-2-detection-core.md) (Done) |
| FR-8 | Detect extension mismatch by magic bytes | Implemented | Epic 2 | [2.5](epic-2-detection-core.md) (Done) |
| FR-9 | Detect double extensions and right-to-left override | Implemented | Epic 2 | [2.5](epic-2-detection-core.md) (Done) |
| FR-10 | Find single-byte-XOR-hidden executables | Implemented | Epic 2 | [2.7](epic-2-detection-core.md) (Done) |
| FR-11 | Match six YARA rules | Implemented | Epic 2 | [2.6](epic-2-detection-core.md) (Done) |
| FR-12 | Report Authenticode presence for PE files | Partial | Epic 4 | [4.1](epic-4-course-depth.md) (Partial) |
| FR-13 | Avoid false positives on compressed formats | Implemented | Epic 2 | [2.5](epic-2-detection-core.md) (Done) |
| FR-14 | Assign a Tier with reasons and MITRE IDs | Implemented | Epic 2 | [2.8](epic-2-detection-core.md) (Done) |
| FR-15 | Compute Risk Score on a 5×5 matrix | Implemented | Epic 4 | [4.6](epic-4-course-depth.md) (Done) |
| FR-16 | Look up hashes only, in a fixed order | Implemented | Epic 4 | [4.2](epic-4-course-depth.md) (Done) |
| FR-17 | Keep TLS verification on and never download samples | Implemented | Epic 4 | [4.2](epic-4-course-depth.md) (Done) |
| FR-18 | Respect provider limits | Implemented | Epic 4 | [4.3](epic-4-course-depth.md) (Done) |
| FR-19 | Work offline | Implemented | Epic 4 | [4.3](epic-4-course-depth.md) (Done) |
| FR-20 | Fold Intel Verdicts into the Tier | Implemented | Epic 4 | [4.4](epic-4-course-depth.md) (Done) |
| FR-21 | Cache the latest-malware feed | Implemented | Epic 4 | [4.5](epic-4-course-depth.md) (Done) |
| FR-22 | Warm the intel cache before a demo | Implemented | Epic 6 | [6.2](epic-6-hardening-rehearsal.md) (Done) |
| FR-23 | Look up a hash manually | Implemented | Epic 4 | [4.5](epic-4-course-depth.md) (Done), [4.13](epic-4-course-depth.md) (Done) |
| FR-24 | Stream events with a SNAPSHOT first | Implemented | Epic 3 | [1.3](epic-1-foundation.md) (Done), [3.1](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-25 | Serve health, stats and history | Implemented | Epic 3 | [3.2](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-26 | Show the Live tab | Implemented | Epic 3 | [3.3](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-27 | Explain a File Result in a forensic drawer | Implemented | Epic 3 | [3.4](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-28 | Survive reconnects without freezing | Implemented | Epic 3 | [3.3](epic-3-realtime-hub-dashboard.md) (Done) |
| FR-29 | Show the Course Map in an About tab | Implemented | Epic 5 | [5.5](epic-5-grc-documentation.md) (Done) |
| FR-30 | Chain every File Result and verify on demand | Implemented | Epic 4 | [4.7](epic-4-course-depth.md) (Done), [4.13](epic-4-course-depth.md) (Done) |
| FR-31 | Demonstrate and undo tampering live | Implemented | Epic 4 | [4.7](epic-4-course-depth.md) (Done), [4.13](epic-4-course-depth.md) (Done) |
| FR-32 | Persist the chain across restarts | Implemented | Epic 4 | [4.7](epic-4-course-depth.md) (Done) |
| FR-33 | Hold three Station Keys with self-signed certificates | Implemented | Epic 4 | [4.8](epic-4-course-depth.md) (Done) |
| FR-34 | Sign and verify a report | Implemented | Epic 4 | [4.8](epic-4-course-depth.md) (Done), [4.13](epic-4-course-depth.md) (Done) |
| FR-35 | Verify offline and pin the key | Implemented | Epic 4 | [4.9](epic-4-course-depth.md) (Done) |
| FR-36 | Redact filenames in reports | Partial | Epic 4 | [4.10](epic-4-course-depth.md) (Partial) |
| FR-37 | Encrypt flagged files with AES-256-GCM | Implemented | Epic 4 | [4.11](epic-4-course-depth.md) (Done) |
| FR-38 | Restore with integrity re-check | Implemented | Epic 4 | [4.11](epic-4-course-depth.md) (Done) |
| FR-39 | Delete an original only on explicit request | Implemented | Epic 4 | [4.11](epic-4-course-depth.md) (Done) |
| FR-40 | Refuse legacy ciphers | Implemented | Epic 4 | [4.12](epic-4-course-depth.md) (Done) |
| FR-41 | Provide measured demonstrations for Weeks 4 and 6 | Implemented | Epic 4 | [4.12](epic-4-course-depth.md) (Done) |
| FR-42 | Refuse cross-site writes and WebSockets | Implemented | Epic 6 | [6.1](epic-6-hardening-rehearsal.md) (Done) |
| FR-43 | Never touch secrets or real services in tests | Implemented | Epic 1 | [1.1](epic-1-foundation.md) (Done), [1.2](epic-1-foundation.md) (Done) |
| FR-44 | Ship the design documents with references | Implemented | Epic 5 | [5.1](epic-5-grc-documentation.md) (Done), [5.4](epic-5-grc-documentation.md) (Done) |
| FR-45 | Keep the Course Map and its doc in sync | Implemented | Epic 5 | [5.5](epic-5-grc-documentation.md) (Done) |
| FR-46 | Record and treat risks | Implemented | Epic 5 | [5.2](epic-5-grc-documentation.md) (Done) |
| FR-47 | Purge the intel cache by age | Partial | Epic 5 | [5.3](epic-5-grc-documentation.md) (Partial) |
| FR-48 | BadUSB keyboard-appearance alert | Not built | Epic 4 | [4.14](epic-4-course-depth.md) (Backlog) |
| FR-49 | Dynamic analysis / sandbox | Not built | Epic 6 | [6.8](epic-6-hardening-rehearsal.md) (Won't do) |
| FR-50 | Authenticode chain and digest validation | Not built | Epic 4 | [4.15](epic-4-course-depth.md) (Backlog) |
| FR-51 | Authentication on the local API | Not built | Epic 6 | [6.7](epic-6-hardening-rehearsal.md) (Backlog) |
| FR-52 | Retention for the audit log and Vault | Not built | Epic 5 | [5.7](epic-5-grc-documentation.md) (Backlog) |
| FR-53 | Validation on Windows/Linux hardware and on a 2–5 GB stick | Not built | Epic 6 | [6.4](epic-6-hardening-rehearsal.md) (Backlog), [6.5](epic-6-hardening-rehearsal.md) (Backlog) |

## How these were produced

Created with the BMAD `bmad-create-epics-and-stories` workflow from the as-built PRD and architecture, with these honest adaptations:

- **Epic structure was given, not designed.** The six epics come from the original specification, so Epics 1 and 6 are partly technical or process epics. The file-overlap check (the analyzer and the API are touched by several epics) was considered; consolidation was rejected because the specification fixed the epics and they follow different risk boundaries (detection, realtime, evidence, documentation, hardening).
- **XOR detection moved to Epic 2** (the specification listed it under Epic 4) because the Tier story depends on it and it was built in the detection core. Authenticode stays in Epic 4 as specified.
- **Dependency order.** Each story depends only on earlier stories in its epic or on earlier epics: the demo payloads come first in Epic 2, and the dashboard panels come after the endpoints they call in Epic 4. References to later *backlog* stories (for example 2.2 pointing to 6.4) track open gaps; they are not build dependencies.
- **Automated checks run at generation time:** every cited test exists in `qa_demo/`; every FR is cited by a story in its mapped epic; no Done story has an unmet criterion; no Backlog or Won't-do story has a met one; story statuses agree with the PRD's status for each FR; no story depends on a later story in its own epic.
- **Approvals.** The workflow's confirmation menus were satisfied by the instructions that fixed the epics, the Done / Partial / Backlog rule and the evidence rule, rather than by interactive prompts.
