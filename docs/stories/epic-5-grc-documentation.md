---
epic: 5
title: "GRC and documentation"
status: "In progress (as built): 5 Done, 1 Partial, 1 Backlog"
updated: 2026-11-20
---

# Epic 5: GRC and documentation

The design is justified and auditable: research, threat model, crypto design, risk register, privacy, viva Q&A, the Course Map and the runbook.

**Status:** In progress (as built): 5 Done, 1 Partial, 1 Backlog  
**FRs covered:** FR-29, FR-44, FR-45, FR-46, FR-47, FR-52  
**Stories:** 7 · **Owners:** M3, M4, M5  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 5.1: Research, threat model and cryptographic design documents

As an examiner,  
I want documents that justify each security decision, in the team's own words with references,  
So that I can see the work was understood, not copied.

**Status:** Done · **Owner:** M5 · **Covers:** FR-44 · **Course week:** 1, 2, 3-8, 15 · **Architecture:** AD-16

**Acceptance Criteria:**

**Given** each design document  
**When** it is checked  
**Then** it has a References section with URLs and the access date, and no unfinished markers  
*Verified by:* `test_every_doc_has_references_with_access_date`, `test_docs_do_not_contain_unfinished_markers`

**Given** `CRYPTO_DESIGN.md`  
**When** it is read  
**Then** it quotes the measured AES/3DES and signature numbers and states what the hash chain does not prove  
*Verified by:* artifact: docs/CRYPTO_DESIGN.md

---

### Story 5.2: Risk register with NIST CSF and ISO 27001 mapping

As an examiner,  
I want scored risks with treatments and a governance mapping,  
So that I can follow the risk lifecycle from Weeks 10 to 13.

**Status:** Done · **Owner:** M5 · **Covers:** FR-46 · **Course week:** 10, 11-13 · **Architecture:** AD-16

**Acceptance Criteria:**

**Given** `RISK_REGISTER.md`  
**When** it is read  
**Then** it lists 14 risks with likelihood, impact, score, treatment (avoid, mitigate, transfer, accept) and owner, plus NIST CSF 2.0 and ISO 27001 A.7.10 and A.8.7  
*Verified by:* artifact: docs/RISK_REGISTER.md, `test_every_doc_has_references_with_access_date`

---

### Story 5.3: Privacy document and intel-cache retention

As an operator,  
I want privacy principles applied and old cached intel purged,  
So that personal data is minimised and not kept forever.

**Status:** Partial · **Owner:** M5 · **Covers:** FR-47 · **Course week:** 14 · **Architecture:** AD-14

**Acceptance Criteria:**

**Given** `PRIVACY.md`  
**When** it is read  
**Then** GDPR principles, redaction, third-party transfers and the chain-versus-erasure tension are stated  
*Verified by:* artifact: docs/PRIVACY.md, `test_every_doc_has_references_with_access_date`

**Given** the server starts  
**When** cached intel is older than `AEGIS_RETENTION_DAYS`  
**Then** it is purged  
*Verified by:* artifact: IntelCache.purge (no dedicated test)

**⚠ Not met** · **Given** the audit log or the vault  
**When** they are older than the retention period  
**Then** they are purged  
*Verified by:* NOT DONE: not auto-purged; tracked in Story 5.7

---

### Story 5.4: Viva Q&A

As an examiner,  
I want 25 likely questions with crisp, honest answers mapped to course weeks,  
So that the team is ready to defend every claim.

**Status:** Done · **Owner:** M5 · **Covers:** FR-44 · **Course week:** all · **Architecture:** AD-16

**Acceptance Criteria:**

**Given** `VIVA_QA.md`  
**When** it is checked  
**Then** it contains exactly 25 questions and a References section with the access date  
*Verified by:* `test_every_doc_has_references_with_access_date`

---

### Story 5.5: Course Map, generated mapping document and About tab

As an examiner,  
I want a table from lecture week to feature to files, in the app and in the docs,  
So that I can see coverage and gaps in one place.

**Status:** Done · **Owner:** M4 · **Covers:** FR-29, FR-45 · **Course week:** 1 · **Architecture:** AD-16

**Acceptance Criteria:**

**Given** every row of the Course Map  
**When** the files are checked  
**Then** each linked file exists  
*Verified by:* `test_every_course_row_file_exists`

**Given** `COURSE_MAPPING.md`  
**When** it is compared with the generator output  
**Then** they are identical  
*Verified by:* `test_course_mapping_doc_is_generated_from_the_map`

**Given** the map  
**When** it is inspected  
**Then** it covers weeks 1-8, 10, 11-13, 14 and 15 and marks Week 15 as Partial  
*Verified by:* `test_course_map_covers_the_weeks_in_the_spec_and_is_honest_about_gaps`

**Given** the file endpoint  
**When** traversal, `.env` or unlisted paths are requested  
**Then** 404 for all; allow-listed files return plain text  
*Verified by:* `test_course_map_endpoint_and_file_allowlist`

**Given** the About tab  
**When** it is opened  
**Then** the table renders with working file links  
*Verified by:* manual: fresh-clone click-through

---

### Story 5.6: Runbook and five-minute demo script

As a team member,  
I want setup steps, a pre-demo checklist, a timed script and talking points for M1-M5,  
So that anyone can run and present the demo.

**Status:** Done · **Owner:** M5 · **Covers:** UJ-2, SM-6 · **Course week:** 1 · **Architecture:** AD-17

> Supports a user journey and a metric rather than a single FR.

**Acceptance Criteria:**

**Given** a fresh clone  
**When** the README steps are followed literally  
**Then** payloads generate, tests pass and the demo runs on port 8011  
*Verified by:* fresh-clone run recorded in PR #1

**Given** `qa_demo/README.md`  
**When** it is read  
**Then** it contains setup, the "10 minutes before class" steps, the demo script, talking points and troubleshooting  
*Verified by:* artifact: qa_demo/README.md

---

### Story 5.7: Retention for the audit log and vault

As an operator,  
I want a retention rule that also covers the audit log and the vault,  
So that stored data does not outlive its purpose.

**Status:** Backlog · **Owner:** M3 · **Covers:** FR-52 · **Course week:** 14 · **Architecture:** AD-14

**Acceptance Criteria:**

**⚠ Not met** · **Given** records older than the retention period  
**When** the server starts  
**Then** they are removed without breaking the chain  
*Verified by:* NOT DONE: conflicts with tamper-evidence; needs a policy decision (PRIVACY.md section 4)

