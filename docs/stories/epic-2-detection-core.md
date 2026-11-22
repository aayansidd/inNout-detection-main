---
epic: 2
title: "Detection core"
status: "In progress (as built): 7 Done, 1 Partial"
updated: 2026-11-20
---

# Epic 2: Detection core

A drive is detected and scanned safely, and every file gets a fingerprint, static findings and an explained Tier.

**Status:** In progress (as built): 7 Done, 1 Partial  
**FRs covered:** FR-1, FR-2, FR-3, FR-4, FR-6, FR-7, FR-8, FR-9, FR-10, FR-11, FR-13, FR-14  
**Stories:** 8 · **Owners:** M1, M2, M5  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 2.1: Inert demo payloads with expected verdicts

As a team member,  
I want a generator that writes 12 harmless files and prints each expected Tier,  
So that the demo and the tests share one known set of inputs.

**Status:** Done · **Owner:** M5 · **Covers:** SM-1 · **Course week:** 1, 2 · **Architecture:** AD-9

> Supports the success metric SM-1 rather than a single FR.

**Acceptance Criteria:**

**Given** `generate_payloads.py`  
**When** it is run  
**Then** 12 inert files are written and the expected table is printed; no real malware and no real EICAR file is created  
*Verified by:* artifact: qa_demo/generate_payloads.py, `test_each_payload_expected_tier_and_rules`

**Given** the payload bytes  
**When** they are generated twice  
**Then** hashes are identical (seeded), so the offline IOC entry stays valid  
*Verified by:* artifact: seeded generator; qa_demo/local_ioc.txt

---

### Story 2.2: Detect removable drives per operating system

As an operator,  
I want a newly inserted USB stick to be recognised, and system volumes and disk images to be ignored,  
So that scanning starts on the right drive without any clicks.

**Status:** Partial · **Owner:** M1 · **Covers:** FR-1 · **Course week:** 15 · **Architecture:** AD-18, AD-2

> Built part verified with fake partitions; the real-hardware criterion is open.

**Acceptance Criteria:**

**Given** partitions on Windows, Linux and macOS  
**When** the removable rules run  
**Then** Windows needs `removable` and not `cdrom`; Linux needs `/media`, `/run/media` or sysfs `removable == 1`; `/mnt` is never removable; macOS system volumes are excluded  
*Verified by:* `test_is_removable_rules`

**Given** a macOS volume  
**When** `diskutil info` reports a disk image or a USB/removable bus  
**Then** disk images are rejected, USB and removable media accepted  
*Verified by:* `test_darwin_diskutil_rule`

**Given** `diskutil` fails  
**When** the volume is checked  
**Then** it is treated as not USB and the failure is not cached  
*Verified by:* `test_darwin_diskutil_failure_is_not_usb_and_not_cached`

**⚠ Not met** · **Given** a real USB stick on Windows, Linux or macOS  
**When** it is plugged in  
**Then** `USB_CONNECTED` appears within 2 s  
*Verified by:* NOT DONE: no real stick has been exercised on any OS; tracked in Story 6.4

---

### Story 2.3: Safe traversal, cancel on removal and size cap

As an operator,  
I want a drive to be walked safely and a pulled stick to stop the scan cleanly,  
So that hostile or huge drives cannot hang or harm the station.

**Status:** Done · **Owner:** M1 · **Covers:** FR-2, FR-3, FR-4 · **Course week:** 1, 15 · **Architecture:** AD-9, AD-2

**Acceptance Criteria:**

**Given** a tree with system folders, hidden files and a symlink  
**When** the walker runs  
**Then** hidden files are scanned, system folders skipped, the symlink not followed and counted as skipped  
*Verified by:* `test_walker_skips_symlinks_and_system_dirs`

**Given** a scan whose cancel event is set  
**When** the scan job runs  
**Then** no `FILE_SCANNED` results are emitted and `SCAN_COMPLETE` reports `cancelled`  
*Verified by:* `test_scan_job_cancel_drops_results`

**Given** a file larger than the size cap  
**When** it is analysed  
**Then** only header and name checks run: `scan_status` is `PARTIAL`, `sha256` is null and it can still be CRITICAL  
*Verified by:* `test_oversize_file_is_partial`

**Given** the demo drive  
**When** a full scan job runs  
**Then** every file is counted and the tallies add up  
*Verified by:* `test_scan_job_full_drive_counts`

---

### Story 2.4: Single-pass fingerprint and entropy

As an operator,  
I want each file hashed and its randomness measured in one read,  
So that I can identify a file and spot packed or encrypted content.

**Status:** Done · **Owner:** M2 · **Covers:** FR-6, FR-7 · **Course week:** 6, 2 · **Architecture:** AD-9

**Acceptance Criteria:**

**Given** byte data using 137 or 158 evenly spread values, and an empty file  
**When** entropy is computed  
**Then** 137 values (H ≈ 7.10) are not flagged, 158 (H ≈ 7.30) are, empty gives 0.0  
*Verified by:* `test_entropy_thresholds`, `test_entropy_flagging_via_analyzer`

**Given** a one-bit change in a message  
**When** SHA-256 is computed  
**Then** about half of the output bits change  
*Verified by:* `test_avalanche_one_bit_changes_about_half_the_hash_bits`

**Given** a scanned file  
**When** its details are shown  
**Then** SHA-256 is primary and MD5/SHA-1 are labelled legacy and collision-prone  
*Verified by:* manual: forensic drawer (see Story 3.4)

---

### Story 2.5: Magic bytes, extension mismatch and filename tricks

As an operator,  
I want disguised executables and misleading filenames to be caught,  
So that a `.pdf` that is really a program does not slip through.

**Status:** Done · **Owner:** M2 · **Covers:** FR-8, FR-9, FR-13 · **Course week:** 2, 11-13 · **Architecture:** AD-7

**Acceptance Criteria:**

**Given** an executable header with a `.pdf` extension, and with an `.exe` extension  
**When** names are checked  
**Then** the first is a mismatch, the second is not; `report.pdf.exe` and right-to-left names are flagged  
*Verified by:* `test_magic_and_names`

**Given** `invoice.pdf` starting `MZ`  
**When** it is analysed  
**Then** the reason reads "Magic bytes (MZ) mismatch claimed .pdf extension", risk is 25 and `T1036.008` is tagged  
*Verified by:* `test_invoice_matches_contract_example`

**Given** an executable whose name contains U+202E  
**When** it is analysed  
**Then** it is CRITICAL  
*Verified by:* `test_rtlo_exe_is_critical`

**Given** a PNG with random pixels  
**When** it is analysed  
**Then** entropy is high but exempt, so it stays SAFE with an explanatory reason  
*Verified by:* `test_png_exempt_and_xor_reported`

---

### Story 2.6: YARA rules for known bad patterns

As an operator,  
I want content rules for autorun abuse, PowerShell droppers, packers, shadow-copy deletion and a demo signature,  
So that dangerous content is caught even when the name looks innocent.

**Status:** Done · **Owner:** M2 · **Covers:** FR-11 · **Course week:** 2 · **Architecture:** AD-9

**Acceptance Criteria:**

**Given** the rule file  
**When** it is compiled  
**Then** all six rules compile  
*Verified by:* `test_yara_rules_compile`

**Given** a clean text file  
**When** it is scanned  
**Then** nothing matches  
*Verified by:* `test_clean_text_hits_nothing`

**Given** each demo payload  
**When** it is scanned  
**Then** it matches exactly its expected rule  
*Verified by:* `test_each_payload_expected_tier_and_rules`

---

### Story 2.7: Find XOR-hidden executables

As an operator,  
I want an executable hidden with a single-byte XOR to be unmasked,  
So that classical obfuscation does not hide malware from me.

**Status:** Done · **Owner:** M2 · **Covers:** FR-10 · **Course week:** 2 · **Architecture:** AD-7

**Acceptance Criteria:**

**Given** a DOS/PE stub XOR-ed with any key 0x01-0xFF  
**When** the first 512 bytes are tested  
**Then** the right key is found; an unobfuscated stub and random bytes give none  
*Verified by:* `test_xor_detection_finds_key`

**Given** `cache/blob.dat`  
**When** it is analysed  
**Then** it reports key 0x5A, tags `T1027` and is CRITICAL  
*Verified by:* `test_png_exempt_and_xor_reported`

---

### Story 2.8: Explained tiers, risk score and MITRE IDs

As an operator,  
I want every file to get a Tier, a likelihood × impact score, reasons and ATT&CK IDs,  
So that I know what to do first and why.

**Status:** Done · **Owner:** M2 · **Covers:** FR-14 · **Course week:** 11-13 · **Architecture:** AD-7

**Acceptance Criteria:**

**Given** the 12 demo files  
**When** they are analysed  
**Then** each lands in its expected Tier (3 SAFE, 2 SUSPICIOUS, 7 CRITICAL), has non-empty reasons and `risk_score = likelihood × impact`  
*Verified by:* `test_each_payload_expected_tier_and_rules`, `test_scan_job_full_drive_counts`

**Given** `invoice.pdf`  
**When** it is analysed  
**Then** its risk is 25 (5 × 5) with `T1036.008`  
*Verified by:* `test_invoice_matches_contract_example`

