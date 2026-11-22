---
title: AEGIS USB
status: final
created: 2026-11-20
updated: 2026-11-20
kind: as-built (brownfield) PRD
---

# PRD: AEGIS USB (as built)

## 0. Document Purpose

This is a **brownfield, as-built PRD**: it describes what AEGIS USB *already does*, not what it
might do. It is written for the examiner and the five-person team (M1–M5) and feeds
`docs/architecture.md` and `docs/stories/`. Every functional requirement (FR) states the **IS-353
course week** it demonstrates, its **status** (Implemented / Partial / Not built), and the **test
or artifact that proves it**. Where the build falls short of the original specification
(`docs/MASTER_PROMPT.md`), the FR is kept and marked honestly rather than dropped; see §5 and §9.

Sources of truth: the code under `backend/` and `frontend/`, the tests under `qa_demo/`
(**139 collected cases from 106 test functions**), and `docs/*.md`. Vocabulary is anchored by the
Glossary (§3); FR, UJ and SM numbers are stable.

## 1. Vision

AEGIS USB is a real-time USB screening and evidence tool: **plug in a drive and see a verdict
(hashed, scored, checked against threat intelligence and cryptographically signed) before anyone
opens a file.** It reads a drive without ever executing it, explains every verdict in plain English
with MITRE ATT&CK IDs, and records what it saw in a tamper-evident log that can be signed and
verified by anyone, offline.

It exists because removable media remains a favoured way into isolated networks, and because the
IS-353 course topics (CIA, attack taxonomy, symmetric and asymmetric crypto, hashes, signatures,
trust on the Internet, GRC, risk, privacy, attack surfaces) are easiest to understand when they
all solve one concrete problem. The thesis: a **small, honest, explainable** tool with verifiable
evidence teaches more, and is safer to claim, than a black box that claims to catch everything.

## 2. Target User

### 2.1 Jobs To Be Done
- *Functional:* "Tell me whether this drive is safe to open, and why, in under a minute."
- *Functional:* "Give me evidence I can hand to someone else that proves what was found and that
  it was not altered afterwards."
- *Contextual:* "Work in a lab with no Internet, or with limited Internet, without losing the
  ability to screen."
- *Course:* "Show an examiner how each lecture week appears in one working system, including where
  we stopped short."

### 2.2 Non-Users (v1)
Not for enterprises needing centrally managed, enforced media control; not for people who need a
malware sandbox or multi-engine local scanner; not a substitute for operating-system device
policy against malicious *devices* (see §5).

### 2.3 Key User Journeys
*All journeys below are supported by the build today. Protagonists are fictional [ASSUMPTION: personas and the examiner illustrate real use; no user research was done].*

- **UJ-1. Hira screens a stick found in the lab.**
  - **Persona + context:** Hira, a university lab technician, has an unlabelled USB stick.
  - **Entry state:** API and dashboard running on the lab PC; intel keys optional.
  - **Path:** plugs the stick in → drive pill appears with a progress bar → files appear in the
    scan queue → counters and risk matrix fill → opens the worst file's forensic drawer.
  - **Climax:** the drawer says *why* (e.g. "Magic bytes (MZ) mismatch claimed .pdf extension"),
    with MITRE ID and risk 25/25.
  - **Resolution:** Hira leaves the stick alone and keeps the evidence.
  - **Edge case:** pulling the stick mid-scan cancels the scan and drops in-flight results.
- **UJ-2. Bilal runs the five-minute live demo.**
  - **Persona + context:** Bilal, team presenter, no spare USB stick and flaky venue Wi-Fi.
  - **Entry state:** `warm_cache` run 10 minutes earlier; dashboard open.
  - **Path:** Simulate USB → counters 3 / 2 / 7 → Intel tab EICAR lookup → quarantine and sign →
    tamper demo → Eject.
  - **Climax:** "Chain BROKEN at #n" appears live after a silent edit.
  - **Resolution:** Undo tampering; chain verified again.
  - **Edge case:** network dies → offline mode keeps everything but live lookups working.
- **UJ-3. Hira quarantines a file and hands a signed report to Sara.**
  - **Persona + context:** Sara, the lab manager, must be able to trust the report without
    trusting Hira's PC.
  - **Path:** Hira quarantines the file (encrypted copy) → signs the scan's report (RSA-PSS) →
    downloads the JSON → Sara runs `verify_report.py` and compares the key fingerprint.
  - **Climax:** "VALID" with a matching fingerprint; a one-digit change makes it "INVALID".
  - **Resolution:** the original stays on the drive; Hira decides separately whether to delete it.
- **UJ-4. Dr. Qureshi, the examiner, probes integrity.**
  - **Persona + context:** an examiner testing whether the claims hold.
  - **Path:** asks for the audit chain to be tampered with → watches the badge turn BROKEN at the
    edited record → asks which sources agree about the EICAR hash.
  - **Climax:** the system names the exact broken record and reports that sources *disagree*
    (VirusTotal malicious, CIRCL known-good, MalwareBazaar not found) with malicious winning.
  - **Edge case:** examiner asks about BadUSB → answered honestly as *not covered* (FR-48).
- **UJ-5. Imran screens drives in an air-gapped lab.**
  - **Persona + context:** Imran's lab forbids outbound connections.
  - **Path:** sets offline mode → scans a drive → the local IOC list flags a known hash.
  - **Climax:** the Intel tab says "offline" yet verdicts, quarantine, signing and the audit chain
    all still work.

## 3. Glossary
*Terms are used verbatim throughout this PRD and in `architecture.md` and the stories.*

- **Station** — the one PC running AEGIS (API + dashboard); owns the Station Key and the Vault.
- **Operator** — a person using the dashboard.
- **Drive** — a removable volume (or the Simulated Drive) being scanned. Has a drive id (`E:\`,
  `/Volumes/X`, or `Z:\`).
- **Simulated Drive** — the demo folder `qa_demo/sample_usb_drive/` presented as drive `Z:\`.
- **Scan** — one pass over one Drive, identified by a `scan_id`.
- **File Result** — the static-analysis outcome for one file (`FILE_SCANNED`): hashes, entropy,
  Tier, reasons, MITRE IDs.
- **Tier** — SAFE, SUSPICIOUS or CRITICAL.
- **Risk Score** — likelihood × impact, each 1–5 (1–25).
- **Indicator** — one finding that contributes to a Tier (YARA hit, mismatch, XOR key, …).
- **Intel Provider** — a hash-only lookup source: Local IOC, CIRCL, MalwareBazaar, VirusTotal.
- **Intel Verdict** — a provider's answer: malicious, suspicious, clean, known_good, not_found,
  error or skipped.
- **Enrichment** — a `FILE_ENRICHED` event that updates a File Result from Intel Verdicts.
- **Known-good** — an Intel Verdict from a known-file corpus (NSRL via CIRCL); advisory only.
- **Offline Mode** — `AEGIS_INTEL_OFFLINE=true`: no network lookups; Local IOC only.
- **Audit Chain** — the SHA-256 hash chain plus HMAC over every File Result.
- **Station Key** — a private/public key pair held by the Station (RSA-3072, DSA-3072, Ed25519)
  with a self-signed certificate "AEGIS Scanner Station".
- **Signed Report** — canonical-JSON report of one Scan plus signature, algorithm, public key and
  certificate.
- **Vault** — the AES-256-GCM encrypted quarantine store.
- **Quarantine Entry** — one file copied into the Vault with its metadata.
- **Course Map** — the week → feature → files table (`course_map.py`), shown in the About tab.

## 4. Features

*Each FR lists **Week** (IS-353 lecture week), **Status** and **Evidence** (test function or
artifact). "Test" names are in `qa_demo/`.*

### 4.1 Drive monitoring and safe traversal *(owner M1)*
**Description:** The Station polls mounted volumes once a second, decides per operating system
what counts as removable media, and scans each Drive on a worker pool without ever executing,
opening or importing a file. Realizes UJ-1, UJ-5.

#### FR-1: Detect removable Drives per OS
The Station detects a newly inserted Drive and emits `USB_CONNECTED`; removal emits
`USB_DISCONNECTED`. **Week 15** · **Status: Partial** · Evidence: `test_is_removable_rules`,
`test_darwin_diskutil_rule`, `test_darwin_diskutil_failure_is_not_usb_and_not_cached`.
**Consequences (testable):**
- Windows: `removable` option present and not `cdrom`; Linux: `/media`, `/run/media` or sysfs
  `removable == 1`, and **never** `/mnt` (WSL mounts `C:` there); macOS: `/Volumes/*` accepted only
  if `diskutil info` reports a USB bus or removable media, and a mounted `.dmg` (BusProtocol
  "Disk Image") is rejected even though it reports RemovableMedia.
- Poll interval 1 s (`POLL_SECONDS`).
- **Partial because** the rules are unit-tested with fake partitions; a *real stick* was never
  exercised on any OS, and Windows/Linux were never run on hardware (§9).

#### FR-2: Traverse a Drive safely
**Week 1 (availability) / 15** · **Status: Implemented** · Evidence: `test_walker_skips_symlinks_and_system_dirs`.
- Iterative `os.scandir`; symlinks never followed (counted as skipped); hidden files scanned;
  `System Volume Information`, `$RECYCLE.BIN`, `.Trashes`, `.Spotlight-V100`, `.fseventsd` skipped;
  `PermissionError` tolerated and counted as skipped.
- `SCAN_PROGRESS` throttled to at most every 0.25 s with files discovered/scanned/skipped.

#### FR-3: Cancel a Scan when the Drive is removed
**Week 1 (availability)** · **Status: Implemented** · Evidence: `test_scan_job_cancel_drops_results`.
- Removal sets a cancel event; in-flight results are dropped; `SCAN_COMPLETE` reports
  `cancelled: true`.

#### FR-4: Cap work on large files
**Week 1 (availability)** · **Status: Implemented** · Evidence: `test_oversize_file_is_partial`.
- Files over `AEGIS_MAX_SCAN_FILE_SIZE_MB` (default 50) get header and name checks only,
  `scan_status: "PARTIAL"`, `sha256: null`; a PARTIAL file can still be CRITICAL.

#### FR-5: Present the demo folder as a Simulated Drive
**Week: cross-cutting (demonstration aid for Weeks 2–8)** · **Status: Implemented** ·
Evidence: `test_websocket_snapshot_first_then_simulate`, `test_eject_and_resimulate`,
`test_simulate_without_drive_is_409`, `test_demo_mode_off_blocks_demo_endpoints`.
- `POST /api/demo/simulate` scans the demo folder as `Z:\`; `POST /api/demo/eject` removes it.
- Returns 409 if the demo folder is missing or already scanning; 403 when `AEGIS_DEMO_MODE=false`.

### 4.2 Static detection engine *(owner M2)*
**Description:** One streaming pass per file feeds hashes and a byte histogram; independent checks
then produce Indicators. Realizes UJ-1.

#### FR-6: Fingerprint files with SHA-256
**Week 6** · **Status: Implemented** · Evidence: `test_each_payload_expected_tier_and_rules`,
`test_avalanche_one_bit_changes_about_half_the_hash_bits`.
- Streaming SHA-256 in 64 KB chunks (`CHUNK_SIZE`); MD5 and SHA-1 computed only for intel
  compatibility and labelled "legacy, collision-prone" in the UI.

#### FR-7: Measure entropy and chi-square
**Week 2** · **Status: Implemented** · Evidence: `test_entropy_thresholds`, `test_entropy_flagging_via_analyzer`.
- Shannon entropy over 256 byte values (0–8); empty file → 0.0; **> 7.2** is high.
- 137 evenly used byte values (H ≈ 7.10) → not flagged; 158 values (H ≈ 7.30) → flagged.
- Chi-square against a uniform distribution is shown in the forensic drawer.

#### FR-8: Detect extension mismatch by magic bytes
**Week 2** · **Status: Implemented** · Evidence: `test_magic_and_names`, `test_invoice_matches_contract_example`.
- Recognises MZ, ELF, Mach-O (4 variants), PDF, PNG, JPEG, GIF, ZIP, OLE, 7z, RAR, gzip, LNK, MP4.
- Executable header behind `.pdf .docx .xlsx .pptx .jpg .png .gif .txt .csv .mp3 .mp4` (and
  `.jpeg`) is `extension_mismatch`; reason reads "Magic bytes (MZ) mismatch claimed .pdf extension".

#### FR-9: Detect double extensions and right-to-left override
**Week 2** · **Status: Implemented** · Evidence: `test_magic_and_names`, `test_rtlo_exe_is_critical`.
- `report.pdf.exe` is flagged (MITRE T1036.007); U+202E is flagged (T1036.002), CRITICAL when the
  file is executable by extension or header, otherwise SUSPICIOUS.

#### FR-10: Find single-byte-XOR-hidden executables
**Week 2 (classical cryptography)** · **Status: Implemented** · Evidence: `test_xor_detection_finds_key`,
`test_png_exempt_and_xor_reported`.
- Tries keys 0x01–0xFF on the first 512 bytes; a result starting `MZ` and containing
  "This program cannot be run" reports "XOR-obfuscated PE (key 0x??)" (T1027). `cache/blob.dat`
  yields key 0x5A.

#### FR-11: Match six YARA rules
**Week 2** · **Status: Implemented** · Evidence: `test_yara_rules_compile`, `test_clean_text_hits_nothing`,
`test_each_payload_expected_tier_and_rules`.
- Rules: `Autorun_Inf_Abuse`, `Suspicious_PowerShell_Dropper`, `Magic_Spoof_Executable`,
  `UPX_Packed_Executable`, `Ransomware_Shadow_Delete`, `Demo_EICAR_Signature`; compiled once with
  externals `filename` and `extension`; scanned by file path with a **10 s timeout**.
- Each demo payload hits exactly its expected rule; a clean text file hits none.

#### FR-12: Report Authenticode presence for PE files
**Week 7** · **Status: Partial** · Evidence: `test_authenticode_states`.
- Reports `signed`, `unsigned` or `invalid` from the PE certificate table's presence and
  structure. **Not built:** certificate-chain or digest validation (FR-50).

#### FR-13: Avoid false positives on compressed formats
**Week 2 / 11–13** · **Status: Implemented** · Evidence: `test_png_exempt_and_xor_reported`.
- JPEG, PNG, ZIP/OOXML, PDF, MP4, 7z, gzip whose extension agrees with the header are exempt from
  the entropy Indicator, with an explanatory reason.

### 4.3 Risk scoring and tiers *(owner M2)*
**Description:** Indicators are folded into a deterministic Tier and a likelihood × impact Risk
Score. Realizes UJ-1, UJ-4.

#### FR-14: Assign a Tier with reasons and MITRE IDs
**Week 11–13** · **Status: Implemented** · Evidence: `test_each_payload_expected_tier_and_rules`
(all 12 demo files), `test_invoice_matches_contract_example`.
- CRITICAL: any YARA hit, executable mismatch, double-extension/RTLO executable, XOR-hidden PE.
  SUSPICIOUS: non-exempt high entropy, script/autorun extension (`.vbs .js .ps1 .bat .cmd .scr
  .lnk .hta`). SAFE otherwise.
- Demo expectation: 3 SAFE, 2 SUSPICIOUS, 7 CRITICAL; every result carries non-empty `reasons[]`.

#### FR-15: Compute Risk Score on a 5×5 matrix
**Week 11–13** · **Status: Implemented** · Evidence: `test_invoice_matches_contract_example`
(25 = 5×5); UI `RiskMatrix.tsx`.
- Likelihood 4 or 5 (5 with ≥ 2 Indicators) × impact 5 for CRITICAL; 3 or 4 × 3 for SUSPICIOUS;
  1 × 2 for SAFE; `risk_score = likelihood × impact`.

### 4.4 Threat intelligence *(owner M2)*
**Description:** Only a SHA-256 ever leaves the Station. Providers are queried in order and results
arrive later as Enrichments, so scanning never waits on the network. Realizes UJ-2, UJ-4, UJ-5.

#### FR-16: Look up hashes only, in a fixed order
**Week 14 (data minimisation)** · **Status: Implemented** · Evidence:
`test_malwarebazaar_malicious_sends_hash_only`, `test_safe_text_file_is_never_sent_to_the_network`,
`test_warm_cache_sends_only_hashes`.
- Order: cache → Local IOC → CIRCL → MalwareBazaar (`get_info`) → VirusTotal v3.
- MalwareBazaar's request body is exactly `query` and `hash`; no filename appears in any
  outgoing request; SAFE non-executable files are not sent at all.

#### FR-17: Keep TLS verification on and never download samples
**Week 8** · **Status: Implemented** · Evidence: `test_source_never_disables_tls_verification_or_downloads_samples`.
- A test scans the source for disabled certificate checking and for `get_file`; either fails the
  build.

#### FR-18: Respect provider limits
**Week 11–13 (risk mitigation, R9)** · **Status: Implemented** · Evidence:
`test_429_triggers_exponential_backoff_then_succeeds`, `test_persistent_429_becomes_error_not_crash`,
`test_token_bucket_limits_rate_with_fake_clock`, `test_vt_daily_quota_exhausted_is_skipped`,
`test_low_quota_reserves_vt_for_flagged_files`, `test_cache_hit_avoids_network_call`.
- VirusTotal token bucket 4 requests/minute; daily quota 500 (configurable); below 50 remaining
  only SUSPICIOUS/CRITICAL files use it.
- HTTP 429: Retry-After honoured else 1 s, 2 s, 4 s back-off; errors are never cached.
- SQLite cache: found answers 24 h, "not found" 1 h.

#### FR-19: Work offline
**Week 14 (privacy by design) / 1 (availability)** · **Status: Implemented** · Evidence:
`test_offline_mode_makes_no_network_calls_but_local_ioc_works`, `test_no_keys_disables_keyed_providers`,
`test_offline_mode_health_and_lookup_use_local_data_only`, `test_offline_local_ioc_produces_exactly_one_enrichment`.
- Offline Mode makes zero network calls; the Local IOC list (`qa_demo/local_ioc.txt`) still flags
  `holiday_photo.jpg.exe`; missing keys disable only the keyed providers; health reports the
  providers in use.

#### FR-20: Fold Intel Verdicts into the Tier
**Week 11–13** · **Status: Implemented** · Evidence: `test_malicious_intel_forces_critical_even_if_known_good`,
`test_known_good_downgrades_entropy_only_alert_with_reason`, `test_known_good_does_not_downgrade_when_not_entropy_only`,
`test_known_good_never_downgrades_critical`, `test_suspicious_intel_lifts_safe_only`,
`test_known_good_corpus_hit_does_not_hide_a_malicious_verdict`, `test_known_good_entropy_only_alert_skips_vt_and_downgrades`,
`test_network_intel_escalates_row_and_moves_stats`.
- Malicious wins over Known-good; Known-good downgrades SUSPICIOUS to SAFE **only** when entropy was
  the sole reason, with the reason shown; counters and reports reflect the corrected Tier.

#### FR-21: Cache the latest-malware feed
**Week 2 (attack taxonomy / threat intelligence)** · **Status: Implemented** · Evidence:
`test_recent_feed_refresh_feeds_local_ioc`, `test_refresh_recent_is_noop_offline`.
- MalwareBazaar `get_recent` (selector=time) refreshed every 10 minutes into the local cache and
  used by the Local IOC provider; `GET /api/intel/recent` serves it.

#### FR-22: Warm the intel cache before a demo
**Week: cross-cutting (demonstration aid)** · **Status: Implemented** · Evidence:
`test_warm_cache_then_live_pipeline_makes_zero_network_calls`, `test_warm_cache_second_run_is_all_cache`,
`test_warm_cache_refuses_offline_mode_and_missing_drive`, `test_cli_warm_cache_reports_clean_errors_instead_of_tracebacks`.
- `python -m app warm_cache` performs the same lookups the live pipeline does; a second run makes
  no hash lookups. Live run measured: 96 s, 30 answers, 0 errors.

#### FR-23: Look up a hash manually
**Week 6 / 14** · **Status: Implemented** · Evidence: `test_intel_lookup_endpoint_eicar_malicious_from_both_providers`.
- `POST /api/intel/lookup` accepts a 64-hex SHA-256 only (422 otherwise); the Intel tab shows each
  Intel Verdict with a source link.

### 4.5 Realtime hub and dashboard *(owners M3, M4)*
**Description:** A WebSocket hub streams events to a React dashboard. Realizes UJ-1, UJ-2, UJ-4.

#### FR-24: Stream events with a SNAPSHOT first
**Week 1 (availability / integrity of the live view)** · **Status: Implemented** · Evidence:
`test_websocket_snapshot_first_then_simulate`, `test_reconnect_snapshot_repopulates_without_duplicates`,
`test_pydantic_models_match_telemetry_ts_field_for_field`, `test_file_scanned_contract_example_fields`.
- First message is `SNAPSHOT` (last 500 events, stats, active Drives); per-client queues (2000)
  so a slow client is dropped without stalling others; heartbeat every 15 s.
- Pydantic models and `telemetry.ts` match field-for-field (contract test).

#### FR-25: Serve health, stats and history
**Week 1** · **Status: Implemented** · Evidence: `test_health_and_empty_state`, `test_cors_allows_vite_origin`.
- `GET /api/health` (status, YARA rule count, providers in use, WebSocket clients), `/api/stats`,
  `/api/history`.

#### FR-26: Show the Live tab
**Week 2 / 11–13** · **Status: Implemented** [ASSUMPTION: UI behaviour is "Implemented" on the strength of the strict build and manual click-throughs, not automated browser tests] · Evidence: UI build (strict TypeScript) and the
fresh-clone click-through.
- Animated counters, entropy scatter with a dashed 7.2 line, 5×5 risk matrix, terminal-style scan
  queue, filterable/searchable threat log, CRITICAL banner, scan-complete toast (both auto-expire).

#### FR-27: Explain a File Result in a forensic drawer
**Week 2 / 6** · **Status: Implemented** · Evidence: UI build; fresh-clone click-through.
- Full SHA-256 with copy, legacy hashes, magic hex vs claimed extension, entropy + chi-square with a
  plain-language note, YARA hits, Authenticode, XOR key, MITRE links, Intel Verdicts, chain index
  and hash.

#### FR-28: Survive reconnects without freezing
**Week 1 (availability)** · **Status: Implemented** · Evidence: UI build; manual.
- Reconnect with exponential back-off and jitter; events batched per animation frame;
  de-duplicated by `event_id`.

#### FR-29: Show the Course Map in an About tab
**Week 1** · **Status: Implemented** · Evidence: `test_every_course_row_file_exists`,
`test_course_map_covers_the_weeks_in_the_spec_and_is_honest_about_gaps`, `test_course_map_endpoint_and_file_allowlist`.
- 12 rows (weeks 1–8, 10, 11–13, 14, 15) with C/I/A tags, status and file links served read-only
  from a strict allowlist (traversal and `.env` return 404).

### 4.6 Audit chain *(owner M3)*
**Description:** Every File Result is chained so tampering is evident. Realizes UJ-4.

#### FR-30: Chain every File Result and verify on demand
**Week 6** · **Status: Implemented** · Evidence: `test_every_scanned_file_gets_a_sequential_chain_index_and_verifies`,
`test_chain_verifies_and_links_hashes`, `test_deleted_record_is_detected`,
`test_recomputing_hashes_without_the_secret_is_still_caught`.
- `chain_hash = SHA-256(prev ‖ canonical_json(event))` plus HMAC-SHA-256; `GET /api/audit/verify`
  returns `valid`, `length`, `broken_at`.

#### FR-31: Demonstrate and undo tampering live
**Week 6** · **Status: Implemented** · Evidence: `test_tamper_breaks_chain_live_over_websocket_then_undo_repairs`,
`test_tamper_reports_the_broken_index_and_undo_repairs`, `test_tamper_needs_data_and_demo_mode`.
- `POST /api/demo/tamper` edits one stored record; `AUDIT_STATUS` turns the badge to
  "BROKEN at #n" in every client; undo restores. Both require demo mode.

#### FR-32: Persist the chain across restarts
**Week 6** · **Status: Implemented** · Evidence: `test_chain_persists_across_restarts_and_rejects_empty_secret`.
- SQLite store; a different secret cannot vouch for the log; empty secret rejected (a random one is
  generated into `data/hmac.secret` if none is configured).

### 4.7 Keys and signed reports *(owner M3)*
**Description:** Scan results can be signed and verified without the Station. Realizes UJ-3, UJ-4.

#### FR-33: Hold three Station Keys with self-signed certificates
**Week 5 / 8** · **Status: Implemented** · Evidence: `test_key_sizes_certificates_and_persistence`.
- RSA-3072, DSA-3072, Ed25519; each with a self-signed X.509 certificate (365 days); key files
  mode 0600; loaded again after restart.

#### FR-34: Sign and verify a report
**Week 7** · **Status: Implemented** · Evidence: `test_sign_then_verify_passes`, `test_one_flipped_byte_in_report_fails`,
`test_canonical_form_is_key_order_independent_and_compact`, `test_sign_report_endpoint_then_verify_and_tamper_detection`,
`test_report_errors_and_foreign_key_is_not_station_key`, `test_verify_never_raises_on_garbage_and_rejects_mismatched_key`.
- Canonical JSON (sorted keys, no whitespace) signed with RSA-PSS (default, SHA-256, salt 32),
  DSA or Ed25519; `POST /api/reports/verify` reports `valid` and whether the key is the Station's.

#### FR-35: Verify offline and pin the key
**Week 7 / 8** · **Status: Implemented** · Evidence: `test_offline_script_verifies_and_detects_tampering`,
`test_offline_script_fingerprint_pinning_and_usage_errors`, `test_openssl_cli_verifies_the_same_rsa_pss_and_ed25519_signatures`.
- `scripts/verify_report.py` needs only `cryptography`; exit 0 valid / 1 invalid / 2 usage;
  `--fingerprint` pins the key; `--export` produces files for `openssl dgst`.

#### FR-36: Redact filenames in reports
**Week 14** · **Status: Partial** · Evidence: `test_redaction_mode_hides_names_and_paths_in_reports`.
- `AEGIS_REDACT_FILENAMES=true` replaces names with `redacted-<8 hash chars>.<ext>` and drops
  paths **in Signed Reports only**; the dashboard and audit records still show real names.

### 4.8 Quarantine Vault *(owner M1)*
**Description:** Flagged files are copied, encrypted, into the Vault; the original is never touched
unless the Operator asks. Realizes UJ-3.

#### FR-37: Encrypt flagged files with AES-256-GCM
**Week 3** · **Status: Implemented** · Evidence: `test_vault_roundtrip_same_sha256_original_untouched_ciphertext_opaque`,
`test_vault_uses_fresh_salt_and_nonce_each_time`, `test_vault_guards`.
- scrypt (N = 2¹⁵, r = 8, p = 1) key per blob from `AEGIS_VAULT_PASSPHRASE` and a fresh 16-byte
  salt; fresh 96-bit nonce; SHA-256 bound as associated data; blob `"AEGQ1" | salt | nonce | ct+tag`;
  no passphrase → 503; 256 MB cap; ids validated against path traversal.

#### FR-38: Restore with integrity re-check
**Week 3 / 6** · **Status: Implemented** · Evidence: `test_vault_wrong_passphrase_fails_cleanly`,
`test_vault_detects_tampered_blob_and_metadata`, `test_quarantine_restore_flow_keeps_original_and_protects_demo_drive`.
- Restore decrypts into `data/restored/` (never back to the Drive), re-hashes, and fails cleanly
  on a wrong passphrase or altered data.

#### FR-39: Delete an original only on explicit request
**Week 1 (integrity vs availability)** · **Status: Implemented** · Evidence:
`test_delete_original_works_for_a_real_drive_only_after_quarantine`, `test_quarantine_input_validation_and_missing_passphrase`.
- Quarantine copies; "delete original" is a separate action, refused for the Simulated Drive, and
  refused if the file changed since quarantine.

#### FR-40: Refuse legacy ciphers
**Week 4** · **Status: Implemented** · Evidence: `test_legacy_ciphers_are_refused`, `test_unknown_cipher_refused_and_default_ok`.
- `AEGIS_VAULT_CIPHER` set to DES, 3DES, RC4, Blowfish (and aliases) stops start-up with a reason;
  only `aes-256-gcm` exists.

#### FR-41: Provide measured demonstrations for Weeks 4 and 6
**Week 4 / 6** · **Status: Implemented** · Evidence: `scripts/bench_ciphers.py`, `scripts/avalanche_demo.py`;
numbers quoted in `docs/CRYPTO_DESIGN.md` (AES-256-GCM ≈ 200× faster than 3DES-CBC on the build
machine [ASSUMPTION: one Apple-silicon Mac; varies by machine]; SHA-256 flips ≈ 128.5 of 256 bits per input-bit change).

### 4.9 Protecting the Station itself *(owner M3)*
**Description:** The API has no login, so access is narrowed instead. Realizes UJ-1.

#### FR-42: Refuse cross-site writes and WebSockets
**Week 15 (attack surfaces)** · **Status: Implemented** · Evidence:
`test_foreign_origin_cannot_trigger_state_changing_requests`, `test_foreign_origin_cannot_open_the_websocket`,
`test_extra_origins_can_be_allowed_by_config`, `test_cors_allows_vite_origin`.
- Server binds 127.0.0.1; CORS allow-list is `localhost:5173` and `127.0.0.1:5173` (+
  `AEGIS_EXTRA_ORIGINS`); POST/PUT/DELETE and WebSocket handshakes with a foreign `Origin` are
  refused (403 / close 1008); requests without `Origin` (curl, tests) pass.

#### FR-43: Never touch secrets or real services in tests
**Week 8** · **Status: Implemented** · Evidence: `qa_demo/conftest.py` (blanks keys, forces offline).
- Secrets only in git-ignored `backend/.env`; tests never use real services or keys.

### 4.10 Documentation and GRC *(owner M5)*
**Description:** Seven design documents, a runbook and the generated Course Map. Realizes UJ-2, UJ-4.

#### FR-44: Ship the design documents with references
**Week 1 / 10 / 11–13 / 14 / 15** · **Status: Implemented** · Evidence: `test_every_doc_has_references_with_access_date`,
`test_docs_do_not_contain_unfinished_markers`.
- `RESEARCH`, `THREAT_MODEL`, `CRYPTO_DESIGN`, `RISK_REGISTER`, `PRIVACY`, `VIVA_QA` (exactly 25
  questions), `COURSE_MAPPING`; each non-generated doc has a References section with URLs and an
  access date.

#### FR-45: Keep the Course Map and its doc in sync
**Week 1** · **Status: Implemented** · Evidence: `test_course_mapping_doc_is_generated_from_the_map`,
`test_every_course_row_file_exists`.
- `docs/COURSE_MAPPING.md` is generated from `course_map.py`; every linked file must exist.

#### FR-46: Record and treat risks
**Week 10 / 11–13** · **Status: Implemented** · Evidence: `docs/RISK_REGISTER.md` (14 risks, each
with likelihood, impact, score, treatment and owner; NIST CSF 2.0 and ISO/IEC 27001:2022 A.7.10,
A.8.7 mapping). No automated test beyond the documentation checks in FR-44.

#### FR-47: Purge the intel cache by age
**Week 14 (storage limitation)** · **Status: Partial** · Evidence: `IntelCache.purge` at start-up
(no dedicated test).
- Intel cache and recent-malware list older than `AEGIS_RETENTION_DAYS` (default 30) are purged at
  start; the audit log, enrichments and Vault are **not** auto-purged (FR-52).

### 4.11 Requirements from the original specification that are NOT built

#### FR-48: BadUSB keyboard-appearance alert
**Week 15** · **Status: Not built** · The stretch goal in `MASTER_PROMPT.md` (`hid_watch.py`).
AEGIS cannot see devices that pretend to be keyboards. Documented in `docs/THREAT_MODEL.md`.

#### FR-49: Dynamic analysis / sandbox
**Week 2** · **Status: Not built (explicitly out of scope in `MASTER_PROMPT.md` §4)**. Static
analysis only.

#### FR-50: Authenticode chain and digest validation
**Week 7** · **Status: Not built.** Presence and structure only (FR-12).

#### FR-51: Authentication on the local API
**Week 8** · **Status: Not built.** Mitigated by FR-42; other local processes can still call it.

#### FR-52: Retention for the audit log and Vault
**Week 14** · **Status: Not built.** Conflicts with tamper-evidence (see `docs/PRIVACY.md` §4).

#### FR-53: Validation on Windows/Linux hardware and on a 2–5 GB stick
**Week 1 (availability)** · **Status: Not built / not done** (the original hardening epic).

## 5. Non-Goals (Explicit)
- **Not an enforcement tool:** AEGIS reports; it cannot block the operating system mounting a
  drive.
- **Not a malware sandbox, nor a multi-engine local AV, nor a content-disarm tool.**
- **Not a device-trust tool:** HID/firmware attacks are out of scope (FR-48).
- **Not a multi-user or managed product:** no accounts, roles or central portal.
- **Never** executes, opens, imports, uploads or downloads samples; no real malware or real EICAR
  file is stored; demo payloads are inert.

## 6. MVP Scope

### 6.1 In Scope (built)
Drive monitoring and safe traversal; static analysis; deterministic Tiers and Risk Scores;
hash-only threat intel with offline mode; realtime dashboard (Live, Intel, Integrity, About);
Audit Chain; Station Keys and Signed Reports with offline verification; Quarantine Vault; the
documentation set; CI.

### 6.2 Out of Scope / not done
FR-48 to FR-53 (§4.11); presentation slides; PRD-level UX specification (the UI was built from
`MASTER_PROMPT.md` §7.4).

## 7. Success Metrics
*Each metric names the FRs it validates; all targets below were **met at the time of writing** [ASSUMPTION: "at the time of writing" means `main` on 2026-11-20].*

**Primary**
- **SM-1 Expected verdicts.** 12 of 12 demo files land in their expected Tier with exactly their
  expected YARA rule; counters read 3 / 2 / 7. Validates FR-6 to FR-15. *(Verified in tests and in a
  fresh-clone run.)*
- **SM-2 Tests pass everywhere.** 139 collected cases pass locally, in a fresh clone and in GitHub
  Actions; `ruff` clean; strict TypeScript build passes. Validates FR-24, FR-43.
- **SM-3 Integrity is demonstrable.** The chain verifies after a Scan and reports the exact edited
  index after tampering; Signed Reports verify with all three algorithms and fail after a one-digit
  change. Validates FR-30, FR-31, FR-34, FR-35.
- **SM-4 Course coverage.** 12 Course Map rows: 11 Implemented, 1 Partial (Week 15), 0 silently
  missing. Validates FR-29, FR-44, FR-45.

**Secondary**
- **SM-5 Privacy claim holds.** No outgoing request contains a filename or content. Validates FR-16.
- **SM-6 Demo readiness.** Warm-up completes in about 2 minutes and a second run makes no hash
  lookups. Validates FR-22.

**Counter-metrics (do not optimize)**
- **SM-C1 Do not tune thresholds to fit the demo.** Raising or lowering 7.2 or exemptions just to
  make the 12 files pass would trade away recall on real drives. Counterbalances SM-1.
- **SM-C2 Do not claim coverage that is not there.** A higher count of "Implemented" rows must
  never be bought by relaxing a gap's wording. Counterbalances SM-4.

## 8. Open Questions
1. Does real-stick detection work on Windows (the demo machine) and Linux? *(FR-1, FR-53)*
2. How does scan time scale on a 2–5 GB drive with many small files? *(FR-4, FR-53)*
3. Should the BadUSB alert be built, or documented only? *(FR-48)*
4. How should an erasure request interact with the Audit Chain? *(FR-52)*
5. Is a per-run API token worth adding on top of the Origin check? *(FR-51)*

## 9. Not built / known gaps (consolidated)
| Gap | Why it matters | Where recorded |
|---|---|---|
| No BadUSB/HID alert (FR-48) | Keyboard-emulating devices are invisible | THREAT_MODEL, RISK_REGISTER R2 |
| No sandbox (FR-49) | Zero-days can pass static checks | RISK_REGISTER R1 |
| Authenticode is presence-only (FR-12, FR-50) | "signed" is not "trusted" | COURSE_MAPPING Week 7 note |
| No API login (FR-51) | Other local processes can call it | RISK_REGISTER R3 |
| Retention purges the intel cache only (FR-47, FR-52) | Audit log and Vault persist | PRIVACY §4 |
| Real-stick, Windows/Linux and 2–5 GB validation not done (FR-1, FR-53) | Platform claims are unit-tested only | this PRD §4.1, §8 |
| Self-signed certificates add no trust (FR-33) | Trust needs an out-of-band fingerprint | CRYPTO_DESIGN §5 |
| Audit-log tail deletion undetectable by the chain (FR-30) | Chain is evident, not proof | CRYPTO_DESIGN §4, R12 |
| UI is not covered by automated browser tests (FR-26–28) | Verified by build and manual run | this PRD |

## 10. Cross-Cutting Non-Functional Requirements
*Bounds, not adjectives; each with its evidence.*

- **NFR-1 Quality gates.** 139 test cases (106 functions) pass; `ruff` clean; strict TypeScript
  build; GitHub Actions runs lint, tests and build on every push and pull request.
- **NFR-2 Throughput bounds.** 64 KB chunks; 50 MB default size cap; scan work window of 4 ×
  workers (default 4 workers); YARA timeout 10 s. Measured: 12 demo files scan in about 0.1 s.
  *No measurement on large drives (§9).*
- **NFR-3 Bounded memory/queues.** History ring 500 events; per-client queue 2000; heartbeat
  15 s; Vault file cap 256 MB.
- **NFR-4 Provider limits.** VirusTotal 4 requests/minute and 500/day; cache TTL 24 h found / 1 h
  not found; recent feed refresh every 10 minutes.
- **NFR-5 Safety.** Files are read-only bytes: never executed, opened with OS handlers or imported;
  quarantine copies; restore never writes back to a Drive.
- **NFR-6 Confidentiality.** Secrets only in `backend/.env` (git-ignored; committed history scanned
  for secret values before each commit); keys mode 0600; Vault AES-256-GCM.
- **NFR-7 Privacy.** Hash-only lookups; Offline Mode; no personal data collected directly.
- **NFR-8 Portability.** Python 3.11–3.13 (3.14 unsupported: no `yara-python` wheel); Node 20+;
  verified on macOS; Windows/Linux logic tested with fakes only.
- **NFR-9 Maintainability.** Type hints, docstrings on public functions, key=value structured
  logging, a Pydantic ↔ TypeScript contract test.
- **NFR-10 Accessibility.** Roles, labels and keyboard-operable rows are present; **no audit was
  performed**, so no conformance level is claimed.

## 11. Constraints and Guardrails
- **Safety rules** (`CLAUDE.md`): never execute scanned files; hash-only intel; inert demo payloads;
  quarantine copies by default.
- **Privacy:** see FR-16, FR-19, FR-36, `docs/PRIVACY.md`.
- **Compliance:** GDPR principles and NIST CSF 2.0 / ISO 27001 alignment are *supported*, not
  certified (`docs/RISK_REGISTER.md`).
- **Platform:** local web app: FastAPI (Python) + React/Vite/TypeScript/Tailwind v4; localhost only.

## 12. Assumptions Index
- [ASSUMPTION] §0 / §7: "at the time of writing" means the state of `main` on 2026-11-20 (merge
  commit plus the README and toast-fix commits).
- [ASSUMPTION] §2.3: all personas and the examiner are fictional illustrations of real use.
- [ASSUMPTION] FR-26–28: "Implemented" for UI behaviour rests on the strict build and manual
  click-throughs, not automated browser tests.
- [ASSUMPTION] FR-41: the 200× figure is from one Apple-silicon Mac and varies by machine.
