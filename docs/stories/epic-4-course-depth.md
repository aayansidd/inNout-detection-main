---
epic: 4
title: "Course-depth features"
status: "In progress (as built): 11 Done, 2 Partial, 2 Backlog"
updated: 2026-11-20
---

# Epic 4: Course-depth features

Verdicts are enriched by threat intel and backed by verifiable evidence: signed reports, a tamper-evident log and an encrypted vault.

**Status:** In progress (as built): 11 Done, 2 Partial, 2 Backlog  
**FRs covered:** FR-12, FR-15, FR-16, FR-17, FR-18, FR-19, FR-20, FR-21, FR-23, FR-30, FR-31, FR-32, FR-33, FR-34, FR-35, FR-36, FR-37, FR-38, FR-39, FR-40, FR-41, FR-48, FR-50  
**Stories:** 15 · **Owners:** M1, M2, M3, M4  
**Inputs:** [`prd.md`](../prd.md) · [`architecture.md`](../architecture.md) · [index](README.md)

*Brownfield, as-built:* these stories record work that exists. **Done** means every acceptance criterion is met and has a cited test or a named artifact; **Partial** means the built part is verified and a criterion is open; **Backlog** and **Won't do** were not built.

---

### Story 4.1: Authenticode presence check

As an operator,  
I want to know whether a PE file carries a certificate table,  
So that unsigned executables add risk.

**Status:** Partial · **Owner:** M2 · **Covers:** FR-12 · **Course week:** 7 · **Architecture:** AD-9

**Acceptance Criteria:**

**Given** PE files that are unsigned, signed, malformed or garbage  
**When** the check runs  
**Then** results are `unsigned`, `signed`, `invalid` and `invalid`  
*Verified by:* `test_authenticode_states`

**⚠ Not met** · **Given** a signed PE  
**When** the check runs  
**Then** the certificate chain and file digest are validated  
*Verified by:* NOT DONE: presence and structure only; tracked in Story 4.15

---

### Story 4.2: Hash-only threat-intel providers

As an operator,  
I want files checked against MalwareBazaar, VirusTotal, CIRCL and a local list using only their hash,  
So that I get live verdicts without sending file contents anywhere.

**Status:** Done · **Owner:** M2 · **Covers:** FR-16, FR-17 · **Course week:** 14, 8 · **Architecture:** AD-8

**Acceptance Criteria:**

**Given** a MalwareBazaar lookup  
**When** the request is sent  
**Then** its body is only `query` and `hash`, with the key in a header  
*Verified by:* `test_malwarebazaar_malicious_sends_hash_only`

**Given** MalwareBazaar answers not found or a bad status  
**When** the lookup finishes  
**Then** the verdict is `not_found` or `error` and the key never appears in the message  
*Verified by:* `test_malwarebazaar_not_found_and_bad_status`

**Given** VirusTotal returns 60, 3, 1, 0 detections  
**When** verdicts are derived  
**Then** they are malicious, malicious, suspicious and clean as defined  
*Verified by:* `test_virustotal_thresholds`

**Given** an enrichment is produced  
**When** it is persisted to the audit database  
**Then** the SQLite write runs in a worker thread, never on the event loop  
*Verified by:* `test_enrichment_is_saved_off_the_event_loop`

**Given** CIRCL returns a trusted or a low-trust record  
**When** the lookup finishes  
**Then** trusted is `known_good`, low trust is `not_found`  
*Verified by:* `test_circl_known_good_and_low_trust`

**Given** a SAFE text file  
**When** enrichment runs  
**Then** nothing is sent to the network; only non-SAFE files, executables and scripts are worth a lookup  
*Verified by:* `test_safe_text_file_is_never_sent_to_the_network`, `test_worth_network_lookup_gating`

**Given** the backend source  
**When** the guard test scans it  
**Then** no disabled certificate checking and no sample-download call exist  
*Verified by:* `test_source_never_disables_tls_verification_or_downloads_samples`

---

### Story 4.3: Rate limits, cache and offline mode

As an operator,  
I want intel to respect provider limits and keep working without the Internet,  
So that quota or network trouble never stops a scan.

**Status:** Done · **Owner:** M2 · **Covers:** FR-18, FR-19 · **Course week:** 11-13, 14, 1 · **Architecture:** AD-8, AD-14

**Acceptance Criteria:**

**Given** HTTP 429  
**When** a lookup retries  
**Then** Retry-After is honoured, else 1 s, 2 s, 4 s; persistent 429 becomes an `error` verdict and is not cached  
*Verified by:* `test_429_triggers_exponential_backoff_then_succeeds`, `test_persistent_429_becomes_error_not_crash`

**Given** the VirusTotal bucket and daily counter  
**When** requests are made  
**Then** the rate is 4/min; exhausted quota is skipped; low quota is reserved for flagged files  
*Verified by:* `test_token_bucket_limits_rate_with_fake_clock`, `test_vt_daily_quota_exhausted_is_skipped`, `test_low_quota_reserves_vt_for_flagged_files`

**Given** a hash already looked up  
**When** it is looked up again  
**Then** no network call is made  
*Verified by:* `test_cache_hit_avoids_network_call`

**Given** offline mode  
**When** files are enriched  
**Then** no network call is made, the local IOC list still flags its hash and exactly one enrichment appears  
*Verified by:* `test_offline_mode_makes_no_network_calls_but_local_ioc_works`, `test_offline_local_ioc_produces_exactly_one_enrichment`, `test_offline_mode_health_and_lookup_use_local_data_only`

**Given** keys are missing or the network fails  
**When** a lookup runs  
**Then** keyed providers are disabled and failures become `error` verdicts  
*Verified by:* `test_no_keys_disables_keyed_providers`, `test_network_failure_becomes_error_verdict`

---

### Story 4.4: Intel verdicts change the Tier

As an operator,  
I want threat intel to raise or lower a file's Tier with the reason shown,  
So that a known-bad hash is CRITICAL and a known-good file stops raising false alarms.

**Status:** Done · **Owner:** M2 · **Covers:** FR-20 · **Course week:** 11-13 · **Architecture:** AD-7, AD-8

**Acceptance Criteria:**

**Given** any malicious verdict  
**When** intel is applied  
**Then** the Tier is CRITICAL (5 × 5), even if CIRCL says known-good  
*Verified by:* `test_malicious_intel_forces_critical_even_if_known_good`, `test_known_good_corpus_hit_does_not_hide_a_malicious_verdict`

**Given** an entropy-only SUSPICIOUS file that is known-good  
**When** intel is applied  
**Then** it becomes SAFE with a "Downgraded" reason and the paid providers are not queried  
*Verified by:* `test_known_good_downgrades_entropy_only_alert_with_reason`, `test_known_good_entropy_only_alert_skips_vt_and_downgrades`, `test_known_good_stops_before_paid_providers`

**Given** a script, an RTLO name or a CRITICAL file  
**When** a known-good verdict arrives  
**Then** the Tier is never lowered  
*Verified by:* `test_known_good_does_not_downgrade_when_not_entropy_only`, `test_known_good_never_downgrades_critical`

**Given** suspicious intel  
**When** it is applied  
**Then** only a SAFE file is lifted to SUSPICIOUS  
*Verified by:* `test_suspicious_intel_lifts_safe_only`

**Given** MalwareBazaar flags the hash of `backup_archive.bin`  
**When** the scan completes  
**Then** its row becomes CRITICAL (risk 25) and the counters move from 3/2/7 to 3/1/8, also after a refresh  
*Verified by:* `test_network_intel_escalates_row_and_moves_stats`

---

### Story 4.5: Latest-malware feed and manual hash lookup

As an operator,  
I want a recent-malware list and a box to look up any SHA-256,  
So that I can check a hash myself and keep a fresh offline list.

**Status:** Done · **Owner:** M2 · **Covers:** FR-21, FR-23 · **Course week:** 2, 6, 14 · **Architecture:** AD-8

**Acceptance Criteria:**

**Given** MalwareBazaar `get_recent`  
**When** the feed refreshes  
**Then** samples are cached and the local provider flags a matching hash; offline it does nothing  
*Verified by:* `test_recent_feed_refresh_feeds_local_ioc`, `test_refresh_recent_is_noop_offline`

**Given** the EICAR SHA-256  
**When** `POST /api/intel/lookup` is called with providers answering malicious  
**Then** the response is malicious and a non-hash input returns 422  
*Verified by:* `test_intel_lookup_endpoint_eicar_malicious_from_both_providers`

**Given** the live EICAR lookup  
**When** it was run with real keys  
**Then** VirusTotal said malicious, CIRCL known-good and MalwareBazaar not found; malicious wins  
*Verified by:* recorded live check: PR #1 description

---

### Story 4.6: Risk matrix and score in the dashboard

As an operator,  
I want a 5 × 5 likelihood × impact heatmap,  
So that I can see where the risk sits.

**Status:** Done · **Owner:** M4 · **Covers:** FR-15 · **Course week:** 11-13 · **Architecture:** AD-7, AD-15

**Acceptance Criteria:**

**Given** the demo scan  
**When** the matrix is shown  
**Then** files sit at 1×2 (3), 3×3 (2), 4×5 (5) and 5×5 (2)  
*Verified by:* manual: click-through, artifact: docs/images/dashboard.jpg

**Given** a file  
**When** its score is computed  
**Then** `risk_score = likelihood × impact`  
*Verified by:* `test_invoice_matches_contract_example`

---

### Story 4.7: Tamper-evident audit chain

As an examiner,  
I want every scan result chained and verifiable, with a live tamper demonstration,  
So that I can see that stored evidence cannot be altered unnoticed.

**Status:** Done · **Owner:** M3 · **Covers:** FR-30, FR-31, FR-32 · **Course week:** 6 · **Architecture:** AD-5, AD-6, AD-14

**Acceptance Criteria:**

**Given** a finished scan  
**When** `/api/audit/verify` is called  
**Then** every file has a sequential index and a 64-hex hash and the chain verifies  
*Verified by:* `test_every_scanned_file_gets_a_sequential_chain_index_and_verifies`, `test_chain_verifies_and_links_hashes`

**Given** one stored record is edited  
**When** verification runs  
**Then** it fails at exactly that index and an `AUDIT_STATUS` event reaches clients; undo repairs it  
*Verified by:* `test_tamper_breaks_chain_live_over_websocket_then_undo_repairs`, `test_tamper_reports_the_broken_index_and_undo_repairs`

**Given** a record is deleted, or hashes are recomputed without the secret  
**When** verification runs  
**Then** both are detected  
*Verified by:* `test_deleted_record_is_detected`, `test_recomputing_hashes_without_the_secret_is_still_caught`

**Given** the server restarts  
**When** the chain is opened  
**Then** it continues and verifies; a different secret cannot vouch for it; an empty secret is rejected  
*Verified by:* `test_chain_persists_across_restarts_and_rejects_empty_secret`

**Given** nothing is scanned yet, or demo mode is off  
**When** tamper is requested  
**Then** 409 or 403  
*Verified by:* `test_tamper_needs_data_and_demo_mode`

---

### Story 4.8: Station keys and signed reports

As an operator,  
I want to sign a scan's report with RSA-PSS, DSA or Ed25519,  
So that another person can trust the report was not changed.

**Status:** Done · **Owner:** M3 · **Covers:** FR-33, FR-34 · **Course week:** 5, 7, 8 · **Architecture:** AD-10, AD-14

**Acceptance Criteria:**

**Given** the keystore  
**When** keys are requested  
**Then** RSA-3072, DSA-3072 and Ed25519 exist with self-signed certificates, file mode 0600, and reload after restart  
*Verified by:* `test_key_sizes_certificates_and_persistence`

**Given** a report signed with each algorithm  
**When** it is verified  
**Then** it is valid; one changed report byte makes it invalid  
*Verified by:* `test_sign_then_verify_passes`, `test_one_flipped_byte_in_report_fails`

**Given** the same data in a different key order  
**When** it is canonicalised  
**Then** the signed bytes are identical and compact  
*Verified by:* `test_canonical_form_is_key_order_independent_and_compact`

**Given** the API  
**When** a scan is signed and verified  
**Then** `/api/reports/{id}/sign` and `/verify` work for all three algorithms and detect tampering  
*Verified by:* `test_sign_report_endpoint_then_verify_and_tamper_detection`

**Given** a scan whose file intel later escalated from SUSPICIOUS to CRITICAL  
**When** the report is signed  
**Then** each file's `tier`, scores, `mitre`, `reasons`, `chain_index` and `chain_hash` equal the audit-chain record, and the intel result appears separately as `final_tier` / `final_risk_score` / `final_reasons` (summary counts by chained tier, with `summary.final` by final tier)  
*Verified by:* `test_signed_report_matches_the_chained_record_even_after_enrichment`, `test_network_intel_escalates_row_and_moves_stats`

**Given** garbage input or a foreign key  
**When** verification runs  
**Then** it never raises, mismatched key types are rejected and a foreign key is valid but not the Station's  
*Verified by:* `test_verify_never_raises_on_garbage_and_rejects_mismatched_key`, `test_report_errors_and_foreign_key_is_not_station_key`

---

### Story 4.9: Offline verification and key pinning

As an examiner,  
I want a verifier that runs without the server,  
So that I can check a report independently.

**Status:** Done · **Owner:** M3 · **Covers:** FR-35 · **Course week:** 7, 8 · **Architecture:** AD-10

**Acceptance Criteria:**

**Given** a signed report file  
**When** `verify_report.py` runs in a separate process  
**Then** it exits 0 when valid and 1 when the report was altered, for all three algorithms  
*Verified by:* `test_offline_script_verifies_and_detects_tampering`

**Given** `--fingerprint`  
**When** it is pinned to the right and a wrong value  
**Then** a match passes, a mismatch exits 1 and a missing file exits 2  
*Verified by:* `test_offline_script_fingerprint_pinning_and_usage_errors`

**Given** the exported files  
**When** the `openssl` CLI verifies them  
**Then** RSA-PSS and Ed25519 signatures verify  
*Verified by:* `test_openssl_cli_verifies_the_same_rsa_pss_and_ed25519_signatures`

---

### Story 4.10: Filename redaction in signed reports

As an operator,  
I want to hide filenames when I share a signed report,  
So that the report does not leak what was on the drive.

**Status:** Partial · **Owner:** M3 · **Covers:** FR-36 · **Course week:** 14 · **Architecture:** AD-10

**Acceptance Criteria:**

**Given** `AEGIS_REDACT_FILENAMES=true`  
**When** a report is signed  
**Then** names become `redacted-<hash prefix>.<ext>` and paths are omitted  
*Verified by:* `test_redaction_mode_hides_names_and_paths_in_reports`

**⚠ Not met** · **Given** redaction is on  
**When** the dashboard or audit records are viewed  
**Then** names are redacted there too  
*Verified by:* NOT DONE: redaction covers Signed Reports only (see PRD FR-36)

---

### Story 4.11: AES-256-GCM quarantine vault

As an operator,  
I want to copy a flagged file into an encrypted vault and restore it with an integrity check,  
So that the evidence is kept safely and cannot run.

**Status:** Done · **Owner:** M1 · **Covers:** FR-37, FR-38, FR-39 · **Course week:** 3, 1 · **Architecture:** AD-11

**Acceptance Criteria:**

**Given** a file  
**When** it is quarantined  
**Then** an encrypted copy exists, the original is untouched and the ciphertext does not contain the plaintext  
*Verified by:* `test_vault_roundtrip_same_sha256_original_untouched_ciphertext_opaque`

**Given** two files with the same content  
**When** both are quarantined  
**Then** each gets a different salt, nonce and ciphertext  
*Verified by:* `test_vault_uses_fresh_salt_and_nonce_each_time`

**Given** a wrong passphrase, or an altered blob or metadata  
**When** restore is attempted  
**Then** it fails cleanly and writes nothing  
*Verified by:* `test_vault_wrong_passphrase_fails_cleanly`, `test_vault_detects_tampered_blob_and_metadata`

**Given** no passphrase, a path-traversal id, a changed file or a duplicate  
**When** quarantine runs  
**Then** each is refused with a clear error  
*Verified by:* `test_vault_guards`

**Given** the API  
**When** a file is quarantined, listed and restored  
**Then** the restore re-checks SHA-256 and the demo drive's original cannot be deleted  
*Verified by:* `test_quarantine_restore_flow_keeps_original_and_protects_demo_drive`

**Given** invalid ids or no passphrase  
**When** the endpoints are called  
**Then** 422, 404, 400 or 503 as appropriate  
*Verified by:* `test_quarantine_input_validation_and_missing_passphrase`

**Given** a real (non-simulated) drive entry  
**When** delete-original is requested  
**Then** a changed file is refused with 409; an unchanged one is deleted  
*Verified by:* `test_delete_original_works_for_a_real_drive_only_after_quarantine`

---

### Story 4.12: Refuse legacy ciphers and measure the alternative

As an examiner,  
I want DES and 3DES refused by configuration and a measured AES-versus-3DES comparison,  
So that the Week 4 argument is backed by code and numbers.

**Status:** Done · **Owner:** M1 · **Covers:** FR-40, FR-41 · **Course week:** 4, 6 · **Architecture:** AD-11, AD-13

**Acceptance Criteria:**

**Given** `AEGIS_VAULT_CIPHER` is DES, 3DES, RC4, Blowfish or an alias  
**When** settings load  
**Then** start-up is refused  
*Verified by:* `test_legacy_ciphers_are_refused`, `test_unknown_cipher_refused_and_default_ok`

**Given** `bench_ciphers.py` and `avalanche_demo.py`  
**When** they are run  
**Then** they print the AES/3DES and signature tables and the SHA-256 bit-change average, quoted in `docs/CRYPTO_DESIGN.md`  
*Verified by:* artifact: backend/scripts/bench_ciphers.py, artifact: backend/scripts/avalanche_demo.py, `test_avalanche_one_bit_changes_about_half_the_hash_bits`

---

### Story 4.13: Intel and Integrity panels

As an operator,  
I want panels for hash lookup, the audit chain, reports, vault and tamper demo,  
So that I can use the evidence features without a terminal.

**Status:** Done · **Owner:** M4 · **Covers:** FR-23, FR-30, FR-31, FR-34 · **Course week:** 6, 7, 14 · **Architecture:** AD-15

> UI half of FRs implemented server-side in Stories 4.5, 4.7 and 4.8.

**Acceptance Criteria:**

**Given** the Intel tab  
**When** it is opened  
**Then** provider chips, a lookup box, an EICAR shortcut and the latest-malware list are shown and "Intel: offline" appears with no network provider  
*Verified by:* manual: click-through

**Given** the Integrity tab  
**When** tamper and undo are clicked  
**Then** the badge reads "BROKEN at #n" then "verified", in the header too  
*Verified by:* manual: click-through (server behaviour tested in Story 4.7)

---

### Story 4.14: BadUSB keyboard-appearance alert

As an operator,  
I want an alert when a new keyboard (HID) appears together with a storage device,  
So that a keyboard-emulating device is not invisible.

**Status:** Backlog · **Owner:** M1 · **Covers:** FR-48 · **Course week:** 15 · **Architecture:** AD-18

**Acceptance Criteria:**

**⚠ Not met** · **Given** a keyboard appears with a storage device  
**When** the monitor polls  
**Then** a BadUSB alert is raised  
*Verified by:* NOT DONE: stretch goal `hid_watch.py` was never built (documented in THREAT_MODEL.md)

---

### Story 4.15: Authenticode chain and digest validation

As an operator,  
I want signed executables to be validated, not just detected,  
So that "signed" means something.

**Status:** Backlog · **Owner:** M2 · **Covers:** FR-50 · **Course week:** 7 · **Architecture:** AD-9

**Acceptance Criteria:**

**⚠ Not met** · **Given** a signed PE  
**When** it is analysed  
**Then** the certificate chain and digest are validated  
*Verified by:* NOT DONE: needs the optional `signify` package and a trust store

