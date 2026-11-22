# Risk register and GRC mapping

*IS-353 Weeks 10–13. Score = **likelihood × impact**, each 1–5 (the same scale the dashboard's
risk matrix uses); bands: 1–4 low, 5–9 moderate, 10–14 high, 15–25 severe.*

Treatment follows the four standard options: **avoid** (stop doing the risky thing),
**mitigate** (reduce likelihood or impact), **transfer** (let someone else carry it), **accept**
(knowingly live with it). "Owner" is the team role (M1 backend/OS, M2 detection/intel, M3
API/crypto, M4 frontend, M5 QA/docs).

## 1. Register

| ID | Risk | L | I | Score | Treatment | What we did / will do | Owner |
|---|---|---|---|---|---|---|---|
| R1 | A zero-day or heavily obfuscated sample passes the static checks | 4 | 5 | **20** | Mitigate + accept residual | Layered signals (entropy, magic, YARA, XOR) plus hash intel. No sandbox: stated openly. | M2 |
| R2 | A drive-by BadUSB device (keyboard/firmware) is not detected | 3 | 5 | **15** | Accept (compensate outside the tool) | Out of scope; documented. Operating-system device-class allow-listing is the real control. Alert unbuilt. | M1 |
| R3 | Anyone on the PC, or a foreign web page, calls the unauthenticated local API | 3 | 4 | **12** | Mitigate | Bind to 127.0.0.1, CORS allow-list, refuse foreign `Origin` on writes and WebSocket (tested). Residual: other local processes. | M3 |
| R4 | A file changes between scan and use (time-of-check/time-of-use) | 3 | 4 | **12** | Mitigate | Hash recorded at scan; quarantine and delete-original re-check it and refuse on mismatch. | M2 |
| R5 | Evading name/header checks (polyglot files, valid header with payload behind it) | 3 | 4 | **12** | Mitigate | Several independent checks; YARA content rules; intel by hash. | M2 |
| R6 | Station signing key stolen (keys are unencrypted files) | 2 | 5 | **10** | Mitigate; transfer long-term | File mode 0600; regenerate keys to rotate; HSM/KMS recommended for production. | M3 |
| R7 | A parser bug (PE, YARA) is exploited by a hostile file | 2 | 5 | **10** | Mitigate + accept residual | Never execute; read-only bytes; size cap; 10 s YARA timeout; run as an ordinary user; keep libraries updated. | M1 |
| R8 | Vault passphrase is weak, default (`change-me`) or lost | 3 | 3 | **9** | Mitigate | Vault refuses to run with no passphrase; scrypt slows guessing; runbook says to set a real one. | M1 |
| R9 | Threat-intel quota exhausted or provider down at demo time | 4 | 2 | **8** | Mitigate | Cache, 4/min limiter, daily counter, offline local IOC list, `warm_cache` before class. | M2 |
| R10 | Operator opens or runs a restored quarantined file | 2 | 4 | **8** | Mitigate | Restore writes to a separate `data/restored/` folder, never back to the drive; never auto-opened; docs warn. | M1 |
| R11 | False positives on compressed or packed legitimate files | 3 | 2 | **6** | Mitigate + accept residual | Magic-aware entropy exemption; known-good (NSRL) downgrade for entropy-only alerts, with the reason shown. | M2 |
| R12 | Newest audit records deleted without the chain noticing | 2 | 3 | **6** | Accept (documented) | Signed reports carry the last index/hash as an outside witness; external anchoring is future work. | M3 |
| R13 | Windows Defender quarantines the demo payloads, or the demo network fails | 3 | 2 | **6** | Mitigate | Defender folder exclusion for `qa_demo/`; offline mode and `warm_cache` rehearsed. | M5 |
| R14 | Hash lookups reveal that a file exists to third parties | 2 | 2 | **4** | Avoid (offline mode) / accept | `AEGIS_INTEL_OFFLINE=true` stops all network lookups; otherwise only hashes are sent. | M5 |

## 2. Residual-risk summary by tier

* **Severe (R1, R2):** inherent to a static, file-only scanner. We accept them and say so in
  the presentation rather than overclaim.
* **High (R3–R7):** mitigated with tested controls; the remaining exposure is local-privilege
  related and sits behind the stated assumptions in `THREAT_MODEL.md`.
* **Low/moderate:** operational; handled by the runbook.

## 3. GRC mapping (Week 10)

*We say "supports", not "complies with": this is a student project, not a certified system.*

**NIST Cybersecurity Framework 2.0** [1] (six functions):

| Function | How AEGIS USB supports it |
|---|---|
| **Govern** | Written scope, threat model, this register, named owners, safety rules in `CLAUDE.md` |
| **Identify** | Inventory of removable media as it appears; risk scoring of each file; ATT&CK tagging |
| **Protect** | Encrypted quarantine, signed records, hash-only lookups, refusal of legacy ciphers, Origin checks |
| **Detect** | Real-time drive detection and static analysis; threat-intel enrichment |
| **Respond** | Alerts (banner, toast), quarantine, signed evidence report |
| **Recover** | Restore from the vault with SHA-256 re-verification; tamper evidence tells you *which* record to distrust |

**ISO/IEC 27001:2022 Annex A** [2]:

* **A 7.10 Storage media:** screening before use; encrypted copy of flagged media content; the
  audit trail of what was scanned.
* **A 8.7 Protection against malware:** detection, quarantine, and user awareness through
  plain-language reasons on every verdict.

## References

All accessed **2026-11-19**.

1. NIST, *Cybersecurity Framework (CSF) 2.0* — https://www.nist.gov/cyberframework
2. ISO, *ISO/IEC 27001:2022 Information security management systems* — https://www.iso.org/standard/27001
3. MITRE ATT&CK (technique IDs used in findings) — https://attack.mitre.org/techniques/T1091/
4. NIST National Software Reference Library (known-good hash corpus behind the false-positive downgrade) — https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
5. CIRCL hashlookup service — https://www.circl.lu/services/hashlookup/
6. CISA, "Using Caution with USB Drives" — https://www.cisa.gov/news-events/news/using-caution-usb-drives
