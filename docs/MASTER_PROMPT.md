# AEGIS USB — Master Build Prompt (Claude Code + BMAD)

> **How to use this file**
> 1. Put this file in the repo root as `docs/MASTER_PROMPT.md`.
> 2. **With BMAD:** install BMAD (`npx bmad-method install`, choose Claude Code). Then use a fresh chat for each agent and point it at this file:
>    - **Analyst** → "Read docs/MASTER_PROMPT.md. Produce the Project Brief + docs/RESEARCH.md from §2 and §3."
>    - **PM** → "Produce the PRD from §4–§7. Every FR must cite the course week it demonstrates (§3)."
>    - **Architect** → "Produce docs/architecture.md from §5–§8. Keep the exact repo tree and contracts."
>    - **SM** → "Shard the PRD into stories using the epics in §11, one story per owner per sprint."
>    - **Dev** → "Implement story X.Y. Follow §8 standards. No TODOs, no stubs."
>    - **QA / Test Architect** → "Review story X.Y against §10 acceptance tests."
> 3. **Without BMAD:** paste the whole file into Claude Code and say: *"Build this in the order of §12. Stop after each phase, run tests, show me the result."*

---

## 1. Role & objective

Act as a **Principal Security Engineer and Full-Stack Architect**. Build **AEGIS USB** — a real-time USB malware detection, threat-intelligence and forensic-integrity system for our **IS-353 Information Security** course project (team of 5, NUST SEECS).

The project must show the examiner that we understood **the whole course**, not just one topic. Every major feature maps to a lecture week (§3), and the repo ships with design documents that justify each security decision with references (§9).

**One-line pitch:** *Plug in a drive. See the verdict — hashed, scored, checked against live threat intel, and cryptographically signed — before anyone opens a file.*

---

## 2. Problem & research context (use in docs/RESEARCH.md and the slides)

- USB removable media remains a primary initial-access vector, especially for air-gapped/OT networks. Honeywell's Industrial USB Threat Report (2022) found **52% of threats were specifically designed to use removable media** (up from 37% in 2021 and 19% in 2020); the 2024 edition reported 51%.
- Historic cases to cite: **Stuxnet** (2010, spread via USB using the Windows LNK flaw CVE-2010-2568), **Agent.btz / Operation Buckshot Yankee** (2008, US DoD), **Raspberry Robin** (2022, USB worm using malicious `.lnk` files).
- MITRE ATT&CK techniques we detect or reference:
  - T1091 Replication Through Removable Media
  - T1204.002 User Execution: Malicious File
  - T1036.007 Masquerading: Double File Extension
  - T1036.008 Masquerading: Masquerade File Type (magic-byte spoof)
  - T1027.002 Obfuscated Files: Software Packing (entropy / UPX)
  - T1059.001 Command and Scripting Interpreter: PowerShell
  - T1200 Hardware Additions (BadUSB / HID injection)
- Research must be **summarised in our own words with a references list** (URLs + access date). No copied paragraphs.

---

## 3. Course-to-feature map (generate as docs/COURSE_MAPPING.md, and show it in the UI's "About" tab)

| Week | Topic | Where it lives in AEGIS USB |
|---|---|---|
| 1 | Intro to InfoSec (CIA triad) | Every feature tagged C/I/A in docs; threat model scope |
| 2 | Attack taxonomy + classical crypto | MITRE/STRIDE tags on each detection; **single-byte XOR de-obfuscation** of hidden PE headers (classical cipher used by real malware); entropy explained as frequency analysis |
| 3 | Symmetric crypto | **AES-256-GCM quarantine vault** — flagged files are encrypted so they can't execute; key from scrypt/PBKDF2 |
| 4 | DES | docs/CRYPTO_DESIGN.md: why DES/3DES are rejected (56-bit key, 64-bit block / Sweet32); config refuses legacy ciphers; small benchmark table AES vs 3DES |
| 5 | Asymmetric crypto | RSA-3072 and DSA/ECDSA key generation in the keystore |
| 6 | Hash functions | Streaming **SHA-256** fingerprint; MD5/SHA-1 computed **only** for threat-intel compatibility (with collision warning: SHAttered 2017); **hash-chained tamper-evident audit log**; avalanche-effect demo |
| 7 | Digital signatures | **Signed scan reports** (RSA-PSS primary, DSA + Ed25519 for comparison); verify endpoint + offline verify script; **Authenticode presence check** on `.exe/.dll` (unsigned executable = extra risk) |
| 8 | Trust over the Internet | TLS-verified threat-intel calls (no `verify=False`), self-signed X.509 "AEGIS Scanner Station" cert for report keys, docs explaining CA chains & what changes in production |
| 10 | GRC | NIST CSF 2.0 mapping (Identify/Protect/Detect/Respond/Recover); ISO/IEC 27001:2022 Annex A 7.10 (storage media) & 8.7 (malware) |
| 11–13 | Risk lifecycle, assessment, analysis, mitigation | Numeric **risk score = likelihood × impact** with a 5×5 matrix in the UI; docs/RISK_REGISTER.md with treatment (avoid/mitigate/transfer/accept) per tier |
| 14 | Privacy & GDPR | Hash-only lookups (file contents never leave the machine) = data minimisation, Art. 5(1)(c); configurable retention; filename redaction mode; docs/PRIVACY.md |
| 15 | IoT security & attack surfaces | docs/THREAT_MODEL.md with USB attack-surface diagram (storage, HID, firmware); **BadUSB alert** when a new keyboard (HID) appears together with a storage device (stretch goal) |

---

## 4. Scope

**In scope:** live USB detection, static analysis, threat-intel enrichment, risk scoring, signed reports, tamper-evident logs, encrypted quarantine, SOC dashboard, safe demo payloads, tests, documentation.

**Out of scope:** dynamic analysis / sandboxing, executing any file, storing or downloading real malware samples, kernel drivers, blocking the OS mount itself.

**Hard safety rules (put these in CLAUDE.md):**
- Never execute, open with OS handlers, or import scanned files.
- Never download samples from MalwareBazaar/VirusTotal (`get_file` is forbidden). **Lookups are hash-only.**
- Demo payloads must be inert bytes. No real malware, no real EICAR file on disk (Defender will quarantine it). The EICAR hash may be *looked up* via the API to demo live intel.
- Quarantine **copies** into the vault by default; deleting the original requires an explicit user click.

---

## 5. Architecture

Two decoupled halves joined by a WebSocket bridge.

```
 USB drive ──► M1 usb_monitor (daemon thread, psutil poll 1s)
                 │ spawn per-drive job
                 ▼
             M1 walker (os.scandir, skip system dirs)
                 │ files → ThreadPoolExecutor
                 ▼
             M2 analyzer ── hasher · entropy+chi² · magic · XOR · YARA · Authenticode
                 │ ScanResult (FILE_SCANNED)          │ hash
                 ▼                                     ▼
             M3 event bus (asyncio.Queue via      M2 intel worker (async, rate-limited,
             call_soon_threadsafe)                 SQLite cache) → FILE_ENRICHED
                 │
                 ├─► M3 audit chain (SHA-256 hash chain + HMAC)
                 ├─► M3 history ring buffer (500) + stats
                 └─► WebSocket /ws ──► M4 React SOC dashboard
```

- **Backend:** Python 3.11+, FastAPI, Uvicorn, Pydantic v2, psutil, yara-python, `cryptography`, httpx, SQLite (stdlib), python-dotenv. Optional: `pefile` (PE parsing), `signify` (Authenticode).
- **Frontend:** React + Vite + TypeScript + **Tailwind CSS v4** (`@import "tailwindcss";`, `@tailwindcss/vite` plugin). Charts in hand-written SVG (no heavy chart lib). Vite dev proxy for `/api` and `/ws` → `localhost:8000`.

---

## 6. Repository structure & ownership

```text
aegis-usb/
├── CLAUDE.md                     # safety rules + conventions for Claude Code
├── backend/
│   ├── app/
│   │   ├── config.py             # env settings (AEGIS_* vars)
│   │   ├── core/                 # [M1 Backend & OS]
│   │   │   ├── usb_monitor.py    # psutil polling, mount diff, scan coordinator, cancel on removal
│   │   │   ├── walker.py         # safe traversal, size guard, progress counters
│   │   │   ├── vault.py          # AES-256-GCM quarantine (Week 3)
│   │   │   └── hid_watch.py      # BadUSB keyboard-appearance alert (stretch, Week 15)
│   │   ├── engine/               # [M2 Detection & Intel]
│   │   │   ├── analyzer.py       # orchestrates checks, risk score, tier
│   │   │   ├── hasher.py         # streaming SHA-256 (+MD5/SHA-1 for intel only)
│   │   │   ├── entropy.py        # Shannon entropy + chi-square uniformity
│   │   │   ├── magic_bytes.py    # header signatures, ext mismatch, double ext, RTLO char
│   │   │   ├── xor_detect.py     # single-byte XOR hidden-PE detection (Week 2)
│   │   │   ├── authenticode.py   # PE signature presence/validity (Week 7)
│   │   │   ├── yara_scanner.py   # compile once, externals filename/extension
│   │   │   └── intel/
│   │   │       ├── base.py       # Provider protocol + IntelVerdict model
│   │   │       ├── malwarebazaar.py
│   │   │       ├── virustotal.py
│   │   │       ├── hashlookup.py # CIRCL known-good (NSRL) lookups → false-positive reduction
│   │   │       ├── local_ioc.py  # offline IOC list (works with no internet)
│   │   │       └── cache.py      # SQLite cache + token-bucket rate limiter
│   │   ├── crypto/               # [M3 API, Integrity & Signatures]
│   │   │   ├── keystore.py       # generate/load RSA-3072, DSA-3072, Ed25519 keys + self-signed X.509
│   │   │   ├── signer.py         # sign/verify canonical JSON reports
│   │   │   └── audit_chain.py    # tamper-evident hash chain + HMAC
│   │   ├── api/                  # [M3]
│   │   │   ├── main.py           # lifespan, CORS (5173), startup/shutdown
│   │   │   ├── ws_manager.py     # per-client queues, heartbeat, snapshot on connect
│   │   │   ├── routes.py         # REST endpoints (§7)
│   │   │   └── schemas.py        # Pydantic v2 event + REST models
│   │   └── rules/usb_threats.yar
│   ├── scripts/verify_report.py  # offline signature verification (no server needed)
│   ├── requirements.txt
│   └── .env.example
├── frontend/                     # [M4 Frontend UI/UX]
│   └── src/
│       ├── types/telemetry.ts
│       ├── hooks/useAegisSocket.ts
│       ├── components/
│       │   ├── HeaderStatus.tsx      # LIVE dot, drive pills + progress, Simulate / Eject buttons
│       │   ├── ThreatCounters.tsx    # Total / Safe / Suspicious / Critical (animated)
│       │   ├── EntropyChart.tsx      # scatter 0–8, dashed red line at 7.2
│       │   ├── ScanQueueFeed.tsx     # terminal-style live feed
│       │   ├── ThreatLogTable.tsx    # filter + forensic drawer
│       │   ├── IntelPanel.tsx        # manual hash lookup + "latest malware" feed
│       │   ├── RiskMatrix.tsx        # 5×5 likelihood × impact heatmap
│       │   ├── AuditChainBadge.tsx   # "Chain verified ✓ / BROKEN at #n"
│       │   └── ReportPanel.tsx       # sign report (choose RSA-PSS/DSA/Ed25519), download, verify
│       ├── App.tsx
│       └── index.css
├── qa_demo/                      # [M5 QA, Payloads, Docs & GRC]
│   ├── generate_payloads.py
│   ├── test_engine.py
│   ├── test_crypto.py
│   ├── test_api.py
│   └── README.md                 # setup + demo runbook
└── docs/
    ├── MASTER_PROMPT.md  COURSE_MAPPING.md  RESEARCH.md  THREAT_MODEL.md
    ├── CRYPTO_DESIGN.md  RISK_REGISTER.md   PRIVACY.md   VIVA_QA.md
    └── architecture.md (BMAD)  prd.md (BMAD)  stories/ (BMAD)
```

**Ownership:** M1 OS + vault · M2 detection + intel · M3 API + crypto + audit · M4 frontend · M5 QA + docs + GRC. Modules talk only through the interfaces in §7 so each member can test alone.

---

## 7. Detailed specifications

### 7.1 M1 — OS monitor & traversal
- Poll `psutil.disk_partitions(all=False)` every 1 s in a daemon thread.
- Removable detection: Windows `'removable' in opts` (skip `cdrom`); Linux mounts under `/media`, `/run/media` **or** `/sys/block/<dev>/removable == 1` (do **not** treat `/mnt` as removable — WSL mounts `C:` there); macOS `/Volumes/*` except the system volume.
- On insert → `USB_CONNECTED` (drive, label, fs_type, total_bytes, simulated) and start a scan job. On removal → `USB_DISCONNECTED` and cancel the job via `threading.Event`; drop in-flight results.
- Walker: iterative `os.scandir`, never follow symlinks, catch `PermissionError`, skip `System Volume Information`, `$RECYCLE.BIN`, `.Trashes`, `.Spotlight-V100`, `.fseventsd`. Scan hidden files (malware hides). Emit throttled `SCAN_PROGRESS` (files_discovered, files_scanned, files_skipped).
- `MAX_SCAN_FILE_SIZE_MB` (default 50): larger files get **header + name checks only** and `scan_status: "PARTIAL"`.
- Vault: `POST /api/quarantine/{event_id}` copies the file, encrypts with **AES-256-GCM** (random 96-bit nonce, file SHA-256 as associated data), key derived with scrypt from `AEGIS_VAULT_PASSPHRASE`. Store `.aegisq` blob + JSON metadata. Restore endpoint decrypts and re-checks the hash (proves integrity + confidentiality together).

### 7.2 M2 — Detection engine
Read each file **once** in 64 KB chunks feeding the hasher and entropy accumulator together.

- **SHA-256** hex digest (primary ID). MD5/SHA-1 only stored for intel providers that need them, labelled "legacy, collision-prone".
- **Shannon entropy** `H = −Σ p(x) log2 p(x)` over 256 byte values (0.0–8.0). Flag > **7.2**. Also compute **chi-square** against a uniform distribution; show it in the drawer to separate *encrypted* (near-uniform) from *compressed* data.
- **False-positive control:** if the magic bytes say JPEG/PNG/ZIP/OOXML/PDF/MP4/7z/gzip **and** the extension agrees, high entropy is expected → don't escalate, add an explanatory reason.
- **Magic bytes** (first 16 bytes): MZ, ELF `7F 45 4C 46`, Mach-O (`FEEDFACE/FEEDFACF/CEFAEDFE/CFFAEDFE`), PDF, PNG, JPEG, GIF, ZIP, OLE, 7z, RAR, gzip, LNK. Executable header + benign extension (`.pdf .docx .xlsx .pptx .jpg .png .gif .txt .csv .mp3 .mp4`) ⇒ **extension_mismatch**. Also flag **double extensions** (`invoice.pdf.exe`) and the **Unicode RTLO** character (U+202E) in filenames.
- **XOR de-obfuscation:** brute-force single-byte keys 0x01–0xFF on the first 512 bytes; if the result starts with `MZ` and contains `This program cannot be run`, report "XOR-obfuscated PE (key 0x??)".
- **Authenticode:** for PE files, report signed / unsigned / invalid. Unsigned executable adds likelihood but does not alone make it CRITICAL.
- **YARA** (`rules/usb_threats.yar`, compiled once, externals `filename` + `extension`):
  - `Autorun_Inf_Abuse` — `[autorun]` with `open=` / `shellexecute=` / `shell\...\command=`
  - `Suspicious_PowerShell_Dropper` — `IEX`/`Invoke-Expression` + `DownloadString`/`DownloadFile`, or `-enc <base64>`
  - `Magic_Spoof_Executable` — exe header + benign extension (uses the `extension` external)
  - `UPX_Packed_Executable` — `UPX0`/`UPX1` section names in an MZ file
  - `Ransomware_Shadow_Delete` — `vssadmin delete shadows`, `bcdedit ... recoveryenabled no`
  - `Demo_EICAR_Signature` — custom harmless string `AEGIS-TEST-MALWARE-SIGNATURE-2026`
  - Scan with `filepath=` (memory-mapped), timeout 10 s.

- **Threat intel (hash-only, async, never blocks scanning):**
  - Order: local cache → local IOC list → **CIRCL hashlookup** (known-good) → **MalwareBazaar** `get_info` → **VirusTotal v3** `GET /api/v3/files/{sha256}`.
  - MalwareBazaar needs a free `Auth-Key` header (`POST https://mb-api.abuse.ch/api/v1/`, `query=get_info&hash=…`). VirusTotal public API is limited to **4 requests/min and 500/day** → token-bucket limiter, exponential backoff on 429, SQLite cache with TTL, and only look up EXE/script/CRITICAL/SUSPICIOUS files when quota is low.
  - "Latest malware" panel: MalwareBazaar `get_recent` (`selector=time`) refreshed every 10 min into the local IOC cache.
  - No API keys? The system still works offline and the UI shows "Intel: offline".
  - Results are sent as a separate `FILE_ENRICHED` event that updates the existing row.

- **Risk scoring (Weeks 11–13):**
  - `likelihood` 1–5 and `impact` 1–5 → `risk_score = likelihood × impact` (1–25), shown on the matrix.
  - Tier rules (deterministic, unit-tested):
    - **CRITICAL** — any YARA match, executable magic mismatch, double-extension/RTLO executable, XOR-hidden PE, or intel says malicious.
    - **SUSPICIOUS** — entropy > 7.2 (not exempt), script/autorun extension (`.vbs .js .ps1 .bat .cmd .scr .lnk .hta`), or unsigned executable plus high entropy.
    - **SAFE** — everything else; a known-good CIRCL/NSRL hit can downgrade an entropy-only SUSPICIOUS to SAFE (with the reason shown).
  - Every result carries human-readable `reasons[]` and `mitre[]` technique IDs.

### 7.3 M3 — API, WebSocket, crypto & audit
- **Events** (Pydantic v2, discriminated on `type`, every event has `event_id` + UTC `timestamp`): `SNAPSHOT`, `USB_CONNECTED`, `USB_DISCONNECTED`, `SCAN_PROGRESS`, `FILE_SCANNED`, `FILE_ENRICHED`, `SCAN_COMPLETE`, `AUDIT_STATUS`, `HEARTBEAT`.
- `FILE_SCANNED` must stay compatible with this contract (extra fields allowed):

```json
{
  "type": "FILE_SCANNED",
  "event_id": "c1f…",
  "timestamp": "2026-11-19T12:00:00Z",
  "scan_id": "…",
  "drive": "E:\\",
  "file": "E:\\invoice.pdf",
  "filename": "invoice.pdf",
  "size_bytes": 245760,
  "sha256": "…",
  "entropy": 7.81,
  "chi_square": 241.7,
  "magic_type": "PE32 executable (MZ)",
  "magic_hex": "4d5a9000…",
  "extension_mismatch": true,
  "yara_matches": ["Magic_Spoof_Executable"],
  "authenticode": "unsigned",
  "likelihood": 5, "impact": 5, "risk_score": 25,
  "tier": "CRITICAL",
  "mitre": ["T1036.008"],
  "reasons": ["Magic bytes (MZ) mismatch claimed .pdf extension", "High Shannon entropy (7.81 > 7.2)"],
  "scan_status": "COMPLETE",
  "chain_index": 42,
  "chain_hash": "…"
}
```

- **WebSocket hub:** worker threads push into an `asyncio.Queue` via `loop.call_soon_threadsafe`. One broadcaster task; **each client has its own send queue + writer task** so a slow client can't stall others. On connect, the server first sends a `SNAPSHOT` (last 500 events, stats, active drives) so a page refresh repopulates instantly with no duplicates. Heartbeat every 15 s.
- **Audit chain (Week 6):** each `FILE_SCANNED` gets `chain_hash = SHA256(prev_hash ‖ canonical_json(event))` plus an HMAC-SHA256 with a server secret. `GET /api/audit/verify` recomputes the chain. `POST /api/demo/tamper` (demo-only flag) edits one stored record so the UI badge turns **BROKEN at #n** live.
- **Signed reports (Weeks 5, 7, 8):** canonical JSON (sorted keys, no whitespace) of a scan session → sign with **RSA-PSS (SHA-256, 3072-bit)** by default; **DSA-3072** and **Ed25519** selectable for comparison. Return `{report, signature_b64, algorithm, public_key_pem, certificate_pem}`. `scripts/verify_report.py` verifies offline; the README also shows the equivalent `openssl dgst` command. docs/CRYPTO_DESIGN.md explains that **FIPS 186-5 (2023) no longer approves DSA for generating new signatures**, which is why RSA-PSS/EdDSA are primary and DSA is kept for comparison only.
- **REST:**
  - `GET /api/health` — status, YARA rule count, intel providers online, WS clients
  - `GET /api/stats`, `GET /api/history`
  - `POST /api/demo/simulate` — scan `qa_demo/sample_usb_drive/` as virtual drive `Z:\`
  - `POST /api/demo/eject`
  - `POST /api/intel/lookup` `{hash}` and `GET /api/intel/recent`
  - `POST /api/reports/{scan_id}/sign?alg=rsa-pss|dsa|ed25519`, `POST /api/reports/verify`
  - `GET /api/audit/verify`
  - `POST /api/quarantine/{event_id}`, `GET /api/quarantine`, `POST /api/quarantine/{id}/restore`
- CORS for `http://localhost:5173` and `http://127.0.0.1:5173`. Secrets only from `.env`; `.env` in `.gitignore`.

### 7.4 M4 — SOC dashboard
- Dark SOC theme: background `#0B0F19`, cards `#111827`, 1px slate borders; Safe `#10B981`, Suspicious `#F59E0B`, Critical `#EF4444`, live telemetry `#06B6D4`. Monospace for hashes. System fonts only (works offline on stage).
- `useAegisSocket`: auto-reconnect with exponential backoff + jitter, reducer state, **batch incoming events per animation frame** so a fast scan doesn't freeze the UI, dedupe by `event_id`.
- Forensic drawer: full SHA-256 (copy button), magic hex vs claimed extension, entropy + chi-square, YARA hits, Authenticode, intel verdicts with source links, MITRE IDs, risk matrix cell, chain index/hash, plus "Quarantine" and "Sign report" actions.
- Tabs: **Live** (counters, entropy chart, feed, table), **Intel**, **Integrity** (audit chain + reports), **About** (course mapping table from §3).
- Toast on `SCAN_COMPLETE` showing counts; a red banner flash when a CRITICAL arrives.

### 7.5 M5 — Payloads, tests, docs
`generate_payloads.py` builds `qa_demo/sample_usb_drive/` with inert files and prints the expected tier for each:

| File | Expected |
|---|---|
| `Q3_Financial_Report.pdf` (real `%PDF-1.4` text) | SAFE |
| `Photos/team_photo.png` (valid PNG of random pixels — high entropy but exempt) | SAFE |
| `meeting_notes.txt` | SAFE |
| `backup_archive.bin` (`os.urandom`) | SUSPICIOUS |
| `Documents/cleanup.bat` (only `echo`) | SUSPICIOUS |
| `invoice.pdf` (`MZ\x90\x00` + random padding) | CRITICAL |
| `holiday_photo.jpg.exe` | CRITICAL |
| `autorun.inf` (`[AutoRun]\nopen=setup.exe`) | CRITICAL |
| `Documents/payroll_update.ps1` (inert text, URL `example.invalid`) | CRITICAL |
| `aegis_test_sample.txt` (custom signature string) | CRITICAL |
| `Tools/driver_update.exe` (MZ + UPX0/UPX1 markers, not runnable) | CRITICAL |
| `cache/blob.dat` (fake PE XOR-encoded with key 0x5A) | CRITICAL |

Add `local_ioc.txt` containing the SHA-256 of one payload so the offline intel path is demonstrable.

---

## 8. Engineering standards
- No blocking in the event loop: polling, traversal, hashing and YARA run in threads; intel calls use async httpx.
- Pydantic models and TypeScript interfaces must match field-for-field; add a test that dumps the JSON schema and compares the keys with `telemetry.ts`.
- Chunked reads only (64 KB). Header reads only for magic checks. Size cap enforced.
- Type hints everywhere, `ruff` clean, docstrings on public functions, structured logging.
- No placeholder TODOs or stubbed logic. Every endpoint is real.
- Cross-platform: Windows 10/11 is the demo machine; also Linux/macOS.
- Conventional commits, one branch per member (`m1-core`, `m2-engine`, …), PRs reviewed by one other member.

---

## 9. Documentation to generate (makes the "we researched it" impression)
Each doc is short (1–3 pages), in our own words, with a references section.

- **RESEARCH.md** — USB threat landscape, case studies (Stuxnet, Agent.btz, Raspberry Robin), how commercial kiosks (e.g. Honeywell SMX, OPSWAT MetaDefender Kiosk) approach the same problem, and what we do differently.
- **THREAT_MODEL.md** — STRIDE table for AEGIS itself, attack-surface diagram of a USB device (mass storage, HID, firmware/BadUSB), trust boundaries, assumptions.
- **CRYPTO_DESIGN.md** — choice table: SHA-256 vs MD5/SHA-1; AES-256-GCM vs DES/3DES/AES-CBC; RSA-PSS vs PKCS#1 v1.5 vs DSA vs Ed25519 (key sizes, speed, standards status); why a hash chain gives tamper-evidence but not tamper-proofing; what a real CA would add.
- **RISK_REGISTER.md** — 10+ risks (e.g. zero-day not caught by static checks, API quota exhaustion, key compromise, false positives on compressed files) with likelihood, impact, score, treatment, owner.
- **PRIVACY.md** — GDPR principles applied: data minimisation (hash-only lookups), purpose limitation, storage limitation (`AEGIS_RETENTION_DAYS`), filename redaction, third-party transfer note for VirusTotal/abuse.ch.
- **COURSE_MAPPING.md** — §3 table with file links.
- **VIVA_QA.md** — 25 likely examiner questions with crisp answers (e.g. "Why is entropy 7.2?", "Can an attacker evade magic-byte checks?", "Why not just upload files to VirusTotal?", "What does the hash chain prove?", "Why is DSA not your default?", "What's the difference between hashing and encryption?", "Limits of static analysis?").
- **qa_demo/README.md** — setup (venv, pip, uvicorn; npm install, npm run dev), `.env` keys, a 5-minute demo script, a per-member talking-points list, and troubleshooting (Windows Defender may flag the `.ps1` demo text → add a folder exclusion for `qa_demo/`).

---

## 10. Acceptance tests (pytest + a manual demo checklist)
- Entropy: 137 evenly-used byte values (H ≈ 7.10) → not flagged; 158 values (H ≈ 7.30) → flagged; empty file → 0.0.
- Magic: MZ in `.pdf` → mismatch; MZ in `.exe` → no mismatch; `report.pdf.exe` and RTLO names → flagged.
- XOR: PE stub XOR'd with a random key is found, and the right key is reported.
- YARA: rules compile; each demo payload hits exactly its expected rule; a clean text file hits nothing.
- Tiers: every row of the §7.5 table produces its expected tier.
- Intel: providers mocked with `respx`; 429 triggers backoff; cache hit avoids a network call; offline mode works.
- Crypto: sign → verify passes for all three algorithms; one flipped byte in the report → verify fails; vault encrypt → restore gives the same SHA-256; a wrong passphrase fails cleanly.
- Audit chain: verify passes; after `/api/demo/tamper` verify reports the broken index.
- WebSocket: connect → `SNAPSHOT` first; `/api/demo/simulate` → `USB_CONNECTED`, N × `FILE_SCANNED`, `SCAN_COMPLETE` with matching counts.
- Frontend: `npm run build` passes with strict TypeScript.
- Manual: real USB stick on Windows is detected within 2 s; unplugging mid-scan cancels cleanly.

---

## 11. Epics (for the BMAD Scrum Master)
1. **Foundation** — repo, CLAUDE.md, configs, CI (pytest + `npm run build`), contracts (`schemas.py` ⇄ `telemetry.ts`).
2. **Detection core** — M1 monitor/walker + M2 hasher/entropy/magic/YARA/analyzer + demo payloads.
3. **Realtime hub & dashboard MVP** — WebSocket, snapshot, simulate endpoint, five core components. *(Demo-able checkpoint.)*
4. **Course-depth features** — XOR, Authenticode, threat intel, risk matrix, audit chain, signed reports, vault.
5. **GRC & documentation** — all docs in §9, About tab, viva Q&A.
6. **Hardening & rehearsal** — cross-platform test, performance on a 2–5 GB stick, demo rehearsal, slides.

---

## 12. Build order (if running without BMAD)
1. Scaffold + `requirements.txt`, `package.json`, `vite.config.ts`, `index.css` (Tailwind v4), CLAUDE.md, `.env.example`.
2. M1 + M2 core (no intel yet) + `usb_threats.yar` + `generate_payloads.py` + engine tests. **Run tests.**
3. M3 schemas, ws_manager, routes, main. **Run the API test.**
4. M4 dashboard (core five components). **Run `npm run build`; start both servers; click Simulate.**
5. Intel providers, audit chain, signer + keystore, vault, XOR, Authenticode + their tests and UI panels.
6. Docs (§9) and the qa_demo README runbook.
7. Final check: fresh clone → `python qa_demo/generate_payloads.py` → `uvicorn app.api.main:app --port 8000` (from `backend/`) → `npm run dev` → Simulate shows every expected tier, chain verifies, a report signs and verifies. Fix anything that fails before saying "done".
