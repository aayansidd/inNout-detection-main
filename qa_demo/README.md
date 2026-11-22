# AEGIS USB: setup, runbook and demo script

*Plug in a drive. See the verdict (hashed, scored, checked against threat intel and
cryptographically signed) before anyone opens a file.*

## 1. Setup (about 5 minutes)

**You need:** Python **3.11–3.13** (3.14 does not work yet: `yara-python` has no wheel for it),
Node.js 20+, and Git.

```bash
git clone https://github.com/Abdul-Rafe8311/inNout-detection.git
cd inNout-detection

# backend
python3.12 -m venv backend/.venv                    # Windows: py -3.12 -m venv backend\.venv
backend/.venv/bin/pip install -r backend/requirements.txt   # Windows: backend\.venv\Scripts\pip ...
cp backend/.env.example backend/.env                # Windows: copy backend\.env.example backend\.env
backend/.venv/bin/python qa_demo/generate_payloads.py       # creates the 12 inert demo files

# frontend
cd frontend && npm install && cd ..
```

### `backend/.env`: the settings that matter

| Variable | Meaning |
|---|---|
| `AEGIS_VAULT_PASSPHRASE` | **Set a real one.** Required for quarantine. Never reuse a real password. |
| `AEGIS_HMAC_SECRET` | Secret for the audit chain. If empty, one is generated into `data/hmac.secret`. |
| `AEGIS_MB_AUTH_KEY` | Free abuse.ch key for MalwareBazaar. Empty = that provider is off. |
| `AEGIS_VT_API_KEY` | Free VirusTotal key (4 requests/min, 500/day). Empty = off. |
| `AEGIS_INTEL_OFFLINE` | `true` = no network lookups at all (local IOC list only). |
| `AEGIS_PORT` | API port (default 8000). If you change it, set `VITE_BACKEND_PORT` in `frontend/.env` to the same number. |
| `AEGIS_REDACT_FILENAMES` | `true` = filenames hidden in signed reports. |
| `AEGIS_RETENTION_DAYS` | Age limit for the intel cache (purged at start-up). |

`.env` is git-ignored. **Never commit it, and never paste its contents into chat or slides.**

### Start the servers (two terminals)

```bash
# terminal 1: API (127.0.0.1:8000, or AEGIS_PORT)
cd backend && .venv/bin/python -m app            # Windows: .venv\Scripts\python -m app

# terminal 2: dashboard (http://localhost:5173)
cd frontend && npm run dev
```

If port 8000 is busy: `AEGIS_PORT=8011 .venv/bin/python -m app` and
`VITE_BACKEND_PORT=8011 npm run dev` (Vite will refuse to start on a different dashboard
port, on purpose: the API only accepts requests from `localhost:5173`).

## 2. Run this 10 minutes before class

1. **Internet on, keys in `.env`.** Close anything using port 5173/8000.
2. **Windows Defender:** add a folder exclusion for `qa_demo\` (it may flag the harmless
   `payroll_update.ps1` text). Then run `python qa_demo/generate_payloads.py`.
3. **Warm the intel cache** so VirusTotal answers appear instantly on stage:
   ```bash
   cd backend && .venv/bin/python -m app warm_cache
   ```
   It looks up the demo hashes and the EICAR hash. VirusTotal is paced at 4 requests/minute, so
   allow about 2 minutes (it took 96 s in our test). A `*` after a result means it came from cache. **Cache lifetime:** "found"
   answers 24 hours, "not found" answers **1 hour**, so do not run it the night before.
4. Start both servers. Open http://localhost:5173. Check the dot says **LIVE**.
5. **Dry run:** click **Simulate USB**, confirm 3 safe / 2 suspicious / 7 critical, then **Eject**.
   Open the **Intel** tab and confirm it says **Intel: online**.
6. **Fallback if the network dies:** stop the API, set `AEGIS_INTEL_OFFLINE=true`, restart.
   Everything works except live lookups (the local IOC list still flags `holiday_photo.jpg.exe`).

## 3. The 5-minute demo script

| Time | Do | Say |
|---|---|---|
| 0:00 | Live tab, empty. | "A USB drive can attack before anyone opens a file. AEGIS screens it and gives a verdict you can verify." |
| 0:30 | Click **Simulate USB**. | "Same code path as a real stick; the demo uses 12 inert files." Counters run to 3 / 2 / 7; banner flashes. |
| 1:15 | Point at the entropy chart and the **risk matrix**. | "Entropy shows random-looking files above the dashed 7.2 line. Risk is likelihood × impact on a 5×5 matrix." |
| 1:45 | Open `invoice.pdf`, then `blob.dat` in the drawer. | "A PDF that is really an executable (magic bytes MZ). And this one is a hidden PE encrypted with a single-byte XOR; we recover key 0x5A." |
| 2:30 | **Intel** tab → "Try the EICAR test file hash". | "Only the hash leaves the machine. VirusTotal says malicious; CIRCL knows it as a test file; MalwareBazaar has never seen it. Sources can disagree, so malicious always wins." |
| 3:00 | Back on Live: open `payroll_update.ps1` → **Quarantine**, then **Sign report**. | "Encrypted AES-256-GCM copy; the original stays. The report is signed RSA-PSS." Click **change one number & re-verify** → rejected. |
| 4:00 | **Integrity** tab → **Demo: tamper with a record**. | "Every result is hash-chained. I edited one stored record silently. The chain now says BROKEN at #6." Click **Undo tampering**. |
| 4:30 | Terminal: `python backend/scripts/verify_report.py <downloaded file>`. | "No server needed: anyone can verify the report offline." |
| 4:50 | **About** tab. | "Every lecture week maps to a feature, with the honest gaps marked." |

## 4. Talking points per team member

* **M1 (backend, OS monitor, vault).** `core/usb_monitor.py` polls mounts every second and
  decides what counts as removable per OS (never `/mnt`: WSL mounts `C:` there; macOS uses
  `diskutil` and rejects disk images). The walker never follows symlinks, scans hidden files
  and cancels cleanly if the stick is pulled. `core/vault.py`: AES-256-GCM, scrypt key, fresh
  salt and nonce per file, SHA-256 bound as associated data, restore re-verifies. Be ready for:
  "what if the stick is removed mid-scan?" (cancel event, in-flight results dropped).
* **M2 (detection and threat intel).** One 64 KB-chunk pass feeds SHA-256 and the entropy
  histogram. Signals: entropy (>7.2 with a compressed-format exemption), magic bytes, double
  extensions, RTLO, XOR key search, six YARA rules, Authenticode presence. Intel order: cache →
  local IOC → CIRCL → MalwareBazaar → VirusTotal, with a token bucket, 429 back-off and an
  offline mode. Say plainly: static analysis only; no sandbox.
* **M3 (API, signatures, audit chain).** Event hub with per-client queues and a `SNAPSHOT`
  on connect. SHA-256 chain + HMAC, `/api/audit/verify`, the tamper demo. Reports are canonical
  JSON signed with RSA-PSS (default), Ed25519 or DSA, verified offline. Own the honest answer
  about the self-signed certificate (adds no trust) and the tail-truncation limit.
* **M4 (frontend).** React + strict TypeScript + Tailwind v4, hand-drawn SVG charts. The socket
  hook reconnects with back-off and jitter, batches events per animation frame and de-duplicates
  by `event_id`. The Pydantic models and `telemetry.ts` are checked against each other by a
  test. Show the forensic drawer's reasons and MITRE links.
* **M5 (QA, payloads, docs, GRC).** `generate_payloads.py` makes inert files with known
  expected tiers; 130+ tests (intel mocked, tests never touch real services); the risk register,
  threat model, privacy and crypto docs; `VIVA_QA.md`. Own the GRC story: NIST CSF 2.0 and
  ISO 27001 A.7.10 / A.8.7, and the list of known gaps.

## 5. Verify a signed report outside the app

Download the signed JSON from the Sign report panel, then:

```bash
python backend/scripts/verify_report.py aegis-report-<id>.rsa-pss.json
# pin the key you trust (fingerprint shown in the UI / printed by the script):
python backend/scripts/verify_report.py aegis-report-<id>.rsa-pss.json --fingerprint <hex>
# let OpenSSL check the same signature (RSA-PSS):
python backend/scripts/verify_report.py aegis-report-<id>.rsa-pss.json --export out
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -verify out/public.pem -signature out/signature.bin out/report.json
```

A "valid" result means *unchanged since signed by the holder of that key*; it does not say who
that is. That is what the fingerprint comparison is for.

## 6. Tests and checks

```bash
backend/.venv/bin/python -m pytest              # all tests (from the repo root)
cd backend && .venv/bin/ruff check .            # lint
cd frontend && npm run build                    # strict TypeScript build
python backend/scripts/bench_ciphers.py         # AES vs 3DES, signature speeds (Weeks 4, 7)
python backend/scripts/avalanche_demo.py        # SHA-256 avalanche (Week 6)
python backend/scripts/gen_course_mapping.py    # regenerate docs/COURSE_MAPPING.md
```

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install` fails building `yara-python` | You are on Python 3.14. Use 3.11–3.13. |
| Header shows **OFFLINE** | API not running, or `VITE_BACKEND_PORT` ≠ `AEGIS_PORT`. |
| `Address already in use` | Another program owns the port; set `AEGIS_PORT` and `VITE_BACKEND_PORT`. |
| Simulate says "Demo drive missing" | Run `python qa_demo/generate_payloads.py`. |
| Quarantine says 503 | Set `AEGIS_VAULT_PASSPHRASE` in `backend/.env` and restart. |
| Intel tab says **offline** | No internet, `AEGIS_INTEL_OFFLINE=true`, or no keys (CIRCL still works without one). |
| VirusTotal rows lag | 4 requests/minute limit: run `warm_cache` first. |
| Defender removes demo files | Folder exclusion for `qa_demo\`, then regenerate. |
| Dashboard works at `localhost:5173` but fails elsewhere | Add the origin to `AEGIS_EXTRA_ORIGINS`. |
| Safe app, scary numbers after several runs | Counters reset on API restart; the audit log persists in `backend/data/`. |
