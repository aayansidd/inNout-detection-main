# Threat model

*IS-353 Weeks 1, 2 and 15 (CIA triad, attack taxonomy, IoT/attack surfaces).*

## 1. What we are protecting, and from whom

**Assets:** (a) the *evidence* AEGIS produces (verdicts, the audit log, signed reports);
(b) the station's private signing keys and the vault passphrase; (c) the threat-intel API
keys; (d) the host PC that the USB drive is plugged into.

**Adversaries considered:** (1) the content of an untrusted USB drive (malware authors);
(2) a local person or process trying to hide a detection or forge a report; (3) a web page in
the operator's browser; (4) a curious or compromised intel provider.

**Not considered:** a determined attacker with administrator rights on the station, hardware
attacks on the PC, and nation-state firmware implants.

## 2. The USB attack surface (Week 15)

A "USB drive" is really a small computer with a controller chip and its own firmware that
tells the host *what it is*. One physical device can announce several roles.

```
                         ┌────────────────────────── USB device ──────────────────────────┐
  Host PC                │  Firmware (reprogrammable controller)  <-- BadUSB lives here   │
  ┌──────────┐  cable    │     │ announces device classes to the host:                    │
  │   OS     │◄─────────►│     ├─ Mass storage  -> filesystem, autorun.inf, files, .lnk   │ AEGIS reads this
  │  drivers │           │     ├─ HID keyboard  -> typed keystrokes / shortcuts           │ NOT covered
  └──────────┘           │     ├─ Network / serial adapters                               │ NOT covered
                         │     └─ Power path (electrical damage devices)                  │ out of scope
                         └─────────────────────────────────────────────────────────────────┘
```

| Layer | Example attack | AEGIS today |
|---|---|---|
| Files on mass storage | disguised executables, `autorun.inf`, script droppers, shortcut tricks | **Detected** (static checks, YARA, intel) |
| Filesystem metadata | hidden files, odd names, right-to-left override characters | **Detected** (hidden files are scanned; RTLO and double extensions flagged) |
| HID emulation ("BadUSB") | a "drive" that also types commands as a keyboard | **Not detected.** The planned keyboard-appearance alert is not built |
| Firmware | reprogrammed controller [3] | **Not detected** (scanning file contents cannot see firmware) |
| Electrical | power-surge devices | Out of scope |

## 3. Trust boundaries

```
 [ USB drive ]  ──untrusted bytes──►  [ Scanner threads ]  ──events──►  [ Hub / API (127.0.0.1) ]  ──►  [ Browser UI ]
   untrusted                           trusted code,                      no login; Origin-checked      same machine
                                       reads hostile input                      │
                                                                                 └─ hash only, over TLS ─►  [ Intel services ]
                                                                                                               third parties
```

1. **Drive → scanner:** everything on the drive is hostile. The scanner only *reads* bytes
   (never executes, opens with the OS, or imports them), caps file size, and times out YARA.
2. **Scanner → API:** in-process; trusted.
3. **API → browser:** localhost only; no login, so a foreign web page is blocked by an
   `Origin` check instead (see STRIDE row "Spoofing").
4. **Station → intel services:** only a SHA-256 leaves the machine, over verified TLS.

## 4. STRIDE for AEGIS itself

| | Threat | Where | Mitigation in this repo | Residual risk |
|---|---|---|---|---|
| **S**poofing | A web page the operator visits sends requests to the local API (e.g. simulate, quarantine) or opens the WebSocket | HTTP/WebSocket | Server binds to 127.0.0.1; CORS allow-list; state-changing requests and WebSocket handshakes with a foreign `Origin` are refused (tested) | Other local processes can still call the API: there is no login |
| **T**ampering | Editing a stored scan result to hide a detection | audit database | SHA-256 hash chain **plus** HMAC; `/api/audit/verify`; demo tamper shows "BROKEN at #n" | Deleting the *newest* records is not detectable by the chain alone |
| **T**ampering | Altering a report after it was issued | signed report | RSA-PSS / Ed25519 / DSA signature over canonical JSON; offline verifier | A signature proves "unchanged since signed", not "signed by a trusted party" |
| **R**epudiation | "I never scanned/approved that file" | audit log, reports | Chained, HMAC-protected log; signed reports record the audit range | One shared station key, no per-user identity |
| **I**nformation disclosure | File contents or names sent to third parties | intel calls | Hash-only lookups (tested: no filenames in requests); offline mode | The hash itself reveals "this file exists" to the provider |
| **I**nformation disclosure | Quarantined malware or keys read from disk | vault, key files | AES-256-GCM vault (scrypt-derived key); key files mode 0600 | Station private keys are stored unencrypted on disk |
| **D**enial of service | Huge files, endless directory trees, slow WebSocket clients | scanner, hub | 50 MB cap (header-only beyond it), 64 KB chunks, YARA 10 s timeout, bounded work queue, per-client queues that drop slow clients | Archives are not unpacked, so "zip bomb" content is not examined |
| **E**levation of privilege | A crafted file exploits a bug in the parser (PE, YARA) and runs code in the scanner | scanner | Files are never executed or imported; parsing happens on bytes in a worker thread | A parser vulnerability would run with the operator's privileges: run unprivileged |

## 5. Assumptions

* The station OS and Python environment are not already compromised.
* The operator runs AEGIS as an ordinary user, not as administrator.
* `backend/.env` and the `data/` folder are readable only by that user.
* Intel providers are honest-but-curious; their verdicts are *advice*, and a "malicious"
  verdict can raise the tier but nothing a provider says can lower a YARA/magic finding.

## 6. Known gaps (deliberately stated)

No sandbox or dynamic analysis; no device-level (HID/firmware) checks; no enforcement (the OS
still mounts the drive); no user accounts. Each is tracked in `RISK_REGISTER.md`.

## References

All accessed **2026-11-19**.

1. MITRE ATT&CK, T1200 Hardware Additions — https://attack.mitre.org/techniques/T1200/
2. MITRE ATT&CK, T1091 Replication Through Removable Media — https://attack.mitre.org/techniques/T1091/
3. K. Nohl and J. Lell, "BadUSB – On Accessories that Turn Evil", Black Hat USA 2014 — https://infocondb.org/con/black-hat/black-hat-usa-2014/badusb-on-accessories-that-turn-evil
4. Honeywell, "Secure Media Exchange" (device-vetting approach for comparison) — https://www.honeywell.com/us/en/solutions/ot-cybersecurity/secure-media-exchange
5. OWASP, "Unicode Encoding" (background on look-alike and direction-control characters) — https://owasp.org/www-community/attacks/Unicode_Encoding
6. MITRE ATT&CK, T1036.002 Right-to-Left Override — https://attack.mitre.org/techniques/T1036/002/
7. CISA, "Using Caution with USB Drives" — https://www.cisa.gov/news-events/news/using-caution-usb-drives
