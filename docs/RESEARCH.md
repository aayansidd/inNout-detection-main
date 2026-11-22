# Research: the USB threat landscape and where AEGIS USB fits

*IS-353 Information Security · Weeks 1, 2, 15. Our own summary; sources are listed at the end.*

## 1. Why a USB stick is still a serious problem

Networks that are deliberately cut off from the internet (industrial control systems, power
and water plants, some government sites) still need to move files in and out, and the easiest
way is a removable drive carried by hand. That gap between "the network is isolated" and
"a person plugs something in" is what attackers aim at.

Honeywell publishes yearly figures from its Secure Media Exchange (SMX) scanning product. Its
2022 report said **52 %** of the threats it saw were built specifically to use removable
media [1]; its 2024 report put the share at **51 %** [2]. Two cautions, which we repeat in
the viva: these numbers come from one vendor's own customers rather than an independent
survey, and the sources we found disagree about the 2021 baseline (32 % in the press release,
37 % in a Honeywell article). We therefore quote only the two headline figures.

## 2. Three incidents worth knowing

| Case | What happened (in short) | Lesson for AEGIS |
|---|---|---|
| **Stuxnet** (found 2010) | A worm aimed at industrial controllers. One of its spreading routes was a USB drive carrying a booby-trapped Windows shortcut (`.lnk`); the flaw, CVE-2010-2568, let the code run just because the folder was *displayed* [3][4]. | Nothing has to be "opened" for a drive to hurt you, so screening has to happen before the user browses it. AEGIS treats `.lnk` as a script-capable type and recognises the shortcut header; it does **not** parse shortcut internals, so a patched-flaw-style exploit would not be recognised as such. |
| **Agent.btz** (2008) | A worm that spread by flash drives and reached US military networks; the clean-up was called Operation Buckshot Yankee, and the Department of Defense temporarily banned removable media [5][6][7]. Who was behind it is disputed, so we make no attribution claim. | A blanket ban is blunt and costly. Screening lets people keep using drives while removing the obviously bad ones. |
| **Raspberry Robin** (2021–22) | A worm that spreads on infected USB drives, where a malicious shortcut (`.lnk`) file poses as a folder [8]. | A shortcut posing as a folder or document is cheap to make. Name and header checks (extension mismatch, double extensions, `.lnk` as script-capable) catch the lazy versions. |

## 3. ATT&CK techniques AEGIS detects or refers to

| ID | Name | Where it shows up in AEGIS |
|---|---|---|
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication through removable media | `autorun.inf` YARA rule |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User execution: malicious file | script/shortcut extensions, intel-confirmed malware |
| [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | Masquerading: double file extension | `invoice.pdf.exe` check |
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Masquerading: file type | executable header behind a document extension |
| [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Masquerading: right-to-left override | U+202E in filenames |
| [T1027](https://attack.mitre.org/techniques/T1027/) / [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | Obfuscated files / software packing | single-byte XOR detector; entropy and UPX rule |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | download-and-execute and encoded-command rule |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit system recovery | shadow-copy deletion rule |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware additions | **referenced only**: BadUSB-style devices are not detected (see THREAT_MODEL.md) |

## 4. How commercial products approach the same problem

* **Honeywell SMX** combines a scanning gateway, a threat-analysis engine backed by threat
  intelligence, a management portal and a client driver on the protected PCs that refuses to
  mount media that has not been scanned. It also tries to spot "weaponised" devices that pose
  as something else (keyboard-emulating gadgets) [9].
* **OPSWAT MetaDefender Kiosk** is a walk-up station that runs files through many antivirus
  engines at once, rebuilds documents to strip active content ("content disarm and
  reconstruction"), and checks for known vulnerable files; the vendor's materials describe
  30+ engines and support for 200+ file types [10]. These are the vendor's own claims.

## 5. What we do differently, and what we do not do

| | Commercial kiosks | AEGIS USB (this project) |
|---|---|---|
| Detection | Many engines, sandboxes, content rebuilding | Static checks only: entropy, magic bytes, name tricks, XOR, YARA, Authenticode presence |
| Intel | Built-in vendor feeds | **Hash-only** lookups to free public services; file contents never leave the machine |
| Evidence | Central management portal | Every verdict has plain-English reasons and ATT&CK IDs; results are chained in a tamper-evident log and can be **signed** and verified offline |
| Enforcement | Blocks unscanned media at the PC | **None.** AEGIS reports; it cannot stop the operating system mounting a drive |
| Devices | Tries to vet the device itself | **Not covered** (no HID/firmware checks; the BadUSB alert is unbuilt) |
| Purpose | Production protection | A teachable, inspectable system showing how each course topic fits one real problem |

The honest summary: AEGIS USB is a transparent *screening and evidence* tool for a student
project, not a replacement for a hardened kiosk. Its strengths are explainability and
verifiable records; its limits are listed above and in `RISK_REGISTER.md`.

## 6. Entropy as a clue (Week 2)

Entropy measures how evenly byte values are spread, from 0 (one repeated byte) to 8 bits per
byte (every value equally likely). Plain text and code sit well below the top; encrypted and
packed data sit near it. Lyda and Hamrock proposed using this to find packed or encrypted
executables [11]. On our demo files the text-like samples measure about 3.7–5.0 and the
random-looking ones 7.98–8.00. We flag anything above **7.2**, which is a rule of thumb we
chose, not a theorem; compressed formats (JPEG, PNG, ZIP, PDF…) legitimately score high, so a
file whose header and extension agree on such a format is exempt.

## References

All accessed **2026-11-19**. Vendor pages are marketing material and are treated as claims.

1. Honeywell, "Cybersecurity research reveals 52 % of cyber threats targeted at removable media" (2022) — https://www.honeywell.com/us/en/press/2022/08/honeywell-cybersecurity-research-reveals-52-of-cyber-threats-targeted-at-removable-media
2. Honeywell GARD, "The 2024 USB Threat Report" — https://www.honeywell.com/us/en/reports/2024/usb-threat-report
3. NIST National Vulnerability Database, CVE-2010-2568 — https://nvd.nist.gov/vuln/detail/CVE-2010-2568
4. Symantec, "W32.Stuxnet Dossier" — https://www.security.com/threat-intelligence/stuxnet-dossier-espionage
5. Kaspersky Securelist, "Agent.btz: a Source of Inspiration?" — https://securelist.com/agent-btz
6. Threatpost, "Buckshot Yankee" — https://threatpost.com/buckshot-yankee/91831
7. W. J. Lynn III, "Defending a New Domain", *Foreign Affairs* (2010) — https://www.foreignaffairs.com/articles/united-states/2010-09-01/defending-new-domain
8. "Raspberry Robin gets the worm early" (originally Red Canary; the old address now redirects here) — https://www.zscaler.com/blogs/cybersecurity-best-practices/raspberry-robin
9. Honeywell, "Secure Media Exchange" — https://www.honeywell.com/us/en/solutions/ot-cybersecurity/secure-media-exchange
10. OPSWAT, "MetaDefender Kiosk" — https://www.opswat.com/products/metadefender/kiosk
11. R. Lyda and J. Hamrock, "Using Entropy Analysis to Find Encrypted and Packed Malware", *IEEE Security & Privacy* 5(2), 2007 — https://ieeexplore.ieee.org/document/4140989
12. MITRE ATT&CK, techniques T1091, T1204.002, T1036.007, T1036.008, T1036.002, T1027.002, T1059.001, T1490, T1200 — https://attack.mitre.org/techniques/T1091/ (other IDs follow the same URL pattern)
