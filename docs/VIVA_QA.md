# Viva Q&A: 25 likely examiner questions

*Short, honest answers. Each is tagged with the course week it belongs to and where to look in
the repo. If a question exposes a real limitation, we say so; that is a stronger answer than
bluffing.*

| Week | Questions |
|---|---|
| 1 (CIA triad) | Q21 |
| 2 (attacks, classical crypto) | Q1, Q2, Q7, Q16, Q17 |
| 3 (symmetric crypto) | Q6, Q8, Q9, Q10 |
| 4 (DES) | Q11 |
| 5 (asymmetric) | Q5, Q12 |
| 6 (hashes) | Q4, Q6, Q15, Q24 |
| 7 (signatures) | Q5, Q12, Q13 |
| 8 (trust on the Internet) | Q13, Q14, Q25 |
| 10 (GRC) | Q22 |
| 11–13 (risk) | Q7, Q18, Q19 |
| 14 (privacy) | Q3, Q20 |
| 15 (attack surfaces) | Q23 |

### Q1. Why is the entropy threshold 7.2? *(Week 2)*
It is a rule of thumb we chose, not a constant of nature. Entropy runs from 0 to 8 bits per
byte. On our demo files, text-like content measured about 3.7–5.0 and random/compressed data
7.98–8.00, so 7.2 sits well above ordinary code and data and below packed or encrypted
content. Lowering it catches more packers but flags more legitimate compressed files. Our unit
test pins the behaviour: a file using 137 evenly spread byte values (H ≈ 7.10) is not flagged,
one using 158 (H ≈ 7.30) is. *Code: `engine/entropy.py`, `config.py`.*

### Q2. Can an attacker evade the magic-byte checks? *(Week 2)*
Yes, in principle. A "polyglot" file can start with a harmless header (say, PDF) and carry a
payload elsewhere, so the header check alone sees nothing wrong. That is why no single check
decides: we also run YARA content rules, name checks (double extension, right-to-left override),
entropy and hash intelligence. We do not claim completeness. *Code: `engine/magic_bytes.py`.*

### Q3. Why not just upload every file to VirusTotal? *(Week 14)*
Because files can hold personal or confidential data, and sending them out breaks data
minimisation (GDPR Art. 5(1)(c)). A hash lookup reveals only "this exact file exists" and still
catches every *known* sample. The trade-off: a hash says nothing about a file nobody has seen
before, which is why we also keep local static analysis. Our code never uses VirusTotal's
download endpoints, and a test checks that no filenames appear in outgoing requests.
*Code: `engine/intel/`.*

### Q4. What does the hash chain prove, and what does it not? *(Week 6)*
It proves that stored records have not been *edited* or removed from the middle: each record's
hash covers the previous hash, so one change breaks every later link, and the verifier names the
first bad index. The HMAC stops someone without the server secret from recomputing a clean
chain. It does **not** prove completeness (deleting the newest records leaves a valid chain) or
who wrote a record, and it is tamper-*evident*, not tamper-*proof*. *Code: `crypto/audit_chain.py`.*

### Q5. Why is DSA not your default signature algorithm? *(Weeks 5, 7)*
FIPS 186-5 (2023) no longer approves DSA for generating new signatures, so a new design should
not choose it. DSA also needs a fresh secret random value for every signature (reuse leaks the
private key), whereas Ed25519 derives it deterministically. RSA-PSS is our default for broad
compatibility and a security proof; Ed25519 is the modern alternative; DSA is kept only so we can
compare. *Code: `crypto/signer.py`, `docs/CRYPTO_DESIGN.md`.*

### Q6. What is the difference between hashing and encryption? *(Weeks 3, 6)*
Hashing is one-way: a fixed-size fingerprint with no key that cannot be reversed, used for
integrity. Encryption is reversible with a key and protects confidentiality. We use SHA-256 for
fingerprints and the audit chain, AES-256-GCM for the vault, and HMAC (a *keyed* hash) when we
need to prove a record came from someone holding the secret.

### Q7. What are the limits of static analysis? *(Weeks 2, 11–13)*
It cannot see what a program *does*. A harmless-looking loader that downloads its payload later,
a logic bomb, or a brand-new exploit passes every static check. Hash intelligence only helps for
samples someone has already seen. AEGIS has no sandbox, so this is our largest accepted risk
(R1 in the register).

### Q8. Why AES-GCM rather than AES-CBC? *(Week 3)*
GCM is *authenticated* encryption: it hides the data and detects any change to it in one
operation. CBC only hides the data; to use it safely you must add and verify a separate MAC
correctly, and mistakes there have led to real attacks (padding oracles). The catch with GCM is
that reusing a nonce under one key is catastrophic, which Q9 addresses. *Code: `core/vault.py`.*

### Q9. Is a random 96-bit nonce safe in GCM? *(Week 3)*
NIST allows random 96-bit nonces up to about 2³² messages under one key. We stay far inside that
because every quarantined file gets its own scrypt salt and therefore its own key, so each key
encrypts exactly one message. *Code: `core/vault.py`.*

### Q10. Why scrypt, and why a salt? *(Weeks 3, 6)*
Passphrases are guessable, so we make each guess expensive: scrypt needs both time and memory
(N = 2¹⁵ uses about 32 MiB), which hurts attackers with GPUs. The random salt means two files
with the same passphrase still get different keys and pre-computed tables are useless.

### Q11. Why are DES and 3DES rejected? *(Week 4)*
DES has a 56-bit key, which is within reach of brute force. 3DES raises the key but keeps a
64-bit block, so after roughly 2³² blocks of data under one key, repeated blocks allow practical
attacks (Sweet32), and NIST has deprecated it. In our benchmark AES-256-GCM was about 200×
faster too. The config refuses `des`, `3des`, `rc4` and similar names at startup.
*Code: `config.py`, `scripts/bench_ciphers.py`.*

### Q12. Why RSA-PSS rather than PKCS#1 v1.5? *(Weeks 5, 7)*
PSS adds a random salt and has a security proof; RFC 8017 recommends it for new designs. v1.5
signatures are not broken when implemented correctly, but they are deterministic and have a
longer history of implementation mistakes. We use 3072-bit keys (about 128-bit security).

### Q13. What does your self-signed certificate actually give you? *(Weeks 7, 8)*
A standard container binding the name "AEGIS Scanner Station" to the public key, with validity
dates and key-usage flags. It adds **no trust**, because it is signed by the very key it
certifies; anyone could create an identical one. A valid signature only proves the report is
unchanged since it was signed by the holder of that key, so the verifier must compare the key
fingerprint through another channel. *Code: `crypto/keystore.py`, `scripts/verify_report.py`.*

### Q14. What would a real certificate authority add? *(Week 8)*
A chain of trust to a root the verifier already trusts, identity checking before issuing,
defined validity periods, and revocation (CRL/OCSP) if a key is stolen. The verifier would
validate `root → station` instead of comparing a hand-delivered fingerprint.

### Q15. Why do you still compute MD5 and SHA-1? *(Week 6)*
Only because some threat-intel feeds index by them. We never use them for integrity decisions,
and the UI labels them "legacy, collision-prone". Practical collisions exist for both (SHA-1 was
shown in 2017), so against an adversary they cannot uniquely identify a file.

### Q16. How do you avoid false positives on JPEG, ZIP and similar files? *(Weeks 2, 11–13)*
Those formats are compressed, so high entropy is normal. If the header says JPEG, PNG, ZIP/OOXML,
PDF, MP4, 7z or gzip **and** the extension agrees, we do not escalate and we explain why. A
known-good hit (NSRL, via CIRCL) can downgrade a file that was suspicious *only* because of
entropy; it never downgrades scripts or executables with other findings, and a malicious intel
verdict always wins. *Code: `engine/analyzer.py`.*

### Q17. Single-byte XOR is trivial to break. Why include it? *(Week 2)*
Exactly because it is trivial: real malware still hides embedded executables with it, and it is
a clean example of a classical cipher whose key space (255 values) can be searched instantly. We
try every key on the first 512 bytes and report the key if a DOS/PE header appears. The lesson
is that a tiny key space gives no real secrecy. *Code: `engine/xor_detect.py`.*

### Q18. How is risk scored, and why likelihood × impact? *(Weeks 11–13)*
Each result gets a likelihood and an impact from 1 to 5 and a score = L × I (1–25) shown on a 5×5
matrix. The rules are deterministic and tested (for example a YARA hit is impact 5, likelihood
4–5). It is simple and explainable; the limitation is that multiplying ordinal scales is
subjective. *Code: `engine/analyzer.py`, `RiskMatrix.tsx`.*

### Q19. Give an example of each risk treatment from your register. *(Weeks 11–13)*
**Mitigate:** quota exhaustion (R9) → cache, rate limiter, offline list. **Accept:** BadUSB not
detected (R2), documented. **Avoid:** third-party hash exposure (R14) → offline mode sends
nothing. **Transfer:** key theft (R6) → long-term, move keys to an HSM/KMS run by someone else.

### Q20. What personal data does the system handle, and how do you minimise it? *(Week 14)*
Indirectly: filenames, paths and drive labels. File contents are read locally and never sent;
intel calls send only a hash; signed reports can redact names; the intel cache is purged after
`AEGIS_RETENTION_DAYS`. Honest gaps: the audit log keeps real names, and erasing a record would
break the chain (see `docs/PRIVACY.md`).

### Q21. How does the CIA triad show up in the design? *(Week 1)*
**Confidentiality:** encrypted vault, hash-only lookups, secrets only in `.env`. **Integrity:**
hashes, the audit chain, signed reports. **Availability:** size caps, timeouts, bounded queues,
slow WebSocket clients dropped, and an offline mode so the tool works without the Internet. The
About tab tags every feature with C/I/A.

### Q22. How does the project map to NIST CSF? *(Week 10)*
CSF 2.0 has six functions. **Govern:** scope, threat model, risk register. **Identify:** risk
scoring of every file. **Protect:** vault, signing, Origin checks. **Detect:** live scan and
enrichment. **Respond:** alerts, quarantine, signed evidence. **Recover:** restore with SHA-256
verification. We say "supports", not "complies". *See `docs/RISK_REGISTER.md`.*

### Q23. What attacks do you NOT detect? *(Week 15)*
Anything that is not file content: a BadUSB device that pretends to be a keyboard, reprogrammed
controller firmware, and electrical attacks. AEGIS reads files only, and the planned
keyboard-appearance alert was not built. The control for that class is operating-system
device-class allow-listing. *See `docs/THREAT_MODEL.md`.*

### Q24. What if someone deletes the newest audit records? *(Week 6)*
The chain still verifies, because nothing after the deletion exists to disagree. Mitigations: a
signed report records the last index and hash, so earlier reports act as outside witnesses
(a gap becomes provable), and a production system would also publish the head hash to an external
timestamp service. We list it as accepted risk R12.

### Q25. Why does it matter that TLS verification stays on? *(Week 8)*
Without certificate checking, an on-path attacker could impersonate an intel provider, answer
"clean" for a malicious hash, and read our API keys from the request headers. We never disable
verification, and a test scans the source code to enforce that.

## References

All accessed **2026-11-19**.

1. NIST FIPS 186-5, *Digital Signature Standard* — https://csrc.nist.gov/pubs/fips/186-5/final
2. NIST SP 800-38D, *GCM and GMAC* — https://csrc.nist.gov/pubs/sp/800/38/d/final
3. K. Bhargavan and G. Leurent, *Sweet32* — https://sweet32.info/
4. M. Stevens et al., *SHAttered* — https://shattered.io/
5. RFC 8017, *PKCS #1 v2.2* — https://www.rfc-editor.org/rfc/rfc8017
6. RFC 7914, *scrypt* — https://www.rfc-editor.org/rfc/rfc7914
7. RFC 5280, *X.509 PKI certificate profile* — https://www.rfc-editor.org/rfc/rfc5280
8. GDPR Article 5 — https://gdpr-info.eu/art-5-gdpr/
9. NIST *Cybersecurity Framework 2.0* — https://www.nist.gov/cyberframework
10. R. Lyda and J. Hamrock, *Using Entropy Analysis to Find Encrypted and Packed Malware*, IEEE S&P 2007 — https://ieeexplore.ieee.org/document/4140989
11. MITRE ATT&CK T1200 (hardware additions) — https://attack.mitre.org/techniques/T1200/
12. Project design docs: `docs/CRYPTO_DESIGN.md`, `docs/THREAT_MODEL.md`, `docs/RISK_REGISTER.md`, `docs/PRIVACY.md`
