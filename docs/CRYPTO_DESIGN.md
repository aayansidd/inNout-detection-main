# Cryptographic design

*IS-353 Weeks 3–8. Every choice below is what the code actually does; file names are given so
you can check.*

## 1. Choices at a glance

| Job | We use | We reject | Why |
|---|---|---|---|
| File fingerprint (Wk 6) | **SHA-256** (`engine/hasher.py`) | MD5, SHA-1 as identifiers | Practical collisions exist for both; a SHA-1 collision was demonstrated in 2017 [1]. They are computed **only** because some intel feeds index by them, and the UI labels them "legacy, collision-prone". |
| Vault encryption (Wk 3–4) | **AES-256-GCM** (`core/vault.py`) | DES, 3DES, RC4, Blowfish, AES-CBC without a MAC | GCM encrypts *and* authenticates in one step, so a tampered blob fails to decrypt. DES has a 56-bit key; 3DES's 64-bit block makes long-lived data open to birthday attacks (Sweet32) [2]; NIST deprecated it [3]. `AEGIS_VAULT_CIPHER` set to any of these stops the program at startup (`config.py`, tested). |
| Key from passphrase (Wk 3) | **scrypt**, N = 2¹⁵, r = 8, p = 1, fresh 16-byte salt per blob [4] | raw passphrase as key; a fast hash | scrypt is deliberately slow and memory-hungry, which makes guessing passphrases expensive. |
| Report signature (Wk 5, 7) | **RSA-PSS 3072** (default) | PKCS#1 v1.5 for new signatures | PSS has a security proof and randomised padding [5]. 3072-bit RSA targets roughly 128-bit security. |
| Comparison signatures | **Ed25519**, **DSA-3072** | — | Ed25519 [6] is small and fast. DSA is kept **only for comparison**: FIPS 186-5 (2023) no longer approves DSA for generating new signatures [7]. |
| Audit log integrity (Wk 6) | **SHA-256 chain + HMAC-SHA-256** [8] | a plain checksum | See §4. |
| Certificates (Wk 8) | self-signed **X.509** per key [9] | pretending it is a trust anchor | See §5. |

## 2. Measured: why not 3DES (Week 4)

Run `python backend/scripts/bench_ciphers.py` to reproduce. Our run (Apple-silicon Mac, macOS,
32 MiB buffer, best of 3; your numbers will differ, the ratios are the point):

| Cipher | Key | Block | Integrity built in | Encrypt MiB/s |
|---|---|---|---|---|
| AES-256-GCM | 256-bit | 128-bit | yes | ≈ 9,000 |
| AES-256-CBC | 256-bit | 128-bit | no (needs a separate MAC) | ≈ 1,970 |
| 3DES-CBC | 168-bit nominal, ≈ 112 effective | 64-bit | no (needs a separate MAC) | ≈ 45 |

AES-256-GCM was about **200×** faster than 3DES here, partly because modern CPUs have AES
instructions and nothing equivalent for DES. Speed is the minor argument; the 64-bit block and
the deprecation are the real ones.

## 3. Signatures compared (Week 7)

Same script, second table (4 KB message; operations per second on the same machine):

| Scheme | Key | Signature | Sign/s | Verify/s | Standards status |
|---|---|---|---|---|---|
| RSA-3072 PSS | 3072-bit | 384 B | ≈ 1,080 | ≈ 46,000 | Approved (FIPS 186-5) [7] |
| RSA-3072 PKCS#1 v1.5 | 3072-bit | 384 B | ≈ 1,070 | ≈ 49,000 | Approved but older padding; avoid for new designs [5] |
| DSA-3072 | 3072-bit (q = 256) | 64 B | ≈ 2,660 | ≈ 2,970 | **Not approved for new signatures** (FIPS 186-5) [7] |
| Ed25519 | 256-bit | 64 B | ≈ 54,800 | ≈ 26,100 | Approved (FIPS 186-5) [6][7] |

For one report per scan, all of these are fast enough; we chose on standards status and
robustness, not speed. RSA verification is quick, which suits "sign once, verify many times".

## 4. The hash chain: what it proves and what it does not

Each audit record stores `chain_hash = SHA-256(previous_hash ‖ canonical_json(record))` and an
`HMAC-SHA-256(server_secret, chain_hash)`.

* **Proves:** if any stored record is edited, every later `chain_hash` stops matching, and
  `/api/audit/verify` reports the first record that fails ("BROKEN at #n"). Deleting a record
  in the middle shows up as a numbering gap. Someone *without the secret* cannot repair the
  chain by recomputing hashes, because the HMAC would not match.
* **Does not prove:** that the chain is *complete*. An attacker who deletes the newest records
  leaves a chain that still verifies. Signed reports record the last index and hash, so
  printed or emailed reports act as outside witnesses; a production system would also
  publish the head hash to an external timestamp service.
* **Not tamper-*proof*:** it makes tampering *evident*, not impossible. Anyone with both the
  database and the secret can rewrite history.

## 5. What a real CA would add (Week 8)

Our station certificate says "this public key belongs to *AEGIS Scanner Station*", but it is
signed by the same key it certifies, so it adds **no trust**: anyone could mint an identical
one. What it does give is the standard container (name, validity, key usage) that other tools
understand. In production a certificate authority that the verifier already trusts would sign
the station's certificate, giving a chain `root CA → station`; verifiers would check that chain,
the validity dates and revocation status [9]. In this project the trust decision is made
**out of band**: compare the printed key fingerprint (SHA-256 of the public key) with one you
received separately. `backend/scripts/verify_report.py --fingerprint …` does exactly that.

Threat-intel calls are made with certificate checking **on** (never disabled; a test scans the
source to make sure), so we trust providers' public CAs for those connections.

## 6. Details worth knowing

* **Vault format** (`.aegisq`): `"AEGQ1" | salt(16) | nonce(12) | ciphertext+tag`. A fresh
  random 96-bit nonce is used for every encryption. NIST limits random-nonce GCM to about
  2³² messages per key [10]; here each blob has its own salt, hence its own key, so a key
  encrypts exactly one message. The file's SHA-256 is bound in as *associated data*, so
  swapping blobs or editing the metadata hash makes decryption fail. Restore re-hashes the
  plaintext and compares.
* **Canonical JSON:** reports are signed as UTF-8 JSON with sorted keys and no whitespace
  (Python's `json`). That is *not* the full RFC 8785 canonicalisation, so a verifier in another
  language must reproduce this exact form; the offline script and the `openssl` export
  show how.
* **Key storage:** private keys are PEM files with mode 0600, **unencrypted**. That is a
  known weakness recorded in the risk register; an HSM or key-management service is the
  production answer.
* **RSA-PSS salt length** is 32 bytes (the SHA-256 digest size); the `openssl` command in the
  runbook uses the same value.

## References

All accessed **2026-11-19**.

1. M. Stevens et al., "The first collision for full SHA-1" (SHAttered), 2017 — https://shattered.io/
2. K. Bhargavan and G. Leurent, "Sweet32: Birthday attacks on 64-bit block ciphers" — https://sweet32.info/
3. NIST SP 800-131A Rev. 2, *Transitioning the Use of Cryptographic Algorithms and Key Lengths* — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
4. RFC 7914, *The scrypt Password-Based Key Derivation Function* — https://www.rfc-editor.org/rfc/rfc7914
5. RFC 8017, *PKCS #1: RSA Cryptography Specifications v2.2* — https://www.rfc-editor.org/rfc/rfc8017
6. RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)* — https://www.rfc-editor.org/rfc/rfc8032
7. NIST FIPS 186-5, *Digital Signature Standard (DSS)* — https://csrc.nist.gov/pubs/fips/186-5/final
8. RFC 2104, *HMAC: Keyed-Hashing for Message Authentication* — https://www.rfc-editor.org/rfc/rfc2104
9. RFC 5280, *Internet X.509 Public Key Infrastructure Certificate and CRL Profile* — https://www.rfc-editor.org/rfc/rfc5280
10. NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: GCM and GMAC* — https://csrc.nist.gov/pubs/sp/800/38/d/final
11. NIST FIPS 180-4, *Secure Hash Standard* — https://csrc.nist.gov/pubs/fips/180-4/upd1/final
12. `cryptography` library documentation — https://cryptography.io/en/latest/
