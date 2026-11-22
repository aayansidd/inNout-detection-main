# Privacy and GDPR

*IS-353 Week 14. Written for this repository as it is today; where something is only partly
done, the text says so.*

## 1. What personal data can AEGIS touch?

AEGIS has no user accounts and does not collect names or emails. Personal data can still appear
indirectly:

* **Filenames and folder paths** on a scanned drive (for example `Ahmed_CV.pdf`) shown in the
  dashboard, stored in the audit log, and included in reports.
* **Drive labels** such as a person's name.
* **File contents**, which AEGIS reads locally to analyse them. They are never sent anywhere.
* **File hashes.** A hash is not usually personal data on its own, but looking one up tells
  the provider "someone has this exact file".

## 2. GDPR principles [1], applied

| Principle (Art. 5) | What the code does | Honest limit |
|---|---|---|
| **Lawfulness, fairness, transparency** | This document and the About tab say what is processed and why | Operators must still have a legal basis to scan other people's media |
| **Purpose limitation** (1)(b) | Data is used only to judge and record the safety of removable media | — |
| **Data minimisation** (1)(c) | **Intel lookups send only a SHA-256 hash.** Contents, names and paths are never sent (a test checks outgoing requests). Files are streamed in 64 KB chunks and not copied unless the operator quarantines them | The hash still reveals existence of a file |
| **Storage limitation** (1)(e) | `AEGIS_RETENTION_DAYS` (default 30) purges the **intel cache** and the recent-malware list when the server starts | The audit log, enrichments and vault are **not** auto-purged (see §4) |
| **Integrity and confidentiality** (1)(f) | Quarantined files are AES-256-GCM encrypted; the audit log is hash-chained; reports can be signed; keys and `.env` are git-ignored | Station keys are unencrypted on disk (risk R6) |
| **Privacy by design** (Art. 25) [2] | Offline mode (`AEGIS_INTEL_OFFLINE=true`) disables every network call; redaction mode; localhost-only API | — |

## 3. Redaction mode

With `AEGIS_REDACT_FILENAMES=true`, **signed reports** replace each filename with
`redacted-<first 8 hash characters>.<extension>` and leave out the full path, so a report can be
shared without leaking what files were on the drive. The hash still identifies the file for
anyone who already holds it. **Not covered:** the live dashboard and the stored audit records
still show real names.

## 4. The tension between tamper-evidence and erasure

A hash chain works because records are never removed. A request to erase a record (Art. 17)
would break the chain after that point. Options for a real deployment: store only hashes and
metadata in the chain and keep names in a separate, deletable table; or "tombstone" a record
and re-anchor the chain, accepting a documented break. We have **not** implemented either; if
the log must contain personal data, set a retention rule for the whole database and start a new
chain.

## 5. Third-party transfers

When network intel is on, a SHA-256 is sent over verified TLS to:

| Service | Used for | Needs key |
|---|---|---|
| VirusTotal | Multi-engine verdict for a hash | yes |
| abuse.ch MalwareBazaar | Known-malware lookup and the recent feed | yes |
| CIRCL hashlookup | Known-good (NSRL and similar) lookup | no |

Each is operated by a different organisation under its own terms and privacy policy [3][4][5];
check them before using AEGIS on real data. API keys live only in `backend/.env`, which is
git-ignored. Turning on offline mode avoids all of these transfers, at the cost of live
verdicts.

## 6. Operator checklist

1. Prefer offline mode for sensitive environments.
2. Set `AEGIS_RETENTION_DAYS` to a value your policy allows and restart to purge the cache.
3. Use redaction mode before sharing signed reports.
4. Protect `backend/data/` and `backend/.env` (ordinary-user permissions only).

## References

All accessed **2026-11-19**.

1. GDPR Article 5, *Principles relating to processing of personal data* — https://gdpr-info.eu/art-5-gdpr/
2. GDPR Article 25, *Data protection by design and by default* — https://gdpr-info.eu/art-25-gdpr/
3. VirusTotal API overview (limits and terms) — https://docs.virustotal.com/docs/api-overview
4. abuse.ch MalwareBazaar API — https://bazaar.abuse.ch/api/
5. CIRCL hashlookup — https://www.circl.lu/services/hashlookup/
6. NIST National Software Reference Library — https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
