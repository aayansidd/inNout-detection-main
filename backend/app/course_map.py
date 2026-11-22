"""Course week -> feature map (§3): the single source for the About tab and COURSE_MAPPING.md.

Every path listed here is checked by a test, so a renamed or deleted file fails the build
instead of leaving a dead link in the UI or the docs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[2]
Status = Literal["implemented", "partial", "not_built"]


class CourseRow(BaseModel):
    week: str
    topic: str
    feature: str
    files: list[str]
    cia: str  # Confidentiality / Integrity / Availability
    status: Status
    note: str | None = None


ROWS: list[CourseRow] = [
    CourseRow(
        week="1", topic="Intro to InfoSec (CIA triad)", cia="C, I, A", status="implemented",
        feature="Every feature is tagged with the CIA property it protects (this table); the "
                "threat model sets the scope and trust boundaries.",
        files=["docs/THREAT_MODEL.md", "docs/COURSE_MAPPING.md"],
    ),
    CourseRow(
        week="2", topic="Attack taxonomy + classical crypto", cia="I", status="implemented",
        feature="MITRE ATT&CK tags on every detection; single-byte XOR de-obfuscation of hidden "
                "PE headers (a classical cipher real malware uses); entropy as frequency analysis.",
        files=["backend/app/engine/xor_detect.py", "backend/app/engine/entropy.py",
               "backend/app/engine/analyzer.py", "backend/app/rules/usb_threats.yar"],
    ),
    CourseRow(
        week="3", topic="Symmetric crypto", cia="C, I", status="implemented",
        feature="AES-256-GCM quarantine vault: flagged files are copied in encrypted so they "
                "cannot execute; key from scrypt; the file hash is bound in as associated data.",
        files=["backend/app/core/vault.py", "qa_demo/test_crypto.py"],
    ),
    CourseRow(
        week="4", topic="DES", cia="C", status="implemented",
        feature="Why DES/3DES are rejected (56-bit key; 64-bit block, Sweet32); the config "
                "refuses legacy ciphers; measured AES vs 3DES benchmark.",
        files=["docs/CRYPTO_DESIGN.md", "backend/scripts/bench_ciphers.py",
               "backend/app/config.py"],
    ),
    CourseRow(
        week="5", topic="Asymmetric crypto", cia="I", status="implemented",
        feature="RSA-3072, DSA-3072 and Ed25519 key generation in the station keystore.",
        files=["backend/app/crypto/keystore.py"],
    ),
    CourseRow(
        week="6", topic="Hash functions", cia="I", status="implemented",
        feature="Streaming SHA-256 fingerprints; MD5/SHA-1 only for threat-intel lookups (with a "
                "collision warning); hash-chained tamper-evident audit log; avalanche demo.",
        files=["backend/app/engine/hasher.py", "backend/app/crypto/audit_chain.py",
               "backend/scripts/avalanche_demo.py"],
    ),
    CourseRow(
        week="7", topic="Digital signatures", cia="I", status="implemented",
        feature="Signed scan reports (RSA-PSS default; DSA and Ed25519 for comparison), a verify "
                "endpoint and an offline verifier; Authenticode presence check on PE files.",
        files=["backend/app/crypto/signer.py", "backend/scripts/verify_report.py",
               "backend/app/engine/authenticode.py"],
        note="Authenticode check verifies the certificate table's presence and structure, not "
             "the certificate chain.",
    ),
    CourseRow(
        week="8", topic="Trust over the Internet", cia="I, C", status="implemented",
        feature="TLS-verified threat-intel calls (certificate checking is never switched off, "
                "enforced by a test); self-signed X.509 'AEGIS Scanner Station' certificates; "
                "docs on what a CA adds.",
        files=["backend/app/engine/intel/base.py", "backend/app/crypto/keystore.py",
               "qa_demo/test_intel.py", "docs/CRYPTO_DESIGN.md"],
    ),
    CourseRow(
        week="10", topic="GRC", cia="C, I, A", status="implemented",
        feature="NIST CSF 2.0 and ISO/IEC 27001:2022 (Annex A 7.10, 8.7) mapping.",
        files=["docs/RISK_REGISTER.md"],
    ),
    CourseRow(
        week="11-13", topic="Risk lifecycle, assessment, analysis, mitigation", cia="A, I",
        status="implemented",
        feature="Numeric risk = likelihood x impact on a 5x5 matrix in the UI; a risk register "
                "with a treatment (avoid / mitigate / transfer / accept) for each risk.",
        files=["backend/app/engine/analyzer.py", "frontend/src/components/RiskMatrix.tsx",
               "docs/RISK_REGISTER.md"],
    ),
    CourseRow(
        week="14", topic="Privacy & GDPR", cia="C", status="implemented",
        feature="Hash-only lookups (data minimisation, Art. 5(1)(c)); retention for the intel "
                "cache; filename redaction in signed reports.",
        files=["docs/PRIVACY.md", "backend/app/engine/intel/base.py", "backend/app/config.py"],
        note="Retention purges only the intel cache; the audit log and vault are not "
             "auto-purged (see PRIVACY.md).",
    ),
    CourseRow(
        week="15", topic="IoT security & attack surfaces", cia="I, A", status="partial",
        feature="USB attack-surface analysis (storage, HID, firmware) in the threat model.",
        files=["docs/THREAT_MODEL.md"],
        note="The BadUSB keyboard-appearance alert (stretch goal) is NOT built: AEGIS "
             "inspects storage content only.",
    ),
]

# Docs and the runbook may be opened from the About tab even when no table row links them.
EXTRA_PUBLIC_FILES = [
    "docs/RESEARCH.md", "docs/VIVA_QA.md", "docs/PRIVACY.md", "docs/CRYPTO_DESIGN.md",
    "docs/RISK_REGISTER.md", "docs/THREAT_MODEL.md", "docs/COURSE_MAPPING.md",
    "qa_demo/README.md",
]


def public_files() -> set[str]:
    """Repo-relative files the API may serve (read-only, plain text). Nothing else."""
    return {f for row in ROWS for f in row.files} | set(EXTRA_PUBLIC_FILES)


def read_public_file(rel: str) -> str | None:
    """Return the file's text if ``rel`` is on the allowlist and resolves inside the repo."""
    if rel not in public_files():
        return None
    path = (REPO_ROOT / rel).resolve()
    if REPO_ROOT not in path.parents or not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


_STATUS_LABEL = {"implemented": "Implemented", "partial": "Partial", "not_built": "Not built"}


def render_markdown(rows: list[CourseRow] | None = None) -> str:
    """Render docs/COURSE_MAPPING.md (links are relative to docs/)."""
    rows = rows if rows is not None else ROWS
    lines = [
        "# Course-to-feature map",
        "",
        "<!-- Generated by backend/scripts/gen_course_mapping.py from backend/app/course_map.py. "
        "Do not edit by hand. -->",
        "",
        "Each row ties an IS-353 lecture week to the part of AEGIS USB that demonstrates it. "
        "The **CIA** column says which security property the feature protects "
        "(C = confidentiality, I = integrity, A = availability). The same table is shown in "
        "the dashboard's **About** tab.",
        "",
        "| Week | Topic | Where it lives in AEGIS USB | CIA | Status | Files |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        files = "<br>".join(f"[`{f}`](../{f})" for f in r.files)
        feature = r.feature + (f" **Note:** {r.note}" if r.note else "")
        lines.append(
            f"| {r.week} | {r.topic} | {feature} | {r.cia} | {_STATUS_LABEL[r.status]} | {files} |"
        )
    lines += [
        "",
        "## Honest gaps",
        "",
        "- **Week 15, BadUSB alert:** not built. A malicious *device* that pretends to be a "
        "keyboard is invisible to a tool that only reads file contents; "
        "`docs/THREAT_MODEL.md` explains the gap.",
        "- **Week 7, Authenticode:** we check that a signature is present and well-formed, not "
        "that its certificate chain is trusted.",
        "- **Week 14, retention:** only the intel cache is purged automatically.",
        "",
        "Back to the [project docs](./) · [Viva Q&A](VIVA_QA.md) · [Runbook](../qa_demo/README.md)",
        "",
    ]
    return "\n".join(lines)
