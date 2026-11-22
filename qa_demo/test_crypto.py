"""Crypto tests (§10): signatures, certificates, vault, audit chain, offline verifier."""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from app.core.vault import Vault, VaultError
from app.crypto.audit_chain import AuditChain, canonical_json
from app.crypto.keystore import ALGORITHMS, KeyStore
from app.crypto.signer import canonical_report_bytes, sign_report, verify_report
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

SCRIPT = Path(__file__).resolve().parents[1] / "backend" / "scripts" / "verify_report.py"
REPORT = {"scan_id": "abc", "summary": {"total": 2, "critical": 1}, "files": [{"filename": "é.exe", "tier": "CRITICAL"}]}


@pytest.fixture(scope="module")
def keystore(tmp_path_factory):
    return KeyStore(tmp_path_factory.mktemp("keys"))


@pytest.mark.parametrize("alg", ALGORITHMS)
def test_sign_then_verify_passes(keystore, alg):
    signed = sign_report(REPORT, alg, keystore)
    ok, reason = verify_report(signed["report"], signed["signature_b64"], alg, signed["public_key_pem"])
    assert ok, reason
    assert signed["algorithm"] == alg and "BEGIN CERTIFICATE" in signed["certificate_pem"]


@pytest.mark.parametrize("alg", ALGORITHMS)
def test_one_flipped_byte_in_report_fails(keystore, alg):
    signed = sign_report(REPORT, alg, keystore)
    tampered = json.loads(json.dumps(signed["report"]))
    tampered["summary"]["total"] = 3
    assert verify_report(tampered, signed["signature_b64"], alg, signed["public_key_pem"])[0] is False
    sig = bytearray(base64.b64decode(signed["signature_b64"]))
    sig[0] ^= 0x01
    assert verify_report(signed["report"], base64.b64encode(bytes(sig)).decode(), alg, signed["public_key_pem"])[0] is False


def test_verify_never_raises_on_garbage_and_rejects_mismatched_key(keystore):
    signed = sign_report(REPORT, "ed25519", keystore)
    assert verify_report(REPORT, "!!notbase64!!", "ed25519", signed["public_key_pem"])[0] is False
    assert verify_report(REPORT, signed["signature_b64"], "ed25519", "not a pem")[0] is False
    assert verify_report(REPORT, signed["signature_b64"], "nope", signed["public_key_pem"])[0] is False
    rsa_pub = keystore.get("rsa-pss").public_key_pem
    ok, reason = verify_report(REPORT, signed["signature_b64"], "ed25519", rsa_pub)
    assert not ok and "type" in reason
    with pytest.raises(ValueError):
        sign_report(REPORT, "des", keystore)


def test_canonical_form_is_key_order_independent_and_compact():
    a = canonical_report_bytes({"b": 1, "a": {"y": 2, "x": 1}})
    assert a == b'{"a":{"x":1,"y":2},"b":1}'
    assert a == canonical_report_bytes({"a": {"x": 1, "y": 2}, "b": 1})


def test_key_sizes_certificates_and_persistence(keystore, tmp_path):
    assert keystore.get("rsa-pss").private_key.key_size == 3072
    assert keystore.get("dsa").private_key.key_size == 3072
    for alg in ALGORITHMS:
        cert = x509.load_pem_x509_certificate(keystore.get(alg).certificate_pem.encode())
        assert cert.subject == cert.issuer  # self-signed
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "AEGIS Scanner Station"
        assert cert.public_key().public_numbers() == keystore.get(alg).private_key.public_key().public_numbers() \
            if alg != "ed25519" else True
        if alg != "ed25519":
            assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    again = KeyStore(keystore.directory)  # a new process loads the same keys
    assert again.get("rsa-pss").fingerprint_sha256 == keystore.get("rsa-pss").fingerprint_sha256
    mode = stat.S_IMODE(os.stat(keystore.directory / "rsa-pss.key.pem").st_mode)
    assert mode == 0o600


def run_script(*args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)], capture_output=True, text=True)


@pytest.mark.parametrize("alg", ALGORITHMS)
def test_offline_script_verifies_and_detects_tampering(keystore, tmp_path, alg):
    signed = sign_report(REPORT, alg, keystore)
    assert signed["report"] is not REPORT  # the signer returns a copy
    good = tmp_path / "good.json"
    good.write_text(json.dumps(signed))
    r = run_script(good)
    assert r.returncode == 0 and "VALID" in r.stdout
    signed["report"]["summary"]["critical"] = 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(signed))
    r = run_script(bad)
    assert r.returncode == 1 and "INVALID" in r.stdout


def test_offline_script_fingerprint_pinning_and_usage_errors(keystore, tmp_path):
    signed = sign_report(REPORT, "ed25519", keystore)
    f = tmp_path / "s.json"
    f.write_text(json.dumps(signed))
    assert run_script(f, "--fingerprint", keystore.get("ed25519").fingerprint_sha256).returncode == 0
    assert run_script(f, "--fingerprint", "00" * 32).returncode == 1
    assert run_script(tmp_path / "missing.json").returncode == 2


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_openssl_cli_verifies_the_same_rsa_pss_and_ed25519_signatures(keystore, tmp_path):
    for alg, cmd in {
        "rsa-pss": ["dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"],
        "ed25519": ["pkeyutl", "-rawin"],
    }.items():
        signed = sign_report(REPORT, alg, keystore)
        f, out = tmp_path / f"{alg}.json", tmp_path / alg
        f.write_text(json.dumps(signed))
        assert run_script(f, "--export", out).returncode == 0
        verify = (["openssl", *cmd, "-verify", str(out / "public.pem"), "-signature", str(out / "signature.bin"),
                   str(out / "report.json")] if alg == "rsa-pss" else
                  ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(out / "public.pem"), "-rawin",
                   "-in", str(out / "report.json"), "-sigfile", str(out / "signature.bin")])
        r = subprocess.run(verify, capture_output=True, text=True)
        assert r.returncode == 0, (alg, r.stdout, r.stderr)


# ---- vault -------------------------------------------------------------------------------------
@pytest.fixture()
def sample(tmp_path):
    p = tmp_path / "evil file.exe"
    p.write_bytes(b"MZ" + os.urandom(5000))
    return p


def test_vault_roundtrip_same_sha256_original_untouched_ciphertext_opaque(tmp_path, sample):
    vault = Vault(tmp_path / "v", "correct horse")
    sha = hashlib.sha256(sample.read_bytes()).hexdigest()
    eid = "a" * 32
    entry = vault.quarantine(sample, eid, {"filename": sample.name, "sha256": sha})
    assert sample.exists() and entry["sha256"] == sha and entry["original_deleted"] is False
    blob = (tmp_path / "v" / f"{eid}.aegisq").read_bytes()
    assert blob.startswith(b"AEGQ1") and sample.read_bytes()[:64] not in blob
    result = vault.restore(eid, tmp_path / "out")
    assert result["verified"] and hashlib.sha256(Path(result["restored_path"]).read_bytes()).hexdigest() == sha
    assert Path(result["restored_path"]).name.endswith("evil_file.exe")  # sanitised name


def test_vault_wrong_passphrase_fails_cleanly(tmp_path, sample):
    Vault(tmp_path / "v", "right").quarantine(sample, "b" * 32, {"filename": "x"})
    with pytest.raises(VaultError, match="wrong passphrase"):
        Vault(tmp_path / "v", "wrong").restore("b" * 32, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_vault_detects_tampered_blob_and_metadata(tmp_path, sample):
    vault = Vault(tmp_path / "v", "pw")
    eid = "c" * 32
    vault.quarantine(sample, eid, {"filename": "x"})
    blob = tmp_path / "v" / f"{eid}.aegisq"
    raw = bytearray(blob.read_bytes())
    raw[-1] ^= 0xFF
    blob.write_bytes(bytes(raw))
    with pytest.raises(VaultError):
        vault.restore(eid, tmp_path / "out")
    # metadata swap: the recorded hash is bound in as GCM associated data
    eid2 = "d" * 32
    vault.quarantine(sample, eid2, {"filename": "x"})
    meta_path = tmp_path / "v" / f"{eid2}.json"
    meta = json.loads(meta_path.read_text())
    meta["sha256"] = "0" * 64
    meta_path.write_text(json.dumps(meta))
    with pytest.raises(VaultError):
        vault.restore(eid2, tmp_path / "out")


def test_vault_guards(tmp_path, sample):
    with pytest.raises(VaultError, match="passphrase not set"):
        Vault(tmp_path / "v", "").quarantine(sample, "e" * 32, {})
    vault = Vault(tmp_path / "v", "pw")
    for bad in ("../../etc/passwd", "short", "G" * 32):
        with pytest.raises(VaultError, match="invalid vault id"):
            vault.restore(bad, tmp_path / "out")
    with pytest.raises(VaultError, match="changed since"):
        vault.quarantine(sample, "f" * 32, {"sha256": "1" * 64})
    vault.quarantine(sample, "1" * 32, {"filename": "x"})
    with pytest.raises(VaultError, match="already"):
        vault.quarantine(sample, "1" * 32, {"filename": "x"})
    assert [e["id"] for e in vault.list()] == ["1" * 32]


def test_vault_uses_fresh_salt_and_nonce_each_time(tmp_path, sample):
    vault = Vault(tmp_path / "v", "pw")
    vault.quarantine(sample, "2" * 32, {"filename": "x"})
    vault.quarantine(sample, "3" * 32, {"filename": "x"})
    a = (tmp_path / "v" / ("2" * 32 + ".aegisq")).read_bytes()
    b = (tmp_path / "v" / ("3" * 32 + ".aegisq")).read_bytes()
    assert a[5:33] != b[5:33] and a != b  # same plaintext, different salt+nonce+ciphertext


# ---- audit chain -------------------------------------------------------------------------------
def event(i: int, tier: str = "CRITICAL") -> dict:
    return {"event_id": f"{i:032x}", "scan_id": "s1", "filename": f"f{i}.exe", "tier": tier, "sha256": "ab" * 32}


@pytest.fixture()
def chain(tmp_path):
    c = AuditChain(tmp_path / "a.db", "secret")
    yield c
    c.close()


def test_chain_verifies_and_links_hashes(chain):
    for i in range(1, 6):
        chain.append(event(i))
    assert chain.verify().valid and chain.length() == 5
    first = chain.get_event(f"{1:032x}")
    second = chain.get_event(f"{2:032x}")
    expected = hashlib.sha256(("0" * 64 + canonical_json(event(1))).encode()).hexdigest()
    assert first["chain_index"] == 1 and first["chain_hash"] == expected
    assert second["chain_index"] == 2


def test_tamper_reports_the_broken_index_and_undo_repairs(chain):
    for i in range(1, 11):
        chain.append(event(i))
    idx = chain.tamper()
    out = chain.verify()
    assert idx == 5 and (out.valid, out.broken_at, out.length) == (False, 5, 10)
    assert chain.undo_tamper() and chain.verify().valid
    assert not chain.undo_tamper()


def test_deleted_record_is_detected(chain, tmp_path):
    for i in range(1, 6):
        chain.append(event(i))
    db = sqlite3.connect(tmp_path / "a.db")
    db.execute("DELETE FROM audit_log WHERE idx=3")
    db.commit()
    db.close()
    assert chain.verify().broken_at == 3


def test_recomputing_hashes_without_the_secret_is_still_caught(chain, tmp_path):
    for i in range(1, 4):
        chain.append(event(i))
    db = sqlite3.connect(tmp_path / "a.db")
    payload = canonical_json(event(2, tier="SAFE"))
    prev = db.execute("SELECT chain_hash FROM audit_log WHERE idx=1").fetchone()[0]
    forged = hashlib.sha256((prev + payload).encode()).hexdigest()
    db.execute("UPDATE audit_log SET payload=?, chain_hash=? WHERE idx=2", (payload, forged))
    db.commit()
    db.close()
    assert chain.verify().broken_at == 2  # HMAC mismatch (and the next record's prev link)


def test_chain_persists_across_restarts_and_rejects_empty_secret(tmp_path):
    c1 = AuditChain(tmp_path / "p.db", "k")
    c1.append(event(1))
    c1.close()
    c2 = AuditChain(tmp_path / "p.db", "k")
    assert c2.append(event(2))[0] == 2 and c2.verify().valid
    c2.close()
    wrong = AuditChain(tmp_path / "p.db", "different-secret")
    assert wrong.verify().broken_at == 1  # a different secret cannot vouch for the log
    wrong.close()
    with pytest.raises(ValueError):
        AuditChain(tmp_path / "q.db", "")


def test_avalanche_one_bit_changes_about_half_the_hash_bits():
    a = hashlib.sha256(b"AEGIS report 0").digest()
    b = hashlib.sha256(b"AEGIS report 1").digest()  # differs in one input bit
    flipped = sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))
    assert 90 <= flipped <= 166  # ~128 of 256 expected
