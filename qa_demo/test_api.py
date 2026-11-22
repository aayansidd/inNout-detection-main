"""API, WebSocket and schema-contract tests (§10)."""

import re
from pathlib import Path

import pytest
from app.api import schemas
from app.config import get_settings
from fastapi.testclient import TestClient

import generate_payloads as gp

TELEMETRY_TS = Path(__file__).resolve().parents[1] / "frontend/src/types/telemetry.ts"


@pytest.fixture()
def client(drive, monkeypatch):
    monkeypatch.setenv("AEGIS_DEMO_DRIVE_PATH", str(drive))
    monkeypatch.setenv("AEGIS_WATCH_USB", "false")
    monkeypatch.setenv("AEGIS_DEMO_MODE", "true")
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def collect_until_complete(ws, limit=200):
    events = []
    for _ in range(limit):
        ev = ws.receive_json()
        events.append(ev)
        if ev["type"] == "SCAN_COMPLETE":
            return events
    raise AssertionError("no SCAN_COMPLETE")


def test_health_and_empty_state(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["yara_rules"] == 6 and h["ws_clients"] == 0
    assert client.get("/api/stats").json()["total"] == 0
    assert client.get("/api/history").json() == []


def test_websocket_snapshot_first_then_simulate(client):
    n = len(gp.EXPECTED)
    with client.websocket_connect("/ws") as ws:
        first = ws.receive_json()
        assert first["type"] == "SNAPSHOT" and first["events"] == []
        assert client.post("/api/demo/simulate").status_code == 200
        events = collect_until_complete(ws)
    types = [e["type"] for e in events]
    assert types[0] == "USB_CONNECTED"
    assert types.count("FILE_SCANNED") == n
    done = events[-1]
    assert done["total"] == n and (done["safe"], done["suspicious"], done["critical"]) == (3, 2, 7)
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))
    tiers = {e["filename"]: e["tier"] for e in events if e["type"] == "FILE_SCANNED"}
    for rel, (tier, _) in gp.EXPECTED.items():
        assert tiers[Path(rel).name] == tier


def test_reconnect_snapshot_repopulates_without_duplicates(client):
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        client.post("/api/demo/simulate")
        collect_until_complete(ws)
    with client.websocket_connect("/ws") as ws:
        snap = ws.receive_json()
    assert snap["type"] == "SNAPSHOT"
    ids = [e["event_id"] for e in snap["events"]]
    assert len(ids) == len(set(ids))
    assert sum(e["type"] == "FILE_SCANNED" for e in snap["events"]) == len(gp.EXPECTED)
    assert snap["stats"]["total"] == len(gp.EXPECTED)
    assert snap["drives"][0]["drive"] == "Z:\\" and snap["drives"][0]["scanning"] is False
    assert client.get("/api/stats").json()["critical"] == 7
    assert len(client.get("/api/history?limit=5").json()) == 5


def test_eject_and_resimulate(client):
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        client.post("/api/demo/simulate")
        collect_until_complete(ws)
        assert client.post("/api/demo/eject").json() == {"ejected": True}
        while (ev := ws.receive_json())["type"] != "USB_DISCONNECTED":
            pass
        assert client.post("/api/demo/eject").json() == {"ejected": False}
        assert client.post("/api/demo/simulate").status_code == 200
        collect_until_complete(ws)


def test_simulate_without_drive_is_409(drive, monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DEMO_DRIVE_PATH", str(tmp_path / "nope"))
    monkeypatch.setenv("AEGIS_WATCH_USB", "false")
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        assert c.post("/api/demo/simulate").status_code == 409
    get_settings.cache_clear()


def test_demo_mode_off_blocks_demo_endpoints(drive, monkeypatch):
    monkeypatch.setenv("AEGIS_DEMO_MODE", "false")
    monkeypatch.setenv("AEGIS_WATCH_USB", "false")
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        assert c.post("/api/demo/simulate").status_code == 403
        assert c.post("/api/demo/eject").status_code == 403
    get_settings.cache_clear()


def test_cors_allows_vite_origin(client):
    r = client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def _ts_interfaces() -> dict[str, set[str]]:
    text = TELEMETRY_TS.read_text()
    out = {}
    for m in re.finditer(r"export interface (\w+) \{(.*?)\n\}", text, re.S):
        out[m.group(1)] = set(re.findall(r"^\s+(\w+)\??:", m.group(2), re.M))
    return out


def test_pydantic_models_match_telemetry_ts_field_for_field():
    ts = _ts_interfaces()
    for model in schemas.CONTRACT_MODELS:
        name = model.__name__
        assert name in ts, f"{name} missing from telemetry.ts"
        assert set(model.model_json_schema()["properties"]) == ts[name], name


def test_file_scanned_contract_example_fields():
    required = {
        "type", "event_id", "timestamp", "scan_id", "drive", "file", "filename", "size_bytes",
        "sha256", "entropy", "chi_square", "magic_type", "magic_hex", "extension_mismatch",
        "yara_matches", "authenticode", "likelihood", "impact", "risk_score", "tier", "mitre",
        "reasons", "scan_status", "chain_index", "chain_hash",
    }
    assert required <= set(schemas.FileScannedEvent.model_fields)
    assert schemas.FileScannedEvent.model_config["extra"] == "allow"


# ======================= Phase 5: audit chain, reports, quarantine, intel =======================
import hashlib  # noqa: E402
import time  # noqa: E402
from contextlib import contextmanager  # noqa: E402
from urllib.parse import parse_qs  # noqa: E402

import httpx  # noqa: E402
import respx  # noqa: E402

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
N = len(gp.EXPECTED)


@contextmanager
def app_client(drive, monkeypatch, **env):
    monkeypatch.setenv("AEGIS_DEMO_DRIVE_PATH", str(drive))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def wait_for(predicate, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("timed out waiting for condition")


def run_scan(client):
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        assert client.post("/api/demo/simulate").status_code == 200
        return collect_until_complete(ws)


def file_events(events):
    return [e for e in events if e["type"] == "FILE_SCANNED"]


def test_every_scanned_file_gets_a_sequential_chain_index_and_verifies(client):
    events = file_events(run_scan(client))
    assert sorted(e["chain_index"] for e in events) == list(range(1, N + 1))
    assert all(len(e["chain_hash"]) == 64 for e in events)
    result = client.get("/api/audit/verify").json()
    assert result == {"valid": True, "length": N, "broken_at": None}


def test_tamper_breaks_chain_live_over_websocket_then_undo_repairs(client):
    run_scan(client)
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        idx = client.post("/api/demo/tamper").json()["tampered_index"]
        status = next(e for e in (ws.receive_json() for _ in range(20)) if e["type"] == "AUDIT_STATUS")
    assert status["valid"] is False and status["broken_at"] == idx
    assert client.get("/api/audit/verify").json()["broken_at"] == idx
    assert client.post("/api/demo/tamper/undo").json() == {"restored": True}
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_tamper_needs_data_and_demo_mode(client, drive, monkeypatch):
    assert client.post("/api/demo/tamper").status_code == 409  # nothing scanned yet
    with app_client(drive, monkeypatch, AEGIS_DEMO_MODE="false") as c:
        assert c.post("/api/demo/tamper").status_code == 403
        assert c.post("/api/demo/tamper/undo").status_code == 403


@pytest.mark.parametrize("alg", ["rsa-pss", "dsa", "ed25519"])
def test_sign_report_endpoint_then_verify_and_tamper_detection(client, alg):
    scan_id = run_scan(client)[0]["scan_id"]
    signed = client.post(f"/api/reports/{scan_id}/sign?alg={alg}")
    assert signed.status_code == 200
    body = signed.json()
    assert body["algorithm"] == alg and "BEGIN CERTIFICATE" in body["certificate_pem"]
    report = body["report"]
    assert report["summary"] == {
        "total": N, "safe": 3, "suspicious": 2, "critical": 7,
        "final": {"safe": 3, "suspicious": 2, "critical": 7},  # offline: no enrichment
    }
    assert len(report["files"]) == N and report["station"] == "AEGIS Scanner Station"
    assert all(f["chain_index"] for f in report["files"])
    ok = client.post("/api/reports/verify", json={k: body[k] for k in ("report", "signature_b64", "algorithm", "public_key_pem")})
    assert ok.json()["valid"] is True and ok.json()["matches_station_key"] is True
    body["report"]["summary"]["critical"] = 0
    bad = client.post("/api/reports/verify", json={k: body[k] for k in ("report", "signature_b64", "algorithm", "public_key_pem")})
    assert bad.json()["valid"] is False and "altered" in bad.json()["reason"]


def test_report_errors_and_foreign_key_is_not_station_key(client):
    scan_id = run_scan(client)[0]["scan_id"]
    assert client.post("/api/reports/nope/sign").status_code == 404
    assert client.post(f"/api/reports/{scan_id}/sign?alg=des").status_code == 422
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    other = ed25519.Ed25519PrivateKey.generate()
    pem = other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    import base64

    from app.crypto.signer import canonical_report_bytes

    rep = {"x": 1}
    sig = base64.b64encode(other.sign(canonical_report_bytes(rep))).decode()
    r = client.post("/api/reports/verify", json={"report": rep, "signature_b64": sig, "algorithm": "ed25519", "public_key_pem": pem}).json()
    assert r["valid"] is True and r["matches_station_key"] is False  # valid, but not OUR key
    junk = client.post("/api/reports/verify", json={"report": rep, "signature_b64": "x", "algorithm": "ed25519", "public_key_pem": "nope"})
    assert junk.status_code == 200 and junk.json()["valid"] is False


def test_redaction_mode_hides_names_and_paths_in_reports(drive, monkeypatch):
    with app_client(drive, monkeypatch, AEGIS_REDACT_FILENAMES="true") as c:
        scan_id = run_scan(c)[0]["scan_id"]
        files = c.post(f"/api/reports/{scan_id}/sign?alg=ed25519").json()["report"]["files"]
    assert all(f["filename"].startswith("redacted-") and "file" not in f for f in files)
    assert any(f["filename"].endswith(".exe") for f in files)  # extension kept


def critical_event(events):
    return next(e for e in file_events(events) if e["filename"] == "payroll_update.ps1")


def test_quarantine_restore_flow_keeps_original_and_protects_demo_drive(client, drive):
    event = critical_event(run_scan(client))
    eid = event["event_id"]
    q = client.post(f"/api/quarantine/{eid}")
    assert q.status_code == 200
    entry = q.json()
    original = Path(event["file"])
    assert original.exists() and entry["sha256"] == event["sha256"] and entry["original_deleted"] is False
    assert client.post(f"/api/quarantine/{eid}").status_code == 409  # already in the vault
    assert [e["id"] for e in client.get("/api/quarantine").json()] == [eid]
    restored = client.post(f"/api/quarantine/{eid}/restore").json()
    assert restored["verified"] and hashlib.sha256(Path(restored["restored_path"]).read_bytes()).hexdigest() == event["sha256"]
    refused = client.post(f"/api/quarantine/{eid}/delete-original")
    assert refused.status_code == 403 and original.exists()  # demo drive is protected


def test_quarantine_input_validation_and_missing_passphrase(client, drive, monkeypatch):
    assert client.post("/api/quarantine/zzz").status_code == 422
    assert client.post(f"/api/quarantine/{'a' * 32}").status_code == 404
    assert client.post(f"/api/quarantine/{'a' * 32}/restore").status_code == 400
    with app_client(drive, monkeypatch, AEGIS_VAULT_PASSPHRASE="") as c:
        r = c.post(f"/api/quarantine/{'a' * 32}")
        assert r.status_code == 503 and "AEGIS_VAULT_PASSPHRASE" in r.json()["detail"]


def test_delete_original_works_for_a_real_drive_only_after_quarantine(tmp_path, monkeypatch):
    """Non-simulated entry: the explicit delete removes the original but only if unchanged."""
    from app.core.vault import Vault

    victim = tmp_path / "usb" / "evil.exe"
    victim.parent.mkdir()
    victim.write_bytes(b"MZ" + b"\x01" * 100)
    sha = hashlib.sha256(victim.read_bytes()).hexdigest()
    eid = "9" * 32
    monkeypatch.setenv("AEGIS_DEMO_DRIVE_PATH", str(tmp_path / "usb"))
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        Vault(get_settings().data_dir / "vault", "test-vault-passphrase").quarantine(
            victim, eid, {"filename": "evil.exe", "original_path": str(victim), "sha256": sha, "tier": "CRITICAL",
                          "scan_id": "s", "drive": "E:\\", "simulated": False})
        victim.write_bytes(b"changed after quarantine")
        assert c.post(f"/api/quarantine/{eid}/delete-original").status_code == 409 and victim.exists()
        victim.write_bytes(b"MZ" + b"\x01" * 100)
        done = c.post(f"/api/quarantine/{eid}/delete-original").json()
        assert done["original_deleted"] is True and not victim.exists()


def mock_circl_404(router):
    router.get(url__regex=r"https://hashlookup\.circl\.lu/lookup/sha256/.*").mock(return_value=httpx.Response(404))


def test_intel_lookup_endpoint_eicar_malicious_from_both_providers(drive, monkeypatch):
    with respx.mock(assert_all_called=False) as router, app_client(
        drive, monkeypatch, AEGIS_INTEL_OFFLINE="false", AEGIS_MB_AUTH_KEY="k1", AEGIS_VT_API_KEY="k2"
    ) as c:
        mock_circl_404(router)
        router.post("https://mb-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(200, json={
            "query_status": "ok", "data": [{"signature": "EICAR", "file_type": "com", "first_seen": "x"}]}))
        router.get(f"https://www.virustotal.com/api/v3/files/{EICAR}").mock(return_value=httpx.Response(200, json={
            "data": {"attributes": {"last_analysis_stats": {"malicious": 64, "undetected": 6}}}}))
        assert c.get("/api/health").json()["intel_providers_online"] == ["local_ioc", "circl", "malwarebazaar", "virustotal"]
        r = c.post("/api/intel/lookup", json={"hash": EICAR.upper()}).json()
        assert r["sha256"] == EICAR and r["malicious"] is True
        status = {v["provider"]: v["status"] for v in r["verdicts"]}
        assert status["malwarebazaar"] == status["virustotal"] == "malicious"
        assert c.post("/api/intel/lookup", json={"hash": "123"}).status_code == 422
        assert c.get("/api/intel/recent").json() == []


def test_offline_mode_health_and_lookup_use_local_data_only(client):
    assert client.get("/api/health").json()["intel_providers_online"] == ["local_ioc"]
    r = client.post("/api/intel/lookup", json={"hash": EICAR}).json()
    assert [v["provider"] for v in r["verdicts"]] == ["local_ioc"] and r["malicious"] is False


def history_enriched(client):
    return [e for e in client.get("/api/history").json() if e["type"] == "FILE_ENRICHED"]


def test_offline_local_ioc_produces_exactly_one_enrichment(client):
    run_scan(client)
    enriched = wait_for(lambda: history_enriched(client))
    time.sleep(0.5)
    enriched = history_enriched(client)
    assert len(enriched) == 1  # offline "not found" results stay quiet
    e = enriched[0]
    assert e["verdicts"][0]["provider"] == "local_ioc" and e["verdicts"][0]["status"] == "malicious"
    assert e["tier"] == e["previous_tier"] == "CRITICAL"
    assert client.get("/api/stats").json()["critical"] == 7  # unchanged


def test_network_intel_escalates_row_and_moves_stats(drive, monkeypatch):
    target = hashlib.sha256((drive / "backup_archive.bin").read_bytes()).hexdigest()

    def mb_handler(request):
        form = parse_qs(request.content.decode())
        if form["query"] == ["get_info"] and form["hash"] == [target]:
            return httpx.Response(200, json={"query_status": "ok", "data": [{"signature": "FakeLocker", "file_type": "bin", "first_seen": "2026-01-01"}]})
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    with respx.mock(assert_all_called=False) as router, app_client(
        drive, monkeypatch, AEGIS_INTEL_OFFLINE="false", AEGIS_MB_AUTH_KEY="k1"
    ) as c:
        mock_circl_404(router)
        router.post("https://mb-api.abuse.ch/api/v1/").mock(side_effect=mb_handler)
        scan_id = run_scan(c)[0]["scan_id"]
        enriched = wait_for(lambda: (e := history_enriched(c)) and len(e) >= 9 and e)
        row = next(e for e in enriched if e["sha256"] == target)
        assert (row["previous_tier"], row["tier"], row["risk_score"]) == ("SUSPICIOUS", "CRITICAL", 25)
        assert "FakeLocker" in row["reasons"][0] and "T1204.002" in row["mitre"]
        stats = c.get("/api/stats").json()
        assert (stats["safe"], stats["suspicious"], stats["critical"], stats["total"]) == (3, 1, 8, N)
        with c.websocket_connect("/ws") as ws:  # a refresh reproduces the corrected state
            snap = ws.receive_json()
        assert snap["stats"]["critical"] == 8
        files = c.post(f"/api/reports/{scan_id}/sign?alg=ed25519").json()["report"]
        backup = next(f for f in files["files"] if f["sha256"] == target)
        # the report carries the chained (scan-time) tier; the intel upgrade is separate
        assert backup["tier"] == "SUSPICIOUS" and backup["final_tier"] == "CRITICAL"
        assert backup["intel"][0]["status"] in ("not_found", "malicious")
        assert files["summary"]["critical"] == 7 and files["summary"]["final"]["critical"] == 8


def test_signed_report_matches_the_chained_record_even_after_enrichment(drive, monkeypatch):
    """Every chained field in a signed report equals the audit-chain record; intel is separate."""
    target = hashlib.sha256((drive / "backup_archive.bin").read_bytes()).hexdigest()

    def mb_handler(request):
        form = parse_qs(request.content.decode())
        if form["query"] == ["get_info"] and form["hash"] == [target]:
            return httpx.Response(200, json={"query_status": "ok", "data": [{"signature": "FakeLocker", "file_type": "bin", "first_seen": "2026-01-01"}]})
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    with respx.mock(assert_all_called=False) as router, app_client(
        drive, monkeypatch, AEGIS_INTEL_OFFLINE="false", AEGIS_MB_AUTH_KEY="k1"
    ) as c:
        mock_circl_404(router)
        router.post("https://mb-api.abuse.ch/api/v1/").mock(side_effect=mb_handler)
        scan_id = run_scan(c)[0]["scan_id"]
        wait_for(lambda: (e := history_enriched(c)) and len(e) >= 9 and e)
        report = c.post(f"/api/reports/{scan_id}/sign?alg=ed25519").json()["report"]
        chained = {e["event_id"]: e for e in c.app.state.audit.events_for_scan(scan_id)}
        assert len(report["files"]) == len(chained)
        by_index = {e["chain_index"]: e for e in chained.values()}
        for f in report["files"]:
            rec = by_index[f["chain_index"]]
            assert f["chain_hash"] == rec["chain_hash"]
            for key in ("sha256", "tier", "likelihood", "impact", "risk_score", "mitre", "reasons"):
                assert f[key] == rec[key], key
        upgraded = next(f for f in report["files"] if f["sha256"] == target)
        assert upgraded["tier"] == "SUSPICIOUS" and upgraded["final_tier"] == "CRITICAL"
        assert upgraded["final_risk_score"] == 25 and "FakeLocker" in upgraded["final_reasons"][0]


def test_quarantine_audit_lookup_runs_off_the_event_loop(client, monkeypatch):
    """audit.get_event (SQLite) must not execute on the asyncio loop thread."""
    import asyncio
    import threading

    seen = {}
    audit = client.app.state.audit
    real = audit.get_event

    def spy(event_id):
        try:
            asyncio.get_running_loop()
            seen["on_loop"] = True
        except RuntimeError:
            seen["on_loop"] = False
        seen["thread"] = threading.get_ident()
        return real(event_id)

    monkeypatch.setattr(audit, "get_event", spy)
    event = critical_event(run_scan(client))
    assert client.post(f"/api/quarantine/{event['event_id']}").status_code == 200
    assert seen["on_loop"] is False


def test_reset_clears_stats_history_and_pushes_a_fresh_snapshot(client):
    scan_id = run_scan(client)[0]["scan_id"]
    assert client.get("/api/stats").json()["total"] == N
    audit_len = client.app.state.audit.length()
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        r = client.post("/api/demo/reset")
        assert r.status_code == 200 and r.json()["cleared_events"] > 0
        snap = ws.receive_json()  # every connected dashboard gets the cleared state
    assert snap["type"] == "SNAPSHOT" and snap["events"] == []
    assert snap["stats"] == {"total": 0, "safe": 0, "suspicious": 0, "critical": 0, "scans_completed": 0}
    assert client.get("/api/history").json() == []
    assert client.get("/api/stats").json()["total"] == 0
    assert client.app.state.audit.length() == audit_len  # evidence is kept
    assert client.post(f"/api/reports/{scan_id}/sign?alg=ed25519").status_code == 200


def test_reset_is_demo_only_and_refused_mid_scan(client, drive, monkeypatch):
    client.app.state.hub.drives["Z:\\"] = schemas.DriveState(
        drive="Z:\\", label="x", fs_type="demo", total_bytes=0, simulated=True, scan_id="s1"
    )
    assert client.post("/api/demo/reset").status_code == 409  # still scanning
    client.app.state.hub.drives.clear()
    assert client.get("/api/health").json()["demo_mode"] is True
    monkeypatch.setenv("AEGIS_DEMO_MODE", "false")
    get_settings.cache_clear()
    assert client.post("/api/demo/reset").status_code == 403
    assert client.get("/api/health").json()["demo_mode"] is False
