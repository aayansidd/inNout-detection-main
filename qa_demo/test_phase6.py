"""Phase 6 tests: course map, legacy-cipher refusal, warm_cache, offline CLI behaviour."""

import hashlib
import re
from pathlib import Path

import generate_payloads as gp
import httpx
import pytest
import respx
from app import warm_cache
from app.config import ConfigError, get_settings, validate_cipher
from app.course_map import REPO_ROOT, ROWS, public_files, render_markdown
from app.engine.intel.cache import TokenBucket
from app.engine.intel.service import IntelService
from fastapi.testclient import TestClient

EICAR = warm_cache.EICAR_SHA256
MB_URL = "https://mb-api.abuse.ch/api/v1/"
CIRCL = r"https://hashlookup\.circl\.lu/lookup/sha256/.*"
VT = r"https://www\.virustotal\.com/api/v3/files/.*"


# ---- course map -----------------------------------------------------------------------------
def test_every_course_row_file_exists():
    missing = [f for r in ROWS for f in r.files if not (REPO_ROOT / f).is_file()]
    assert missing == []


def test_course_mapping_doc_is_generated_from_the_map():
    doc = (REPO_ROOT / "docs" / "COURSE_MAPPING.md").read_text(encoding="utf-8")
    assert doc == render_markdown(), "run: python backend/scripts/gen_course_mapping.py"


def test_course_map_covers_the_weeks_in_the_spec_and_is_honest_about_gaps():
    weeks = [r.week for r in ROWS]
    assert weeks == ["1", "2", "3", "4", "5", "6", "7", "8", "10", "11-13", "14", "15"]
    assert next(r for r in ROWS if r.week == "15").status == "partial"
    assert all(r.cia for r in ROWS)


def test_course_map_endpoint_and_file_allowlist(drive):
    from app.api.main import app

    with TestClient(app) as c:
        rows = c.get("/api/course-map").json()["rows"]
        assert len(rows) == len(ROWS)
        ok = c.get("/api/files/docs/COURSE_MAPPING.md")
        assert ok.status_code == 200 and ok.headers["content-type"].startswith("text/plain")
        assert ok.headers["x-content-type-options"] == "nosniff"
        for bad in ["backend/.env", ".env", "backend/.env.example", "../backend/.env",
                    "docs/../backend/.env", "backend/app/../.env", "CLAUDE.md",
                    "%2e%2e/backend/.env"]:
            assert c.get(f"/api/files/{bad}").status_code == 404, bad
        every = [f for f in public_files() if (REPO_ROOT / f).is_file()]
        assert every and all(c.get(f"/api/files/{f}").status_code == 200 for f in every)


# ---- legacy ciphers ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["DES", "3des", "TripleDES", "RC4", "blowfish", " des-ede3 "])
def test_legacy_ciphers_are_refused(name):
    with pytest.raises(ConfigError, match="refused"):
        validate_cipher(name)


def test_unknown_cipher_refused_and_default_ok(monkeypatch):
    with pytest.raises(ConfigError, match="Unsupported"):
        validate_cipher("aes-128-ecb")
    assert validate_cipher("AES-256-GCM") == "aes-256-gcm"
    monkeypatch.setenv("AEGIS_VAULT_CIPHER", "3des")
    get_settings.cache_clear()
    with pytest.raises(ConfigError):
        get_settings()


# ---- warm_cache -------------------------------------------------------------------------------
def make_service(monkeypatch, vt="vt-key"):
    monkeypatch.setenv("AEGIS_INTEL_OFFLINE", "false")
    monkeypatch.setenv("AEGIS_MB_AUTH_KEY", "mb-key")
    monkeypatch.setenv("AEGIS_VT_API_KEY", vt)
    get_settings.cache_clear()

    async def no_sleep(_s: float) -> None:
        return None

    settings = get_settings()
    svc = IntelService(settings, client=httpx.AsyncClient(), sleep=no_sleep)
    svc.vt.bucket = TokenBucket(1000, 1000.0)  # the real 4/min limiter has its own tests
    return settings, svc


def mock_all(router):
    router.get(url__regex=CIRCL).mock(return_value=httpx.Response(404))
    router.get(url__regex=VT).mock(return_value=httpx.Response(404))
    router.post(MB_URL).mock(return_value=httpx.Response(200, json={"query_status": "hash_not_found"}))


@respx.mock(assert_all_called=False)
async def test_warm_cache_then_live_pipeline_makes_zero_network_calls(monkeypatch, drive, respx_mock):
    settings, svc = make_service(monkeypatch)
    mock_all(respx_mock)
    lines: list[str] = []
    report = await warm_cache.warm(settings, drive, service=svc, say=lines.append)
    assert report.files == len(gp.EXPECTED) and report.network_lookups > 0 and report.errors == 0
    calls_after_warm = respx_mock.calls.call_count
    # The live pipeline now asks for exactly the same keys: every answer must be a cache hit.
    from app.engine.analyzer import analyze_file

    for rel in ("backup_archive.bin", "invoice.pdf", "Tools/driver_update.exe"):
        event = analyze_file(str(drive / rel), max_size_bytes=50 * 1024 * 1024).to_dict()
        verdicts, worth = await svc.lookup_for_event(event)
        assert worth and all(v.cached for v in verdicts if v.provider != "local_ioc"), rel
    assert respx_mock.calls.call_count == calls_after_warm
    assert any("EICAR" in line for line in lines)
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_warm_cache_second_run_is_all_cache(monkeypatch, drive, respx_mock):
    settings, svc = make_service(monkeypatch)
    mock_all(respx_mock)
    def hash_lookups() -> int:  # the recent-malware feed refresh is intentionally not cached
        return sum(b"get_recent" not in c.request.content for c in respx_mock.calls)

    await warm_cache.warm(settings, drive, service=svc, say=lambda _m: None)
    before = hash_lookups()
    second = await warm_cache.warm(settings, drive, service=svc, say=lambda _m: None)
    assert second.network_lookups == 0 and second.cached_answers > 0
    assert hash_lookups() == before
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_warm_cache_sends_only_hashes(monkeypatch, drive, respx_mock):
    settings, svc = make_service(monkeypatch)
    mock_all(respx_mock)
    await warm_cache.warm(settings, drive, service=svc, say=lambda _m: None)
    sent = " ".join(str(c.request.url) + c.request.content.decode() for c in respx_mock.calls)
    for name in ("invoice", "payroll", "holiday_photo", "backup_archive", "Q3_Financial"):
        assert name not in sent  # filenames never leave the machine
    assert hashlib.sha256((drive / "invoice.pdf").read_bytes()).hexdigest() in sent


async def test_warm_cache_refuses_offline_mode_and_missing_drive(monkeypatch, drive, tmp_path):
    settings = get_settings()  # conftest: offline=true
    with pytest.raises(RuntimeError, match="nothing to warm"):
        await warm_cache.warm(settings, drive)
    monkeypatch.setenv("AEGIS_INTEL_OFFLINE", "false")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="Demo drive not found"):
        await warm_cache.warm(get_settings(), tmp_path / "nope")


def test_cli_warm_cache_reports_clean_errors_instead_of_tracebacks(capsys):
    from app.__main__ import main

    assert main(["warm_cache"]) == 1  # conftest forces offline mode
    assert "nothing to warm" in capsys.readouterr().err


def test_docs_do_not_contain_unfinished_markers():
    pattern = re.compile(r"\b(TODO|FIXME|TBD|lorem ipsum)\b", re.I)
    offenders = [
        p.name for p in list((REPO_ROOT / "docs").glob("*.md")) + [REPO_ROOT / "qa_demo" / "README.md"]
        if p.name != "MASTER_PROMPT.md" and p.exists() and pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_every_doc_has_references_with_access_date():
    required = ["RESEARCH", "THREAT_MODEL", "CRYPTO_DESIGN", "RISK_REGISTER", "PRIVACY", "VIVA_QA"]
    for name in required:
        text = (REPO_ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8")
        assert re.search(r"^## References", text, re.M), f"{name} lacks a References section"
        assert re.search(r"https?://", text.split("## References", 1)[1]), name
        assert "2026-11-19" in text.split("## References", 1)[1], f"{name}: no access date"
    assert Path(REPO_ROOT / "docs" / "VIVA_QA.md").read_text(encoding="utf-8").count("\n### Q") == 25


# ---- cross-site protection ----------------------------------------------------------------------
def test_foreign_origin_cannot_trigger_state_changing_requests(drive, monkeypatch):
    monkeypatch.setenv("AEGIS_DEMO_DRIVE_PATH", str(drive))
    get_settings.cache_clear()
    from app.api.main import app

    with TestClient(app) as c:
        evil = {"Origin": "https://evil.example"}
        for path in ("/api/demo/simulate", f"/api/quarantine/{'a' * 32}", "/api/demo/tamper"):
            assert c.post(path, headers=evil).status_code == 403, path
        assert c.get("/api/health", headers=evil).status_code == 200  # reads are not writes
        good = c.post("/api/demo/simulate", headers={"Origin": "http://localhost:5173"})
        assert good.status_code == 200
        assert c.post("/api/demo/eject").status_code == 200  # no Origin: curl/tests still work


def test_foreign_origin_cannot_open_the_websocket(drive):
    from app.api.main import app
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as c:
        with pytest.raises(WebSocketDisconnect) as err:
            with c.websocket_connect("/ws", headers={"Origin": "https://evil.example"}):
                pass
        assert err.value.code == 1008
        with c.websocket_connect("/ws", headers={"Origin": "http://127.0.0.1:5173"}) as ws:
            assert ws.receive_json()["type"] == "SNAPSHOT"


def test_extra_origins_can_be_allowed_by_config(monkeypatch):
    monkeypatch.setenv("AEGIS_EXTRA_ORIGINS", "http://localhost:4173, http://demo.local:5173")
    get_settings.cache_clear()
    assert "http://localhost:4173" in get_settings().allowed_origins
    assert "http://demo.local:5173" in get_settings().allowed_origins
