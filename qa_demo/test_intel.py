"""Threat-intel tests (§10): providers mocked with respx; no real network is ever used."""

import hashlib
import re
from pathlib import Path

import generate_payloads as gp
import httpx
import pytest
import respx
from app.config import get_settings
from app.engine.analyzer import apply_intel
from app.engine.intel.base import IntelVerdict
from app.engine.intel.cache import TokenBucket
from app.engine.intel.service import IntelService, worth_network_lookup

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
VT_URL = f"https://www.virustotal.com/api/v3/files/{EICAR}"
CIRCL_URL = f"https://hashlookup.circl.lu/lookup/sha256/{EICAR}"
BACKEND_APP = Path(__file__).resolve().parents[1] / "backend" / "app"


def make_service(monkeypatch, *, offline=False, mb="mb-test-key", vt="vt-test-key", sleeps=None):
    monkeypatch.setenv("AEGIS_INTEL_OFFLINE", "true" if offline else "false")
    monkeypatch.setenv("AEGIS_MB_AUTH_KEY", mb)
    monkeypatch.setenv("AEGIS_VT_API_KEY", vt)
    get_settings.cache_clear()
    record = sleeps if sleeps is not None else []

    async def fake_sleep(seconds: float) -> None:
        record.append(seconds)

    return IntelService(get_settings(), client=httpx.AsyncClient(), sleep=fake_sleep)


def vt_json(malicious: int, suspicious: int = 0, undetected: int = 10) -> dict:
    stats = {"malicious": malicious, "suspicious": suspicious, "undetected": undetected, "harmless": 0}
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


@respx.mock(assert_all_called=False)
async def test_malwarebazaar_malicious_sends_hash_only(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, vt="")
    mb = respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "data": [{"signature": "EICAR", "file_type": "com", "first_seen": "2020-01-01"}]}))
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    verdicts = await svc.lookup(EICAR)
    by = {v.provider: v for v in verdicts}
    assert by["malwarebazaar"].status == "malicious" and "EICAR" in by["malwarebazaar"].summary
    request = mb.calls.last.request
    assert request.headers["Auth-Key"] == "mb-test-key"
    form = dict(re.findall(r"([a-z_]+)=([^&]*)", request.content.decode()))
    assert form == {"query": "get_info", "hash": EICAR}  # nothing but the hash leaves the machine
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_malwarebazaar_not_found_and_bad_status(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, vt="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={"query_status": "hash_not_found"}))
    assert {v.provider: v.status for v in await svc.lookup(EICAR)}["malwarebazaar"] == "not_found"
    respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={"query_status": "unknown_auth_key"}))
    other = "ab" * 32
    respx_mock.get(f"https://hashlookup.circl.lu/lookup/sha256/{other}").mock(return_value=httpx.Response(404))
    v = {x.provider: x for x in await svc.lookup(other)}["malwarebazaar"]
    assert v.status == "error" and "mb-test-key" not in v.summary
    await svc.stop()


@pytest.mark.parametrize(("mal", "sus", "expected"), [(60, 0, "malicious"), (3, 0, "malicious"),
                                                        (1, 0, "suspicious"), (0, 2, "suspicious"), (0, 0, "clean")])
@respx.mock(assert_all_called=False)
async def test_virustotal_thresholds(monkeypatch, respx_mock, mal, sus, expected):
    svc = make_service(monkeypatch, mb="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    route = respx_mock.get(VT_URL).mock(return_value=httpx.Response(200, json=vt_json(mal, sus)))
    v = {x.provider: x for x in await svc.lookup(EICAR)}["virustotal"]
    assert v.status == expected
    assert route.calls.last.request.headers["x-apikey"] == "vt-test-key"
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_429_triggers_exponential_backoff_then_succeeds(monkeypatch, respx_mock):
    sleeps: list[float] = []
    svc = make_service(monkeypatch, mb="", sleeps=sleeps)
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    route = respx_mock.get(VT_URL).mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(429),
        httpx.Response(200, json=vt_json(50)),
    ])
    v = {x.provider: x for x in await svc.lookup(EICAR)}["virustotal"]
    assert v.status == "malicious" and route.call_count == 3
    assert sleeps == [3.0, 2.0]  # Retry-After honoured, then the doubled default
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_persistent_429_becomes_error_not_crash(monkeypatch, respx_mock):
    sleeps: list[float] = []
    svc = make_service(monkeypatch, mb="", sleeps=sleeps)
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    respx_mock.get(VT_URL).mock(return_value=httpx.Response(429))
    v = {x.provider: x for x in await svc.lookup(EICAR)}["virustotal"]
    assert v.status == "error" and sleeps == [1.0, 2.0, 4.0]
    assert await svc.cache.get("virustotal", EICAR) is None  # errors are never cached
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_cache_hit_avoids_network_call(monkeypatch, respx_mock):
    svc = make_service(monkeypatch)
    circl = respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    mb = respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={"query_status": "hash_not_found"}))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(200, json=vt_json(40)))
    first = await svc.lookup(EICAR)
    second = await svc.lookup(EICAR)
    assert (circl.call_count, mb.call_count, vt.call_count) == (1, 1, 1)
    assert not any(v.cached for v in first)
    assert all(v.cached for v in second if v.provider != "local_ioc")
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_offline_mode_makes_no_network_calls_but_local_ioc_works(monkeypatch, respx_mock, drive):
    svc = make_service(monkeypatch, offline=True)
    anything = respx_mock.route().mock(return_value=httpx.Response(500))
    ioc_hash = hashlib.sha256((drive / gp.IOC_TARGET).read_bytes()).hexdigest()
    verdicts = await svc.lookup(ioc_hash)
    assert [v.provider for v in verdicts] == ["local_ioc"] and verdicts[0].status == "malicious"
    assert svc.enabled_names() == ["local_ioc"]
    assert anything.call_count == 0
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_no_keys_disables_keyed_providers(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, mb="", vt="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    assert svc.enabled_names() == ["local_ioc", "circl"]
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_network_failure_becomes_error_verdict(monkeypatch, respx_mock):
    svc = make_service(monkeypatch)
    respx_mock.route().mock(side_effect=httpx.ConnectError("boom"))
    verdicts = await svc.lookup(EICAR)
    net = [v for v in verdicts if v.provider != "local_ioc"]
    assert net and all(v.status == "error" for v in net)
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_circl_known_good_and_low_trust(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, mb="", vt="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(200, json={
        "FileName": "calc.exe", "source": "NSRL", "hashlookup:trust": 100}))
    v = {x.provider: x for x in await svc.lookup(EICAR)}["circl"]
    assert v.status == "known_good" and "NSRL" in v.summary
    low = "cd" * 32
    respx_mock.get(f"https://hashlookup.circl.lu/lookup/sha256/{low}").mock(
        return_value=httpx.Response(200, json={"source": "x", "hashlookup:trust": 10}))
    assert {x.provider: x for x in await svc.lookup(low)}["circl"].status == "not_found"
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_known_good_stops_before_paid_providers(monkeypatch, respx_mock):
    svc = make_service(monkeypatch)
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(200, json={"source": "NSRL"}))
    mb = respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={"query_status": "hash_not_found"}))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(404))
    await svc.lookup(EICAR, stop_on_known_good=True)
    assert mb.call_count == 0 and vt.call_count == 0  # quota is saved
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_vt_daily_quota_exhausted_is_skipped(monkeypatch, respx_mock):
    monkeypatch.setenv("AEGIS_VT_DAILY_QUOTA", "1")
    svc = make_service(monkeypatch, mb="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(404))
    await svc.lookup(EICAR)
    other = "ef" * 32
    respx_mock.get(f"https://hashlookup.circl.lu/lookup/sha256/{other}").mock(return_value=httpx.Response(404))
    v = {x.provider: x for x in await svc.lookup(other)}["virustotal"]
    assert v.status == "skipped" and vt.call_count == 1
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_low_quota_reserves_vt_for_flagged_files(monkeypatch, respx_mock):
    monkeypatch.setenv("AEGIS_VT_DAILY_QUOTA", "10")  # < 50 remaining = "low"
    svc = make_service(monkeypatch, mb="")
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(404))
    quiet = {x.provider: x for x in await svc.lookup(EICAR, vt_priority=False)}["virustotal"]
    assert quiet.status == "skipped" and vt.call_count == 0
    await svc.lookup(EICAR, vt_priority=True)
    assert vt.call_count == 1
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_recent_feed_refresh_feeds_local_ioc(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, vt="")
    fresh = "12" * 32
    route = respx_mock.post(MB_URL).mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "data": [{"sha256_hash": fresh, "file_name": "a.exe",
                                         "file_type": "exe", "signature": "Emotet", "first_seen": "2026-11-19"}]}))
    assert await svc.refresh_recent() == 1
    assert dict(re.findall(r"([a-z_]+)=([^&]*)", route.calls.last.request.content.decode())) == {
        "query": "get_recent", "selector": "time"}
    assert (await svc.recent())[0]["signature"] == "Emotet"
    verdict = (await svc.local.lookup(fresh))
    assert verdict.status == "malicious" and "Emotet" in verdict.summary
    await svc.stop()


async def test_refresh_recent_is_noop_offline(monkeypatch):
    svc = make_service(monkeypatch, offline=True)
    assert await svc.refresh_recent() == 0
    await svc.stop()


async def test_token_bucket_limits_rate_with_fake_clock():
    now = [0.0]
    waits: list[float] = []

    async def sleep(s: float) -> None:
        waits.append(s)
        now[0] += s

    bucket = TokenBucket(4, 4 / 60, clock=lambda: now[0], sleep=sleep)
    for _ in range(4):
        await bucket.acquire()
    assert waits == []  # a burst of 4 is free
    await bucket.acquire()
    assert waits and waits[0] == pytest.approx(15.0)  # then one request per 15 s


def test_worth_network_lookup_gating():
    assert not worth_network_lookup({"tier": "SAFE", "filename": "notes.txt", "magic_type": "unknown / text"})
    assert worth_network_lookup({"tier": "SAFE", "filename": "app.exe", "magic_type": "unknown"})
    assert worth_network_lookup({"tier": "SUSPICIOUS", "filename": "a.bin", "magic_type": "unknown"})


# ---- verdict -> tier rules --------------------------------------------------------------------
def v(status, provider="x", summary="s"):
    return IntelVerdict(provider=provider, status=status, summary=summary)


BASE = dict(likelihood=3, impact=3, reasons=["High Shannon entropy (7.9 > 7.2)"], mitre=["T1027.002"],
            filename="backup.bin", rtlo=False, entropy=7.9)


def test_malicious_intel_forces_critical_even_if_known_good():
    out = apply_intel(tier="SAFE", verdicts=[v("known_good", "circl"), v("malicious", "virustotal", "60/70")], **BASE)
    assert (out.tier, out.likelihood, out.impact) == ("CRITICAL", 5, 5)
    assert out.reasons[0].startswith("Threat intel (virustotal)") and "T1204.002" in out.mitre


def test_known_good_downgrades_entropy_only_alert_with_reason():
    out = apply_intel(tier="SUSPICIOUS", verdicts=[v("known_good", "circl", "Known-good: x (NSRL)")], **BASE)
    assert out.tier == "SAFE" and out.known_good and "Downgraded" in out.reasons[0]


@pytest.mark.parametrize("override", [{"filename": "run.ps1"}, {"rtlo": True}, {"entropy": 5.0}])
def test_known_good_does_not_downgrade_when_not_entropy_only(override):
    out = apply_intel(tier="SUSPICIOUS", verdicts=[v("known_good")], **{**BASE, **override})
    assert out.tier == "SUSPICIOUS"


def test_known_good_never_downgrades_critical():
    assert apply_intel(tier="CRITICAL", verdicts=[v("known_good")], **BASE).tier == "CRITICAL"


def test_suspicious_intel_lifts_safe_only():
    assert apply_intel(tier="SAFE", verdicts=[v("suspicious")], **BASE).tier == "SUSPICIOUS"
    assert apply_intel(tier="CRITICAL", verdicts=[v("suspicious")], **BASE).tier == "CRITICAL"


# ---- safety rules enforced by tests ----------------------------------------------------------
def test_source_never_disables_tls_verification_or_downloads_samples():
    sources = {p: p.read_text() for p in BACKEND_APP.rglob("*.py")}
    for path, text in sources.items():
        assert not re.search(r"verify\s*=\s*False", text), f"{path} disables TLS verification"
        assert not re.search(r"[\"']get_file[\"']", text), f"{path} would download samples"


# ---- the enrichment pipeline itself ----------------------------------------------------------
def scanned(**over):
    base = {"event_id": "e" * 32, "scan_id": "s", "drive": "Z:\\", "filename": "eicar.com", "sha256": EICAR,
            "size_bytes": 68, "tier": "SAFE", "likelihood": 1, "impact": 2, "reasons": ["No indicators found"],
            "mitre": [], "rtlo": False, "entropy": 4.7, "magic_type": "unknown / text"}
    return {**base, **over}


@respx.mock(assert_all_called=False)
async def test_known_good_corpus_hit_does_not_hide_a_malicious_verdict(monkeypatch, respx_mock):
    """EICAR is in NSRL (known_good) AND flagged by 65 engines: malicious must win."""
    svc = make_service(monkeypatch, mb="")
    published = []
    svc._publish = published.append
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(200, json={"FileName": "eicar.com", "source": "NSRL"}))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(200, json=vt_json(65, undetected=9)))
    await svc._enrich(scanned())
    assert vt.call_count == 1  # not short-circuited by the known-good hit
    ev = published[0]
    assert (ev.previous_tier, ev.tier, ev.risk_score) == ("SAFE", "CRITICAL", 25)
    assert ev.known_good is True and "virustotal" in ev.reasons[0]
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_known_good_entropy_only_alert_skips_vt_and_downgrades(monkeypatch, respx_mock):
    svc = make_service(monkeypatch, mb="")
    published = []
    svc._publish = published.append
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(200, json={"FileName": "x.dat", "source": "NSRL"}))
    vt = respx_mock.get(VT_URL).mock(return_value=httpx.Response(404))
    await svc._enrich(scanned(filename="blob.dat", tier="SUSPICIOUS", likelihood=3, impact=3, entropy=7.9,
                              reasons=["High Shannon entropy (7.90 > 7.2)"]))
    assert vt.call_count == 0  # quota saved
    assert (published[0].previous_tier, published[0].tier) == ("SUSPICIOUS", "SAFE")
    assert "Downgraded" in published[0].reasons[0]
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_safe_text_file_is_never_sent_to_the_network(monkeypatch, respx_mock):
    svc = make_service(monkeypatch)
    published = []
    svc._publish = published.append
    anything = respx_mock.route().mock(return_value=httpx.Response(500))
    await svc._enrich(scanned(filename="notes.txt", sha256="aa" * 32))
    assert anything.call_count == 0 and published == []
    await svc.stop()


@respx.mock(assert_all_called=False)
async def test_enrichment_is_saved_off_the_event_loop(monkeypatch, respx_mock):
    """save_enrichment (SQLite) must run in a worker thread, never on the loop thread."""
    import asyncio
    import threading

    class SpyAudit:
        calls: list[tuple[int, str, str]] = []

        def save_enrichment(self, file_event_id, scan_id, payload):
            self.calls.append((threading.get_ident(), file_event_id, scan_id))

    svc = make_service(monkeypatch, mb="")
    svc.audit = spy = SpyAudit()
    svc._publish = lambda event: None
    respx_mock.get(CIRCL_URL).mock(return_value=httpx.Response(404))
    respx_mock.get(VT_URL).mock(return_value=httpx.Response(200, json=vt_json(65, undetected=9)))
    loop_thread = threading.get_ident()
    await svc._enrich(scanned())
    assert len(spy.calls) == 1 and spy.calls[0][1:] == ("e" * 32, "s")
    assert spy.calls[0][0] != loop_thread
    assert asyncio.get_running_loop() is not None
    await svc.stop()
