"""Tests for blue.esp_sensor — serial + HTTP ingest are mocked with the EXACT
ESP JSON schemas; NO hardware, no real serial port, no network."""
from __future__ import annotations

import json

from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.log import get_logger
from core.schema import RunResult, utcnow_iso
from core.store import Store
from plugins.blue import esp_sensor as mod
from plugins.blue.esp_sensor import EspSensor

# --- EXACT ESP schema samples (from esp32/README.md) ----------------------
DET_AGG = ('{"t":"detection","type":"deauth_flood_aggregate","severity":"critical",'
           '"mac":"","ssid":"","channel":6,"uptime_ms":48213,'
           '"evidence":"aggregate deauth/disassoc=42 in 1000ms (thr 30)"}')
DET_SRC = ('{"t":"detection","type":"deauth_flood_src","severity":"high",'
           '"mac":"DE:AD:BE:EF:00:01","ssid":"","channel":6,"uptime_ms":48100,'
           '"evidence":"deauth/disassoc from src=14 in 1000ms (thr 10)"}')
DET_TWIN = ('{"t":"detection","type":"evil_twin","severity":"high",'
            '"mac":"AA:BB:CC:00:11:22","ssid":"CampusWiFi","channel":6,'
            '"uptime_ms":41002,"evidence":"SSID advertised by 2 BSSIDs (thr 2)"}')
HB = ('{"t":"heartbeat","mode":"sniffer","channel":6,"uptime_ms":50000,'
      '"frames_seen":1234,"dropped":0,"wifi_connected":false,"detections_total":3}')
HB_LATE = ('{"t":"heartbeat","mode":"sniffer","channel":6,"uptime_ms":55000,'
           '"frames_seen":1500,"dropped":2,"wifi_connected":false,"detections_total":4}')
BOOT = '{"t":"boot","sensor":"sentinel-esp32-s3","role":"wifi-attack-detection"}'
UNKNOWN_DET = ('{"t":"detection","type":"nonsense_x","severity":"high","mac":"X",'
               '"ssid":"","channel":1,"uptime_ms":1,"evidence":"e"}')


def make_ctx(tmp_path, **cfg_over):
    cfg = Config(root=tmp_path)
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    run = RunResult(run_id="t", workflow="esp_monitor", target="", started_at=utcnow_iso())
    store = Store(run, tmp_path / "t.json")
    return RunContext(target="", workflow="esp_monitor", config=cfg, store=store,
                      log=get_logger("sentinel.test"), hw=build_hardware(cfg),
                      events=EventBus())


def _serial(monkeypatch, lines):
    monkeypatch.setattr(mod, "_iter_serial_lines",
                        lambda port, baud, duration: iter(list(lines)))


def _esp_asset(ctx):
    return next(a for a in ctx.store.assets() if a.kind == "esp_sensor")


# --- detections -> findings ------------------------------------------------
def test_detections_parse_into_findings_with_severities(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    _serial(monkeypatch, [BOOT, DET_AGG, DET_SRC, DET_TWIN, HB])
    EspSensor().run(ctx)
    dets = [f for f in ctx.store.findings() if f.type in mod.DETECTION_TYPES]
    sev = {f.type: f.severity for f in dets}
    assert sev == {"deauth_flood_aggregate": "critical",
                   "deauth_flood_src": "high", "evil_twin": "high"}
    # offender MAC becomes the target; SSID preserved in detail
    src = next(f for f in dets if f.type == "deauth_flood_src")
    assert src.target == "DE:AD:BE:EF:00:01"
    twin = next(f for f in dets if f.type == "evil_twin")
    assert "CampusWiFi" in twin.detail
    # ESP relative uptime is kept in evidence/detail, NOT used as the finding time
    assert "uptime_ms=48100" in src.evidence
    assert src.timestamp and src.timestamp.endswith("Z")


def test_heartbeats_update_status_without_findings(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    _serial(monkeypatch, [HB, HB_LATE])          # heartbeats only
    EspSensor().run(ctx)
    assert ctx.store.findings() == []            # heartbeats never create findings
    esp = _esp_asset(ctx)
    assert esp.alive is True
    assert esp.extra["mode"] == "sniffer"
    assert esp.extra["frames_seen"] == 1500      # latest heartbeat wins
    assert esp.extra["heartbeats"] == 2
    assert esp.extra["detections_total"] == 4


def test_identical_detections_deduped_into_one_with_count(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    _serial(monkeypatch, [DET_SRC] * 50)
    EspSensor().run(ctx)
    dets = [f for f in ctx.store.findings() if f.type == "deauth_flood_src"]
    assert len(dets) == 1                        # a flood -> one finding, not 50
    assert "50x" in dets[0].evidence
    assert "50 occurrence" in dets[0].detail


def test_distinct_detections_not_collapsed(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    _serial(monkeypatch, [DET_SRC, DET_AGG, DET_TWIN])
    EspSensor().run(ctx)
    dets = [f for f in ctx.store.findings() if f.type in mod.DETECTION_TYPES]
    assert len(dets) == 3                        # different (type,mac,channel) keys


def test_busy_serial_port_handled_gracefully(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)

    def busy(port, baud, duration):
        raise mod.PortBusy("could not open /dev/ttyACM0: [Errno 11] busy")

    monkeypatch.setattr(mod, "_iter_serial_lines", busy)
    EspSensor().run(ctx)                          # must NOT raise or hang
    busyf = [f for f in ctx.store.findings() if f.type == "esp_sensor_busy"]
    assert len(busyf) == 1 and "busy" in busyf[0].title.lower()
    assert [f for f in ctx.store.findings() if f.type in mod.DETECTION_TYPES] == []
    assert _esp_asset(ctx).extra["busy"] is True
    assert _esp_asset(ctx).alive is False


def test_malformed_lines_skipped(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    _serial(monkeypatch, ["not json {{{", "", "   ", "garbage", UNKNOWN_DET, DET_SRC])
    EspSensor().run(ctx)                          # must NOT raise
    dets = [f for f in ctx.store.findings() if f.type in mod.DETECTION_TYPES]
    assert len(dets) == 1 and dets[0].type == "deauth_flood_src"
    assert _esp_asset(ctx).extra["malformed_lines"] >= 3


# --- HTTP transport --------------------------------------------------------
def test_http_transport_ingests_status_and_detections(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, esp_url="http://esp.local", esp_listen_seconds=0)
    status = {"uptime_ms": 5, "mode": "connected", "channel": 6, "frames_seen": 10,
              "dropped": 0, "wifi_connected": True, "detections_total": 1}
    detobj = json.loads(DET_TWIN)

    def fake_get(base, path, timeout):
        assert base == "http://esp.local"
        if path == "/status":
            return status
        if path == "/detections":
            return {"count": 1, "detections": [detobj]}
        return None

    monkeypatch.setattr(mod, "_http_get_json", fake_get)
    EspSensor().run(ctx)
    dets = [f for f in ctx.store.findings() if f.type == "evil_twin"]
    assert len(dets) == 1
    esp = _esp_asset(ctx)
    assert esp.extra["transport"] == "http"
    assert esp.extra["mode"] == "connected"
    assert esp.alive is True


# --- availability ----------------------------------------------------------
def test_is_available_on_serial_presence(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    monkeypatch.setattr(mod, "_serial_present", lambda p: True)
    monkeypatch.setattr(mod, "_import_serial", lambda: object())
    monkeypatch.setattr(mod, "_can_access", lambda p: True)
    ok, reason = EspSensor().is_available(ctx)
    assert ok and reason == ""


def test_is_available_dialout_message(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    monkeypatch.setattr(mod, "_serial_present", lambda p: True)
    monkeypatch.setattr(mod, "_import_serial", lambda: object())
    monkeypatch.setattr(mod, "_can_access", lambda p: False)
    monkeypatch.setattr(mod, "_in_group", lambda g: False)
    ok, reason = EspSensor().is_available(ctx)
    assert not ok and "dialout" in reason


def test_is_available_on_http(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, esp_url="http://esp.local")
    monkeypatch.setattr(mod, "_serial_present", lambda p: False)
    monkeypatch.setattr(mod, "_http_get_json",
                        lambda base, path, timeout: {"mode": "connected"})
    ok, reason = EspSensor().is_available(ctx)
    assert ok and reason == ""


def test_is_available_absent(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    monkeypatch.setattr(mod, "_serial_present", lambda p: False)
    ok, reason = EspSensor().is_available(ctx)
    assert not ok and "not present" in reason
