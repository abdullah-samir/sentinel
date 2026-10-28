"""Tests for red.wifi_scan — airodump-ng output and interface detection are
mocked; NO live radio, no real monitor-mode changes, no subprocess to a radio."""
from __future__ import annotations

import subprocess

from core import registry
from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.log import get_logger
from core.schema import RunResult, utcnow_iso
from core.store import Store
from core.workflows import load_workflows
from plugins.red import wifi_scan as mod
from plugins.red.wifi_scan import WifiScan, _parse_airodump_csv


# A realistic airodump-ng CSV: an AP table then a station table. One WPA2, one
# OPEN, one WEP, one WPA2 with WPS=1, plus two clients (one unassociated).
SAMPLE_CSV = (
    "\r\n"
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key, WPS\r\n"
    "AA:AA:AA:AA:AA:01, 2026-10-28 10:00:00, 2026-10-28 10:05:00, 6, 54, WPA2, CCMP, "
    "PSK, -40, 120, 0, 0.0.0.0, 7, HomeNet, , 0\r\n"
    "AA:AA:AA:AA:AA:02, 2026-10-28 10:00:00, 2026-10-28 10:05:00, 11, 54, OPN, , , "
    "-55, 80, 0, 0.0.0.0, 8, FreeWiFi, , 0\r\n"
    "AA:AA:AA:AA:AA:03, 2026-10-28 10:00:00, 2026-10-28 10:05:00, 1, 11, WEP, WEP, , "
    "-60, 40, 12, 0.0.0.0, 6, OldNet, , 0\r\n"
    "AA:AA:AA:AA:AA:04, 2026-10-28 10:00:00, 2026-10-28 10:05:00, 6, 54, WPA2, CCMP, "
    "PSK, -45, 95, 0, 0.0.0.0, 7, RouterX, , 1\r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "CC:CC:CC:CC:CC:01, 2026-10-28 10:01:00, 2026-10-28 10:05:00, -50, 22, "
    "AA:AA:AA:AA:AA:01, HomeNet\r\n"
    "CC:CC:CC:CC:CC:02, 2026-10-28 10:02:00, 2026-10-28 10:05:00, -70, 6, "
    "(not associated), SomeProbe\r\n"
)


def make_ctx(tmp_path, **cfg_over):
    cfg = Config(root=tmp_path)
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    run = RunResult(run_id="t", workflow="wifi_scan", target="", started_at=utcnow_iso())
    store = Store(run, tmp_path / "t.json")
    ctx = RunContext(target="", workflow="wifi_scan", config=cfg, store=store,
                     log=get_logger("sentinel.test"), hw=build_hardware(cfg),
                     events=EventBus())
    return ctx


def wire(monkeypatch, iface="wlan1", default_if="wlan0", ssh_if="",
         driver="rtl8188eus", monitor=True, airodump=None):
    """Patch all host-touching helpers so run()/is_available() are hermetic.
    Returns the list that records every iw/ip command issued."""
    cmds = []
    monkeypatch.setattr(mod, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(mod, "detect_adapter", lambda cfg: iface)
    monkeypatch.setattr(mod, "_default_route_iface", lambda: default_if)
    monkeypatch.setattr(mod, "_ssh_iface", lambda: ssh_if)
    monkeypatch.setattr(mod, "_iface_driver", lambda i: driver)
    monkeypatch.setattr(mod, "_supports_monitor", lambda i: monitor)
    monkeypatch.setattr(mod, "_run_cmd", lambda args, timeout=10: (cmds.append(list(args)) or (0, "")))
    if airodump is not None:
        monkeypatch.setattr(WifiScan, "_run_airodump", airodump)
    return cmds


def _fake_airodump(csv_text, capture):
    """Return a _run_airodump replacement that writes `csv_text` to the outdir
    (so the real _read_csv parses it) and records the outdir for cleanup asserts."""
    def _run(self, ctx, iface, outdir, duration, channel):
        capture["outdir"] = outdir
        (outdir / "scan-01.csv").write_text(csv_text, encoding="utf-8")
        # a .kismet.csv and .cap are also written by real airodump; _read_csv must skip them
        (outdir / "scan-01.kismet.csv").write_text("ignore me", encoding="utf-8")
        (outdir / "scan-01.cap").write_bytes(b"\0\0")
    return _run


# --- parser ---------------------------------------------------------------
def test_parse_airodump_csv():
    aps, clients = _parse_airodump_csv(SAMPLE_CSV)
    assert len(aps) == 4 and len(clients) == 2
    by_bssid = {a["bssid"]: a for a in aps}
    assert by_bssid["AA:AA:AA:AA:AA:01"]["encryption"] == "WPA2"
    assert by_bssid["AA:AA:AA:AA:AA:01"]["essid"] == "HomeNet"
    assert by_bssid["AA:AA:AA:AA:AA:01"]["channel"] == "6"
    assert by_bssid["AA:AA:AA:AA:AA:01"]["signal"] == "-40"
    assert by_bssid["AA:AA:AA:AA:AA:02"]["encryption"] == "OPEN"   # OPN normalised
    assert by_bssid["AA:AA:AA:AA:AA:03"]["encryption"] == "WEP"
    assert by_bssid["AA:AA:AA:AA:AA:04"]["wps"] is True
    assert by_bssid["AA:AA:AA:AA:AA:01"]["wps"] is False
    assert clients[0]["mac"] == "CC:CC:CC:CC:CC:01"
    assert clients[0]["bssid"] == "AA:AA:AA:AA:AA:01"


def test_parse_empty_is_safe():
    assert _parse_airodump_csv("") == ([], [])
    assert _parse_airodump_csv("garbage\nlines\n") == ([], [])


# --- full run: assets + findings ------------------------------------------
def test_run_emits_assets_and_findings(tmp_path, monkeypatch):
    cap = {}
    wire(monkeypatch, airodump=_fake_airodump(SAMPLE_CSV, cap))
    ctx = make_ctx(tmp_path, wifi_scan_seconds=3)
    WifiScan().run(ctx)

    assets = ctx.store.assets()
    aps = [a for a in assets if a.kind == "wifi_ap"]
    clients = [a for a in assets if a.kind == "wifi_client"]
    assert len(aps) == 4 and len(clients) == 2
    home = next(a for a in aps if a.ip == "AA:AA:AA:AA:AA:01")
    assert home.ssid == "HomeNet" and home.channel == "6"
    assert home.encryption == "WPA2" and home.signal == "-40" and home.alive

    findings = ctx.store.findings()
    types = sorted(f.type for f in findings)
    assert "wifi_open" in types and "wifi_wep" in types and "wifi_wps" in types
    sev = {f.type: f.severity for f in findings}
    assert sev["wifi_open"] == "medium" and sev["wifi_wep"] == "medium"
    assert sev["wifi_wps"] == "low"
    # no finding for the plain WPA2 AP (AA:01); WPA2+WPS (AA:04) only yields a wps finding
    assert not any(f.target == "AA:AA:AA:AA:AA:01" for f in findings)


# --- monitor enable/restore + cleanup + no airmon-ng ----------------------
def test_monitor_enable_and_restore_called(tmp_path, monkeypatch):
    cap = {}
    cmds = wire(monkeypatch, iface="wlan1", airodump=_fake_airodump(SAMPLE_CSV, cap))
    WifiScan().run(make_ctx(tmp_path, wifi_scan_seconds=2))
    assert ["iw", "dev", "wlan1", "set", "type", "monitor"] in cmds      # enabled
    assert ["iw", "dev", "wlan1", "set", "type", "managed"] in cmds      # restored
    assert not cap["outdir"].exists()                                    # temp files cleaned


def test_restore_runs_even_when_scan_raises(tmp_path, monkeypatch):
    cap = {}

    def boom(self, ctx, iface, outdir, duration, channel):
        cap["outdir"] = outdir
        (outdir / "scan-01.csv").write_text("partial", encoding="utf-8")
        raise RuntimeError("radio exploded")

    cmds = wire(monkeypatch, iface="wlan1", airodump=boom)
    ctx = make_ctx(tmp_path, wifi_scan_seconds=2)
    WifiScan().run(ctx)                                 # must NOT propagate
    assert ["iw", "dev", "wlan1", "set", "type", "managed"] in cmds      # restored on error
    assert not cap["outdir"].exists()                                   # cleaned on error
    assert any(f.type == "module_error" for f in ctx.store.findings())


def test_never_invokes_airmon_ng(tmp_path, monkeypatch):
    cap = {}
    cmds = wire(monkeypatch, airodump=_fake_airodump(SAMPLE_CSV, cap))
    WifiScan().run(make_ctx(tmp_path, wifi_scan_seconds=2))
    flat = " ".join(tok for c in cmds for tok in c)
    assert "airmon-ng" not in flat and "check kill" not in flat


class _FakeProc:
    """Mimics airodump running until we SIGTERM it at the duration boundary."""
    def __init__(self):
        self._terminated = False

    def wait(self, timeout=None):
        if not self._terminated:
            raise subprocess.TimeoutExpired("airodump-ng", timeout)
        return 0

    def terminate(self):
        self._terminated = True

    def kill(self):
        self._terminated = True


def test_airodump_args_are_passive(tmp_path, monkeypatch):
    """The real _run_airodump must build a PASSIVE airodump-ng command — no
    deauth/injection, no airmon/aireplay — writing only CSV."""
    recorded = {}

    def fake_popen(args, **kw):
        recorded["args"] = list(args)
        return _FakeProc()

    monkeypatch.setattr(mod.subprocess, "Popen", fake_popen)
    ctx = make_ctx(tmp_path)
    WifiScan()._run_airodump(ctx, "wlan1", tmp_path, duration=1, channel="6")
    args = recorded["args"]
    assert args[0] == "airodump-ng" and args[-1] == "wlan1"
    assert "--output-format" in args and "csv" in args
    assert args[args.index("-c") + 1] == "6"                 # channel lock passed through
    flat = " ".join(args)
    for forbidden in ("--deauth", "-0", "aireplay", "airmon", "--inj", "attack"):
        assert forbidden not in flat


# --- self-lockout guard ---------------------------------------------------
def test_refuses_default_route_interface(tmp_path, monkeypatch):
    cmds = wire(monkeypatch, iface="wlan1", default_if="wlan1")      # adapter == uplink
    ctx = make_ctx(tmp_path)
    WifiScan().run(ctx)
    # refused before any monitor-mode change
    assert not any("monitor" in c for c in cmds)
    skips = [f for f in ctx.store.findings() if f.type == "module_status"]
    assert skips and "default route" in skips[0].detail


def test_refuses_ssh_interface(tmp_path, monkeypatch):
    cmds = wire(monkeypatch, iface="wlan1", default_if="wlan0", ssh_if="wlan1")
    ctx = make_ctx(tmp_path)
    WifiScan().run(ctx)
    assert not any("monitor" in c for c in cmds)
    skips = [f for f in ctx.store.findings() if f.type == "module_status"]
    assert skips and "SSH" in skips[0].detail


# --- is_available both branches -------------------------------------------
def test_is_available_true(tmp_path, monkeypatch):
    wire(monkeypatch, iface="wlan1", default_if="wlan0", driver="rtl8188eus", monitor=True)
    ok, reason = WifiScan().is_available(make_ctx(tmp_path))
    assert ok and reason == ""


def test_is_available_no_airodump(tmp_path, monkeypatch):
    wire(monkeypatch)
    monkeypatch.setattr(mod, "which", lambda name: None)
    ok, reason = WifiScan().is_available(make_ctx(tmp_path))
    assert not ok and "airodump-ng" in reason


def test_is_available_no_adapter(tmp_path, monkeypatch):
    wire(monkeypatch, iface=None)
    ok, reason = WifiScan().is_available(make_ctx(tmp_path))
    assert not ok and "no RTL8188EUS" in reason


def test_is_available_wrong_driver(tmp_path, monkeypatch):
    wire(monkeypatch, iface="wlan1", default_if="wlan0", driver="rtl8xxxu")
    ok, reason = WifiScan().is_available(make_ctx(tmp_path))
    assert not ok and "rtl8xxxu" in reason and "rtl8188eus" in reason


def test_is_available_refuses_self_link(tmp_path, monkeypatch):
    wire(monkeypatch, iface="wlan1", default_if="wlan1")
    ok, reason = WifiScan().is_available(make_ctx(tmp_path))
    assert not ok and "self-lockout" in reason


# --- detection never assumes wlan1 by name --------------------------------
def test_detect_adapter_ignores_default_pin_without_chipset(tmp_path, monkeypatch):
    # wlan1 present but NOT an RTL8188EUS, and only the baked-in default names it:
    monkeypatch.delenv("SENTINEL_WIFI_IFACE", raising=False)
    monkeypatch.setattr(mod, "_wifi_interfaces", lambda: ["wlan0", "wlan1"])
    monkeypatch.setattr(mod, "_default_route_iface", lambda: "wlan0")
    monkeypatch.setattr(mod, "_is_rtl8188eus", lambda i: False)
    cfg = Config(root=tmp_path)                       # wifi_iface defaults to "wlan1"
    assert mod.detect_adapter(cfg) is None            # not assumed by name

    # but a real RTL8188EUS (by chipset) IS detected, skipping the uplink
    monkeypatch.setattr(mod, "_is_rtl8188eus", lambda i: i == "wlan1")
    assert mod.detect_adapter(cfg) == "wlan1"


def test_explicit_env_pin_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WIFI_IFACE", "wlan7")
    monkeypatch.setattr(mod, "_wifi_interfaces", lambda: ["wlan0", "wlan7"])
    monkeypatch.setattr(mod, "_is_rtl8188eus", lambda i: False)
    assert mod.detect_adapter(Config(root=tmp_path)) == "wlan7"


# --- registration / workflow ----------------------------------------------
def test_module_registered_and_workflow_references_it(tmp_path):
    mods = registry.discover(force=True)
    assert "red.wifi_scan" in mods
    assert mods["red.wifi_scan"].manifest.category == "red"
    assert mods["red.wifi_scan"].manifest.requires_hw == ["wifi_monitor"]
    assert mods["red.wifi_scan"].manifest.offensive is False      # passive, not gated
    wfs = load_workflows(Config())
    assert "wifi_scan" in wfs and wfs["wifi_scan"]["steps"] == ["red.wifi_scan"]
