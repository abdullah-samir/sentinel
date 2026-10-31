"""Unit tests for dashboard.discovery — on-demand Wi-Fi/nmap sweeps, the
single-adapter fallback for background mode, and the background monitor. No real
radios/nmap: airodump/set-mode/nmap runners are injected."""
from __future__ import annotations

from core import state as core_state
from core.config import Config
from core.state import InterfaceRegistry
from dashboard import discovery as disc
from dashboard import interfaces as ifm

CSV = (
    "\r\nBSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "AA:BB:CC:DD:EE:01, t, t, 6, 54, WPA2, CCMP, PSK, -40, 10, 0, 0.0.0.0, 5, Net1, \r\n"
    "\r\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "11:22:33:44:55:66, t, t, -50, 5, AA:BB:CC:DD:EE:01, \r\n"
)


def _reg(tmp_path):
    return InterfaceRegistry(tmp_path / "data" / "state" / "interfaces.json")


def _wlan(iface, selectable=True, busy=False, holder="", unsafe=False, capable=True):
    return {"iface": iface, "selectable": selectable, "busy": busy, "holder": holder,
            "unsafe": unsafe, "capable": capable, "note": ""}


def _choices(rows):
    def _f(config, registry, default=""):
        return list(rows)
    return _f


# --- clamp (settable duration bounds) -------------------------------------
def test_clamp_seconds():
    assert disc.clamp_seconds(99) == 99
    assert disc.clamp_seconds(9999) == 120
    assert disc.clamp_seconds(0) == 1
    assert disc.clamp_seconds("abc") == disc.DISCOVERY_DEFAULT_SECONDS


# --- Wi-Fi discovery: claim -> sweep -> release -> restore managed --------
def test_discover_wifi_claims_sweeps_releases_restores(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices", _choices([_wlan("wlan1")]))
    monkeypatch.setattr(core_state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(core_state, "ssh_iface", lambda: "")
    reg = _reg(tmp_path)
    seen = {}

    def fake_airodump(iface, outdir, seconds):
        seen["seconds"] = seconds
        seen["busy_during"] = reg.busy_reason(iface, "someone-else")  # busy mid-sweep
        (outdir / "disc-01.csv").write_text(CSV, encoding="utf-8")

    modes = []

    def fake_setmode(iface, mode):
        modes.append(mode)
        return (True, f"{iface} {mode}")

    res = disc.discover_wifi(Config(root=tmp_path), reg, seconds=7,
                             airodump_fn=fake_airodump, set_mode_fn=fake_setmode)
    assert res["ok"] and res["iface"] == "wlan1"
    assert seen["seconds"] == 7                       # settable duration respected
    assert seen["busy_during"] != ""                  # claimed during the sweep
    assert modes == ["monitor", "managed"]            # set monitor, restored managed
    assert reg.busy_reason("wlan1", "x") == ""        # released afterwards
    assert any(t["kind"] == "ap" and t["value"] == "AA:BB:CC:DD:EE:01"
               for t in res["targets"])
    assert any(t["kind"] == "client" for t in res["targets"])


def test_discover_wifi_releases_on_error(tmp_path, monkeypatch):
    """An abandoned/failed sweep still restores managed and releases the radio."""
    monkeypatch.setattr(ifm, "monitor_interface_choices", _choices([_wlan("wlan1")]))
    monkeypatch.setattr(core_state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(core_state, "ssh_iface", lambda: "")
    reg = _reg(tmp_path)
    modes = []

    def boom(iface, outdir, seconds):
        raise RuntimeError("radio died")

    res = disc.discover_wifi(Config(root=tmp_path), reg, seconds=5, airodump_fn=boom,
                             set_mode_fn=lambda i, m: (modes.append(m) or (True, "")))
    assert not res["ok"] and "radio died" in res["error"]
    assert "managed" in modes                         # restored despite the error
    assert reg.busy_reason("wlan1", "x") == ""        # released despite the error


def test_discover_wifi_no_free_adapter(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices",
                        _choices([_wlan("wlan1", selectable=False, busy=True,
                                        holder="Wi-Fi scan / Full Audit")]))
    res = disc.discover_wifi(Config(root=tmp_path), _reg(tmp_path), seconds=5,
                             airodump_fn=lambda *a: None, set_mode_fn=lambda *a: (True, ""))
    assert not res["ok"] and "no free monitor" in res["error"]


# --- nmap -sn host discovery ----------------------------------------------
def test_discover_hosts_parses_live_hosts():
    out = ("Nmap scan report for 10.0.0.1\nHost is up\n"
           "Nmap scan report for gw.lan (10.0.0.254)\nHost is up\n"
           "Nmap scan report for 10.0.0.1\n")      # duplicate ignored
    res = disc.discover_hosts("10.0.0.0/24", 5, runner=lambda s, sec: (0, out))
    assert res["ok"]
    assert [t["value"] for t in res["targets"]] == ["10.0.0.1", "10.0.0.254"]


def test_discover_hosts_invalid_subnet():
    res = disc.discover_hosts("not-a-subnet", 5, runner=lambda s, sec: (0, ""))
    assert not res["ok"] and "invalid" in res["error"]


def test_discover_hosts_nmap_missing():
    res = disc.discover_hosts("10.0.0.0/24", 5, runner=lambda s, sec: (127, "nmap not installed"))
    assert not res["ok"]


# --- mode (b) fallback with one adapter -----------------------------------
def test_background_falls_back_to_on_demand_with_one_adapter(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices", _choices([_wlan("wlan1")]))
    mode, note = disc.effective_discovery_mode("background", Config(root=tmp_path),
                                               _reg(tmp_path))
    assert mode == "on_demand" and "second monitor adapter" in note


def test_background_active_with_two_adapters(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices",
                        _choices([_wlan("wlan1"), _wlan("wlan2")]))
    mode, note = disc.effective_discovery_mode("background", Config(root=tmp_path),
                                               _reg(tmp_path))
    assert mode == "background" and note == ""


def test_on_demand_mode_has_no_note(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices", _choices([_wlan("wlan1")]))
    mode, note = disc.effective_discovery_mode("on_demand", Config(root=tmp_path),
                                               _reg(tmp_path))
    assert mode == "on_demand" and note == ""


# --- background monitor dedicates one adapter, leaves the other free ------
def test_background_monitor_dedicates_one_and_refreshes(tmp_path, monkeypatch):
    monkeypatch.setattr(ifm, "monitor_interface_choices",
                        _choices([_wlan("wlan1"), _wlan("wlan2")]))
    reg = _reg(tmp_path)
    clock = {"t": 1000.0}
    sweeps = {"n": 0}

    def sweep(iface, seconds):
        sweeps["n"] += 1
        return {"targets": [{"kind": "ap", "value": "AA", "display": "AA"}]}

    bm = disc.BackgroundMonitor(Config(root=tmp_path), reg, sweep_fn=sweep,
                                clock=lambda: clock["t"])
    s1 = bm.refresh(5)
    assert s1["active"] and s1["iface"] in ("wlan1", "wlan2")
    dedicated = s1["iface"]
    other = "wlan2" if dedicated == "wlan1" else "wlan1"
    assert reg.busy_reason(dedicated, "x") != ""      # dedicated one held (busy)
    assert reg.busy_reason(other, "x") == ""          # the other left free
    assert sweeps["n"] == 1 and s1["targets"]

    bm.refresh(5)
    assert sweeps["n"] == 1                            # still fresh -> no re-sweep
    clock["t"] += disc.BACKGROUND_STALE_S + 1
    bm.refresh(5)
    assert sweeps["n"] == 2                            # stale -> re-sweeps

    bm.stop()
    assert reg.busy_reason(dedicated, "x") == ""       # released on stop
