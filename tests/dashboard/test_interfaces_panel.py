"""Read-only interfaces panel + startup reservation reset (FastAPI TestClient).

The host (sysfs / iw / lsusb / ip) is fully stubbed so these are deterministic
and never touch a real adapter."""
from __future__ import annotations

import os
import re
import subprocess

from fastapi.testclient import TestClient

from core import state as core_state
from core.config import Config
from core.state import InterfaceRegistry
from dashboard import interfaces as interfaces_mod
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text("wifi_scan: { steps: [red.wifi_scan] }\n",
                                       encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                follow_redirects=False)


def stub_host(monkeypatch, forbid_iw_on=None):
    """Three interfaces: eth0 (built-in uplink), wlan0 (built-in Wi-Fi),
    wlan1 (USB Wi-Fi monitor adapter). iw must never be probed on a busy iface."""
    monkeypatch.setattr(interfaces_mod, "present_interfaces",
                        lambda: ["eth0", "lo", "wlan0", "wlan1"])
    monkeypatch.setattr(interfaces_mod, "is_wifi", lambda i: i.startswith("wlan"))
    monkeypatch.setattr(interfaces_mod, "is_usb", lambda i: i == "wlan1")
    monkeypatch.setattr(interfaces_mod, "iface_driver",
                        lambda i: {"eth0": "bcmgenet", "wlan0": "brcmfmac",
                                   "wlan1": "8188eu"}.get(i, ""))
    monkeypatch.setattr(interfaces_mod, "operstate", lambda i: "up")

    def _iw(i):
        if forbid_iw_on and i == forbid_iw_on:
            raise AssertionError(f"iw must NOT be run against busy interface {i}")
        return "managed"

    monkeypatch.setattr(interfaces_mod, "iw_mode", _iw)
    monkeypatch.setattr(interfaces_mod, "supports_monitor", lambda i: True)
    monkeypatch.setattr(core_state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(core_state, "ssh_iface", lambda: "")


def login_csrf(client):
    """Log in and return a usable CSRF token (for POST routes)."""
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                follow_redirects=False)
    return csrf


def test_interfaces_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    r = TestClient(app).get("/interfaces", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_api_interfaces_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    assert TestClient(app).get("/api/interfaces").status_code == 401


def test_interfaces_panel_renders_free_state(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    r = c.get("/interfaces")
    assert r.status_code == 200
    body = r.text
    assert "wlan1" in body and "8188eu" in body         # the USB monitor adapter
    assert "USB" in body and "built-in" in body
    assert "uplink" in body                             # eth0 flagged default-route
    assert "free" in body                               # nothing reserved
    assert "lo" not in re.findall(r"<td class=\"mono\">(\w+)", body)  # loopback skipped


def test_interfaces_panel_shows_busy_reservation(tmp_path, monkeypatch):
    # wlan1 is reserved in monitor mode -> panel must label it from the
    # reservation and must NOT probe it with iw.
    stub_host(monkeypatch, forbid_iw_on="wlan1")
    _, _, app = make_env(tmp_path)
    # busy attribution: the friendly holder label is shown, never the raw run_id
    app.state.iface_registry.claim("wlan1", "run-xyz-123", "monitor",
                                   label="Wi-Fi scan / Full Audit")
    c = TestClient(app)
    login(c)
    r = c.get("/interfaces")
    assert r.status_code == 200
    body = r.text
    assert "busy" in body
    assert "Wi-Fi scan / Full Audit" in body            # friendly holder name
    assert "run-xyz-123" not in body                    # raw run_id never surfaced
    assert "monitor" in body                            # mode from the reservation


def test_interfaces_panel_is_read_only(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path)
    reg = app.state.iface_registry
    reg.claim("wlan1", "run-abc", "monitor")
    before = reg.reservations()
    c = TestClient(app)
    login(c)
    # both the page and the JSON poll are pure reads
    assert c.get("/interfaces").status_code == 200
    assert c.get("/api/interfaces").status_code == 200
    after = reg.reservations()
    assert set(before) == set(after)                    # panel never claimed/released
    assert after["wlan1"]["run_id"] == "run-abc"


def test_api_interfaces_returns_rows(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    data = c.get("/api/interfaces").json()
    names = {row["iface"] for row in data["interfaces"]}
    assert names == {"eth0", "wlan0", "wlan1"}          # lo excluded
    wlan1 = next(r for r in data["interfaces"] if r["iface"] == "wlan1")
    assert wlan1["usb"] is True and wlan1["wifi"] is True and wlan1["driver"] == "8188eu"
    eth0 = next(r for r in data["interfaces"] if r["iface"] == "eth0")
    assert eth0["default_route"] is True


# --- startup reservation reset is wired into create_app -------------------
def test_startup_reset_frees_dead_keeps_live(tmp_path):
    # Pre-seed the persisted registry BEFORE the app starts: one reservation
    # from a dead process, one from this (live) process.
    dead = subprocess.Popen(["true"]); dead.wait()
    path = tmp_path / "data" / "state" / "interfaces.json"
    seed = InterfaceRegistry(path)
    with seed.lock:
        seed._res["wlan1"] = {"mode": "monitor", "run_id": "dead-run",
                              "pid": dead.pid, "ts": "t"}
        seed._res["wlan2"] = {"mode": "monitor", "run_id": "live-run",
                              "pid": os.getpid(), "ts": "t"}
        seed._save()

    _, _, app = make_env(tmp_path)                       # create_app -> reset_dead()
    res = app.state.iface_registry.reservations()
    assert "wlan1" not in res                            # dead run's reservation freed
    assert "wlan2" in res                                # live run's reservation kept


# --- Part B COMMIT 1: scan interface picker -------------------------------
def test_scan_picker_lists_free_and_disables_busy(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path)
    # wlan1 is held by a named task -> shown but not selectable
    app.state.iface_registry.claim("wlan1", "run-7", "monitor",
                                   label="Wi-Fi scan / Full Audit")
    c = TestClient(app)
    login(c)
    body = c.get("/scan?workflow=wifi_scan").text
    assert 'name="wifi_iface"' in body                   # it's a <select> picker now
    assert "Auto-detect" in body
    # wlan0 (free, safe) is a normal selectable option
    assert re.search(r'<option value="wlan0"(?![^>]*disabled)', body)
    # wlan1 (busy) is disabled and attributed to the holder
    assert re.search(r'<option value="wlan1"[^>]*disabled', body)
    assert "Wi-Fi scan / Full Audit" in body
    # eth0 is not Wi-Fi -> not a monitor choice at all
    assert 'value="eth0"' not in body


def test_scan_picker_selection_reaches_run_config(tmp_path, monkeypatch):
    """Choosing an interface flows into the per-run config, which wifi_scan then
    claims through the registry (claim path covered by the wifi_scan tests)."""
    stub_host(monkeypatch)
    from core import orchestrator as orch
    seen = {}

    def fake_run(wf, target, config=None, authorized=False, events=None, run_id=None):
        seen["wifi_iface"] = getattr(config, "wifi_iface", None)

    monkeypatch.setattr(orch, "run_workflow", fake_run)
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/run/wifi_scan",
               data={"csrf": csrf, "target": "", "wifi_iface": "wlan0",
                     "wifi_scan_seconds": "5", "wifi_scan_channel": ""},
               follow_redirects=False)
    assert r.status_code == 303
    assert seen.get("wifi_iface") == "wlan0"             # selection reached the run


# --- Part B COMMIT 1: mode-assignment control -----------------------------
def test_mode_set_refuses_default_route(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    called = {}
    monkeypatch.setattr(interfaces_mod, "set_interface_mode",
                        lambda i, m: called.setdefault("hit", (i, m)) or (True, "ok"))
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/interfaces/mode", data={"csrf": csrf, "iface": "eth0",
               "mode": "monitor"}, follow_redirects=False)
    assert r.status_code == 200
    assert "Refused" in r.text and "default route" in r.text
    assert "hit" not in called                           # never operated on it


def test_mode_set_refuses_ssh(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    monkeypatch.setattr(core_state, "ssh_iface", lambda: "wlan1")
    called = {}
    monkeypatch.setattr(interfaces_mod, "set_interface_mode",
                        lambda i, m: called.setdefault("hit", True) or (True, "ok"))
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/interfaces/mode", data={"csrf": csrf, "iface": "wlan1",
               "mode": "managed"}, follow_redirects=False)
    assert "Refused" in r.text and "SSH" in r.text
    assert "hit" not in called


def test_mode_set_refuses_busy(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    called = {}
    monkeypatch.setattr(interfaces_mod, "set_interface_mode",
                        lambda i, m: called.setdefault("hit", True) or (True, "ok"))
    _, _, app = make_env(tmp_path)
    app.state.iface_registry.claim("wlan1", "run-9", "monitor", label="Wi-Fi scan")
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/interfaces/mode", data={"csrf": csrf, "iface": "wlan1",
               "mode": "managed"}, follow_redirects=False)
    assert "Refused" in r.text and "busy" in r.text and "Wi-Fi scan" in r.text
    assert "hit" not in called


def test_mode_set_success_claims_then_releases(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    monkeypatch.setattr(interfaces_mod, "set_interface_mode",
                        lambda i, m: (True, f"{i} set to {m} mode"))
    _, _, app = make_env(tmp_path)
    reg = app.state.iface_registry
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/interfaces/mode", data={"csrf": csrf, "iface": "wlan1",
               "mode": "monitor"}, follow_redirects=False)
    assert r.status_code == 200 and "wlan1 set to monitor mode" in r.text
    # the brief mode-set reservation is released afterwards (no leak)
    assert "wlan1" not in reg.reservations()


def test_mode_set_blocked_in_readonly(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path, readonly=True)
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/interfaces/mode", data={"csrf": csrf, "iface": "wlan1",
               "mode": "monitor"}, follow_redirects=False)
    assert r.status_code == 403


def test_mode_set_requires_csrf(tmp_path, monkeypatch):
    stub_host(monkeypatch)
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    r = c.post("/interfaces/mode", data={"iface": "wlan1", "mode": "monitor"},
               follow_redirects=False)
    assert r.status_code == 403


# --- Part B COMMIT 1: default monitor interface persisted via settings -----
def test_settings_default_wifi_iface_persists(tmp_path):
    import pytest
    from types import SimpleNamespace
    from dashboard import settings as settings_mod

    cfg = Config(root=tmp_path)
    dc = SimpleNamespace(readonly=False)
    assert cfg.wifi_iface == "wlan1"                      # built-in default
    settings_mod.update(cfg, dc, {"wifi_iface": "wlan2"})
    assert cfg.wifi_iface == "wlan2"

    # simulate a restart: a fresh config re-applies the stored default
    cfg2 = Config(root=tmp_path)
    assert cfg2.wifi_iface == "wlan1"                     # default before apply
    settings_mod.apply_to(cfg2, SimpleNamespace(readonly=False))
    assert cfg2.wifi_iface == "wlan2"                     # stored default restored

    with pytest.raises(ValueError):
        settings_mod.update(cfg, dc, {"wifi_iface": "bad name!!"})
