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
    monkeypatch.setattr(core_state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(core_state, "ssh_iface", lambda: "")


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
    app.state.iface_registry.claim("wlan1", "run-xyz-123", "monitor")
    c = TestClient(app)
    login(c)
    r = c.get("/interfaces")
    assert r.status_code == 200
    body = r.text
    assert "busy" in body and "run-xyz-123" in body
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
