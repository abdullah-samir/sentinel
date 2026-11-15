# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — the dashboard provisioning SETTINGS route (auth + CSRF + readonly).

Discovery (nmcli) is monkeypatched so no real networking happens; the route only
persists config and never changes the Pi.
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from core.config import Config
from core import provisioning as P
from dashboard import provisioning_discovery as PD
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"
IFACE_OK = {"wlan0": {"exists": True, "ap_capable": True, "reserved_reason": "", "state": "disconnected"}}


def make_env(tmp_path, *, readonly=False, monkeypatch=None, iface_info=None, shared=None):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    app = create_app(cfg, dc)
    if monkeypatch is not None:
        monkeypatch.setattr(PD, "ap_capable_interfaces",
                            lambda config=None: dict(iface_info or IFACE_OK))
        monkeypatch.setattr(PD, "settings_discovery",
                            lambda config=None: (dict(iface_info or IFACE_OK), list(shared or [])))
    return cfg, app


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    r = client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                    follow_redirects=False)
    assert r.status_code == 303


def _csrf(client):
    return client.cookies.get("sentinel_csrf")


def _valid_form(csrf, **over):
    f = {"csrf": csrf, "ap_ssid": "Sentinel-Setup", "ap_password": "correct horse 8+",
         "ap_ifname": "wlan0", "ap_ip": "10.42.0.1", "ap_prefix": "24",
         "grace_seconds": "45", "join_timeout": "30", "probe_timeout": "5",
         "probe_url": "http://connectivitycheck.gstatic.com/generate_204",
         "friendly_hostname": "sentinel.local", "dashboard_port": "8000"}
    f.update(over)
    return f


def test_settings_page_shows_provisioning_off_by_default(tmp_path, monkeypatch):
    _, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    body = c.get("/settings").text
    assert 'id="provisioning"' in body and "Network / Provisioning" in body
    assert "master switch" in body and "Ships disabled" in body
    # enable checkbox is disabled until a PSK is set
    assert "set an AP password first" in body


def test_save_provisioning_persists_but_stays_off(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/provisioning", data=_valid_form(_csrf(c)),
               follow_redirects=False)
    assert r.status_code == 303 and "provsaved" in r.headers["location"]
    s = P.load_provisioning(cfg)
    assert s["ap_password"] == "correct horse 8+"
    assert s["provisioning_enabled"] is False          # not enabled unless ticked


def test_enable_requires_password_present(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    # try to enable while sending a blank password and none stored -> rejected
    r = c.post("/settings/provisioning",
               data=_valid_form(_csrf(c), provisioning_enabled="1", ap_password=""),
               follow_redirects=False)
    assert r.status_code == 303 and "provinvalid" in r.headers["location"]
    assert P.provisioning_enabled(cfg) is False
    # set a password first, then enable
    c.post("/settings/provisioning", data=_valid_form(_csrf(c)))
    r = c.post("/settings/provisioning",
               data=_valid_form(_csrf(c), provisioning_enabled="1", ap_password=""),
               follow_redirects=False)
    assert "provsaved" in r.headers["location"]
    assert P.provisioning_enabled(cfg) is True          # blank kept the stored PSK


def test_blank_password_keeps_stored_secret(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    c.post("/settings/provisioning", data=_valid_form(_csrf(c)))
    c.post("/settings/provisioning", data=_valid_form(_csrf(c), ap_ssid="Renamed",
                                                      ap_password=""))
    s = P.load_provisioning(cfg)
    assert s["ap_ssid"] == "Renamed" and s["ap_password"] == "correct horse 8+"


def test_subnet_clash_rejected(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch, shared=["10.42.0.0/24"])
    c = TestClient(app)
    login(c)
    r = c.post("/settings/provisioning", data=_valid_form(_csrf(c), ap_ip="10.42.0.1"),
               follow_redirects=False)
    assert "provinvalid" in r.headers["location"]


def test_readonly_blocks_save(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, readonly=True, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/provisioning", data=_valid_form(_csrf(c)),
               follow_redirects=False)
    assert r.status_code == 303 and "readonly" in r.headers["location"]
    assert not P.provisioning_path(cfg).exists()        # nothing written


def test_save_requires_csrf_and_auth(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    assert c.post("/settings/provisioning",
                  data=_valid_form("deadbeef")).status_code == 403
    nc = TestClient(app)
    r = nc.post("/settings/provisioning", data=_valid_form("x"), follow_redirects=False)
    assert r.status_code in (303, 401) and "/login" in r.headers.get("location", "/login")
