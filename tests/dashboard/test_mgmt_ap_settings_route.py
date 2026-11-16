# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P2 — the dashboard management-hotspot SETTINGS route (auth + CSRF + readonly).

Discovery (nmcli) is monkeypatched so no real networking happens; the route only
persists config and never changes the Pi. The default-route lookup is also patched so
the uplink self-lockout check is deterministic.
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from core.config import Config
from core import mgmt_ap as M
from dashboard import app as app_mod
from dashboard import provisioning_discovery as PD
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"
IFACE_OK = {"wlan1": {"exists": True, "ap_capable": True, "reserved_reason": "",
                      "state": "disconnected"}}


def make_env(tmp_path, *, readonly=False, monkeypatch=None, iface_info=None,
             shared=None, uplink="eth0"):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    app = create_app(cfg, dc)
    if monkeypatch is not None:
        info = dict(iface_info or IFACE_OK)
        monkeypatch.setattr(PD, "ap_capable_interfaces", lambda config=None: dict(info))
        monkeypatch.setattr(PD, "settings_discovery",
                            lambda config=None: (dict(info), list(shared or [])))
        # uplink is live; pin it so the self-lockout check is deterministic.
        monkeypatch.setattr(app_mod, "default_route_iface", lambda: uplink)
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
    f = {"csrf": csrf, "mgmt_ap_ssid": "Sentinel", "mgmt_ap_password": "correct horse 8+",
         "mgmt_ap_ifname": "wlan1", "mgmt_ap_ip": "10.42.1.1", "mgmt_ap_prefix": "24",
         "mgmt_ap_hostname": "sentinel.local"}
    f.update(over)
    return f


def test_settings_page_shows_mgmt_off_by_default(tmp_path, monkeypatch):
    _, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    body = c.get("/settings").text
    assert 'id="mgmt-ap"' in body and "Management hotspot" in body
    assert "master switch" in body and "Ships disabled" in body
    # enable checkbox is disabled until a PSK is set
    assert "set a password first" in body


def test_save_mgmt_persists_but_stays_off(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c)), follow_redirects=False)
    assert r.status_code == 303 and "mgmtsaved" in r.headers["location"]
    s = M.load_mgmt_ap(cfg)
    assert s["mgmt_ap_password"] == "correct horse 8+"
    assert s["mgmt_ap_ifname"] == "wlan1"
    assert s["mgmt_ap_enabled"] is False               # not enabled unless ticked


def test_enable_requires_password_present(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    # enable with blank password and none stored -> rejected
    r = c.post("/settings/mgmt_ap",
               data=_valid_form(_csrf(c), mgmt_ap_enabled="1", mgmt_ap_password=""),
               follow_redirects=False)
    assert r.status_code == 303 and "mgmtinvalid" in r.headers["location"]
    assert M.mgmt_ap_enabled(cfg) is False
    # set a password, then enable with a blank field (keeps the stored PSK)
    c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c)))
    r = c.post("/settings/mgmt_ap",
               data=_valid_form(_csrf(c), mgmt_ap_enabled="1", mgmt_ap_password=""),
               follow_redirects=False)
    assert "mgmtsaved" in r.headers["location"]
    assert M.mgmt_ap_enabled(cfg) is True


def test_wlan0_rejected(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c), mgmt_ap_ifname="wlan0"),
               follow_redirects=False)
    assert "mgmtinvalid" in r.headers["location"]


def test_uplink_iface_rejected(tmp_path, monkeypatch):
    # The chosen NIC currently carries the default route -> self-lockout, refused.
    info = {"wlan1": {"exists": True, "ap_capable": True, "reserved_reason": ""}}
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch, iface_info=info,
                        uplink="wlan1")
    c = TestClient(app)
    login(c)
    r = c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c)), follow_redirects=False)
    assert "mgmtinvalid" in r.headers["location"]


def test_subnet_clash_with_p1_rejected(tmp_path, monkeypatch):
    # P1's default AP subnet is 10.42.0.0/24; the route folds it into the clash check.
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c), mgmt_ap_ip="10.42.0.5"),
               follow_redirects=False)
    assert "mgmtinvalid" in r.headers["location"]


def test_readonly_blocks_save(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, readonly=True, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    r = c.post("/settings/mgmt_ap", data=_valid_form(_csrf(c)), follow_redirects=False)
    assert r.status_code == 303 and "readonly" in r.headers["location"]
    assert not M.mgmt_ap_path(cfg).exists()             # nothing written


def test_save_requires_csrf_and_auth(tmp_path, monkeypatch):
    cfg, app = make_env(tmp_path, monkeypatch=monkeypatch)
    c = TestClient(app)
    login(c)
    assert c.post("/settings/mgmt_ap",
                  data=_valid_form("deadbeef")).status_code == 403
    nc = TestClient(app)
    r = nc.post("/settings/mgmt_ap", data=_valid_form("x"), follow_redirects=False)
    assert r.status_code in (303, 401) and "/login" in r.headers.get("location", "/login")
