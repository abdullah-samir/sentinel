# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — captive portal routes. Fake IPC send_fn (no sockets, no network); the
portal never calls nmcli and never logs a password.
"""
from __future__ import annotations

from starlette.testclient import TestClient

from core.config import Config
from core import provisioning as P
from core import provisioning_state as pstate
from dashboard.portal import create_portal_app, dashboard_link


def _cfg(tmp_path, **prov_over):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    IFACE = {"wlan0": {"exists": True, "ap_capable": True, "reserved_reason": ""}}
    base = {"ap_ssid": "Sentinel-Setup", "ap_password": "a-strong-psk", "ap_ifname": "wlan0",
            "ap_ip": "10.42.0.1", "ap_prefix": 24}
    base.update(prov_over)
    P.save_provisioning(cfg, base, iface_info=IFACE)
    return cfg


def _client(cfg, sent=None):
    def send(req):
        if sent is not None:
            sent.append(req)
        return {"ok": True, "state": "attempting"}
    app = create_portal_app(cfg, send_fn=send)
    return TestClient(app), send


# ── dashboard link logic (localhost-only dashboard per discovery) ───────────────
def test_dashboard_link_hidden_unless_opted_in():
    assert dashboard_link({"show_dashboard_link": True, "dashboard_on_ap": False}) is None
    link = dashboard_link({"show_dashboard_link": True, "dashboard_on_ap": True,
                           "friendly_hostname": "sentinel.local", "dashboard_port": 8000})
    assert link == "http://sentinel.local:8000/"            # carries the dashboard port
    assert dashboard_link({"show_dashboard_link": False, "dashboard_on_ap": True}) is None


def test_landing_hides_link_by_default(tmp_path):
    cfg = _cfg(tmp_path)                                    # dashboard_on_ap default False
    c, _ = _client(cfg)
    body = c.get("/").text
    assert "Sentinel is offline" in body and "Wi-Fi setup" in body
    assert "Open Dashboard" not in body                    # hidden (localhost-only)


def test_landing_shows_link_when_opted_in(tmp_path):
    cfg = _cfg(tmp_path, dashboard_on_ap=True, show_dashboard_link=True,
               friendly_hostname="sentinel.local", dashboard_port=8000)
    c, _ = _client(cfg)
    body = c.get("/").text
    assert 'href="http://sentinel.local:8000/"' in body and "Open Dashboard" in body


# ── network list ───────────────────────────────────────────────────────────────
def test_wifi_list_renders_and_escapes(tmp_path):
    cfg = _cfg(tmp_path)
    pstate.set_networks(cfg, [
        {"ssid": "Home", "signal": 80, "security": "WPA2", "in_use": False},
        {"ssid": "<script>x</script>", "signal": 40, "security": "--", "in_use": False},
    ])
    c, _ = _client(cfg)
    body = c.get("/wifi").text
    assert "Home" in body
    assert "<script>x</script>" not in body                # escaped
    assert "&lt;script&gt;" in body
    assert "open" in body                                  # the open network label


# ── probe URLs -> 302, never 204 ────────────────────────────────────────────────
def test_probe_urls_redirect_never_204(tmp_path):
    cfg = _cfg(tmp_path)
    c, _ = _client(cfg)
    for path in ("/generate_204", "/gen_204", "/hotspot-detect.html",
                 "/connecttest.txt", "/ncsi.txt", "/anything/unknown"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 302, path
        assert r.headers["location"] == "/"
        assert r.status_code != 204


# ── join forwards validated request, never logs password ────────────────────────
def test_join_forwards_to_ipc_and_shows_switching(tmp_path):
    cfg = _cfg(tmp_path)
    sent = []
    c, _ = _client(cfg, sent)
    r = c.post("/join", data={"ssid": "MyNet", "password": "hunter2secret", "hidden": "1"},
               follow_redirects=False)
    assert r.status_code == 200 and "switching off" in r.text
    assert sent == [{"action": "join", "ssid": "MyNet",
                     "password": "hunter2secret", "hidden": True}]


def test_join_empty_ssid_redirects(tmp_path):
    cfg = _cfg(tmp_path)
    sent = []
    c, _ = _client(cfg, sent)
    r = c.post("/join", data={"ssid": "", "password": "x"}, follow_redirects=False)
    assert r.status_code == 303 and sent == []             # not forwarded


def test_join_result_shown_on_landing_after_reraise(tmp_path):
    cfg = _cfg(tmp_path)
    pstate.set_last_result(cfg, pstate.WRONG_CRED, "MyNet",
                           "couldn't join MyNet — Secrets were required")
    c, _ = _client(cfg)
    body = c.get("/").text
    assert "Couldn’t join" in body and "MyNet" in body     # persisted result surfaced


def test_portal_does_not_import_nmcli_backend_path():
    # structural: the portal talks to IPC, never runs nmcli / subprocess itself.
    import dashboard.portal as portal
    text = open(portal.__file__, encoding="utf-8").read()
    assert "import subprocess" not in text
    assert "subprocess.run" not in text
    assert "NmcliBackend" not in text
    assert "provisioning_net" not in text
