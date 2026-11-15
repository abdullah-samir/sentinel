# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — pure network helpers: scan parse, AP profile builder, captive DNS."""
from __future__ import annotations

import logging

import core.state as cstate
from core import provisioning_net as N


def test_parse_wifi_scan_dedupe_sort_escape_and_drop_hidden():
    out = "\n".join([
        "HomeWifi:72:WPA2:*",          # strongest + in-use
        "HomeWifi:40:WPA2:",           # weaker dup -> dropped, but keep in_use
        r"Cafe\:Net:55:WPA1 WPA2:",    # escaped colon in SSID
        ":30:WPA2:",                   # hidden/empty SSID -> dropped
        "Open:48::",                   # open network, empty security
    ])
    nets = N.parse_wifi_scan(out)
    assert [n["ssid"] for n in nets] == ["HomeWifi", "Cafe:Net", "Open"]  # strongest-first
    assert nets[0]["signal"] == 72 and nets[0]["in_use"] is True
    assert nets[1]["ssid"] == "Cafe:Net" and nets[1]["security"] == "WPA1 WPA2"
    assert nets[2]["security"] == "--"                                   # open -> placeholder


def test_parse_wifi_scan_tolerates_junk():
    assert N.parse_wifi_scan("") == []
    assert N.parse_wifi_scan("\n::::\n:\n") == []      # empty-SSID lines dropped


def test_build_ap_profile_args_pins_everything():
    s = {"ap_ifname": "wlan0", "ap_ssid": "Sentinel-Setup",
         "ap_password": "a-strong-psk-123", "ap_ip": "10.42.0.1", "ap_prefix": 24,
         "ap_hidden": False}
    args = N.build_ap_profile_args(s)
    assert args["con_name"] == "sentinel-ap"
    assert args["add"][:6] == ["connection", "add", "type", "wifi", "ifname", "wlan0"]
    assert "Sentinel-Setup" in args["add"]
    m = args["modify"]
    # critical pins present as adjacent key/value pairs
    def val(key):
        return m[m.index(key) + 1]
    assert val("802-11-wireless.mode") == "ap"
    assert val("802-11-wireless.band") == "bg"
    assert val("ipv4.method") == "shared"
    assert val("ipv4.addresses") == "10.42.0.1/24"
    assert val("wifi-sec.key-mgmt") == "wpa-psk"
    assert val("wifi-sec.psk") == "a-strong-psk-123"      # arg, never shell-interpolated
    assert val("802-11-wireless.hidden") == "no"
    assert val("connection.autoconnect") == "no"


def test_build_ap_profile_args_hidden():
    args = N.build_ap_profile_args({"ap_hidden": True})
    m = args["modify"]
    assert m[m.index("802-11-wireless.hidden") + 1] == "yes"


def _backend():
    # self_link_reason runs no nmcli, so a backend with no real settings is fine.
    return N.NmcliBackend(settings_fn=lambda: {}, config=None)


def test_self_link_guard_fails_closed_on_exception(monkeypatch, caplog):
    def boom(ifname):
        raise RuntimeError("route lookup blew up")
    monkeypatch.setattr(cstate, "self_link_reason", boom)
    with caplog.at_level(logging.ERROR, logger="sentinel.provisioning.net"):
        reason = _backend().self_link_reason("wlan0")
    assert reason != ""                               # FAIL CLOSED — never permit on error
    assert "wlan0" in reason and "fail-closed" in reason
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_self_link_guard_permits_when_safe(monkeypatch):
    monkeypatch.setattr(cstate, "self_link_reason", lambda ifname: "")
    assert _backend().self_link_reason("wlan0") == ""   # normal path unchanged


def test_self_link_guard_passes_reason_through(monkeypatch):
    monkeypatch.setattr(cstate, "self_link_reason",
                        lambda ifname: f"{ifname} carries the default route")
    assert _backend().self_link_reason("wlan0") == "wlan0 carries the default route"


def test_captive_dns_conf_and_file_roundtrip(tmp_path):
    conf = N.captive_dns_conf("10.42.0.1", "sentinel.local")
    assert "address=/#/10.42.0.1" in conf
    assert "address=/sentinel.local/10.42.0.1" in conf
    p = tmp_path / "nm" / "sentinel-captive.conf"
    assert N.write_captive_dns(p, "10.42.0.1", "sentinel.local") is True
    assert "address=/#/10.42.0.1" in p.read_text()
    assert N.remove_captive_dns(p) is True and not p.exists()
    assert N.remove_captive_dns(p) is True                 # idempotent
