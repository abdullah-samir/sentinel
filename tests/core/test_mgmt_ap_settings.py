# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P2 — management-AP SETTINGS: defaults (ships disabled), validation
(SSID/PSK, subnet, dedicated-NIC rules), atomic 0600 persistence + redaction. Pure;
no networking. Live interface facts are passed in as plain data (fakes)."""
from __future__ import annotations

import os
import stat

from core import mgmt_ap as m
from core.config import Config


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


def _full(**over):
    """A fully-merged, valid settings dict (NOT enabled unless asked)."""
    s = dict(m.DEFAULTS)
    s.update({"mgmt_ap_ifname": "wlan1", "mgmt_ap_password": "x" * 12})
    s.update(over)
    return s


# ── defaults / ships-disabled ──────────────────────────────────────────────────
def test_defaults_ship_disabled(tmp_path):
    s = m.load_mgmt_ap(_cfg(tmp_path))
    assert s["mgmt_ap_enabled"] is False
    assert s["mgmt_ap_ifname"] == ""           # must be chosen
    assert s["mgmt_ap_ssid"] == "Sentinel"
    assert s["share_internet"] is False
    assert m.mgmt_ap_enabled(_cfg(tmp_path)) is False


def test_default_subnet_is_off_p1(tmp_path):
    # Distinct from P1's 10.42.0.0/24 so the two hotspots coexist.
    assert m.mgmt_ap_subnet(m.DEFAULTS) == "10.42.1.0/24"


# ── SSID / PSK ──────────────────────────────────────────────────────────────────
def test_empty_ssid_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_ssid="  "))
    assert any("SSID" in e for e in errs)


def test_psk_length_bounds():
    errs, _ = m.validate_settings(_full(mgmt_ap_password="short"))
    assert any("8–63" in e for e in errs)
    errs, _ = m.validate_settings(_full(mgmt_ap_password="x" * 64))
    assert any("8–63" in e for e in errs)


def test_enable_requires_psk():
    errs, _ = m.validate_settings(_full(mgmt_ap_enabled=True, mgmt_ap_password=""))
    assert any("password" in e.lower() for e in errs)


# ── subnet / IP ─────────────────────────────────────────────────────────────────
def test_bad_ip_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_ip="not-an-ip"))
    assert any("IP" in e for e in errs)


def test_subnet_clash_with_p1_rejected():
    # P1's AP subnet is passed in as an existing shared subnet; overlap must block.
    errs, _ = m.validate_settings(_full(mgmt_ap_ip="10.42.0.1"),
                                  shared_subnets=["10.42.0.0/24"])
    assert any("clash" in e.lower() for e in errs)


def test_no_subnet_clash_when_disjoint():
    errs, _ = m.validate_settings(_full(mgmt_ap_ip="10.42.1.1"),
                                  shared_subnets=["10.42.0.0/24"])
    assert errs == []


# ── dedicated-NIC rules ─────────────────────────────────────────────────────────
def test_wlan0_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_ifname="wlan0"))
    assert any("wlan0" in e for e in errs)


def test_uplink_iface_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_ifname="wlan1"),
                                  uplink_iface="wlan1")
    assert any("self-lockout" in e.lower() for e in errs)


def test_absent_interface_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_ifname="wlan7"),
                                  iface_info={"wlan1": {"exists": True,
                                                        "ap_capable": True}})
    assert any("not found" in e.lower() for e in errs)


def test_not_ap_capable_rejected():
    errs, _ = m.validate_settings(
        _full(mgmt_ap_ifname="wlan1"),
        iface_info={"wlan1": {"exists": True, "ap_capable": False}})
    assert any("AP-capable" in e for e in errs)


def test_reserved_interface_warns_not_errors():
    errs, warns = m.validate_settings(
        _full(mgmt_ap_ifname="wlan1"),
        iface_info={"wlan1": {"exists": True, "ap_capable": True,
                              "reserved_reason": "busy — in use by scan"}})
    assert errs == []
    assert any("reserved" in w.lower() for w in warns)


def test_enable_without_iface_rejected():
    errs, _ = m.validate_settings(_full(mgmt_ap_enabled=True, mgmt_ap_ifname=""))
    assert any("dedicated" in e.lower() for e in errs)


# ── persistence + redaction ─────────────────────────────────────────────────────
def test_save_roundtrip_and_0600(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errs, warns, red = m.save_mgmt_ap(
        cfg, {"mgmt_ap_ifname": "wlan1", "mgmt_ap_password": "supersecret1",
              "mgmt_ap_ssid": "Sentinel"})
    assert ok and errs == []
    # secret never echoed back
    assert "mgmt_ap_password" not in red
    assert red["mgmt_ap_password_set"] is True
    # file is 0600 (holds the PSK)
    mode = stat.S_IMODE(os.stat(m.mgmt_ap_path(cfg)).st_mode)
    assert mode == 0o600
    # reload sees the stored secret
    assert m.load_mgmt_ap(cfg)["mgmt_ap_password"] == "supersecret1"


def test_masked_blank_keeps_stored_secret(tmp_path):
    cfg = _cfg(tmp_path)
    m.save_mgmt_ap(cfg, {"mgmt_ap_ifname": "wlan1",
                         "mgmt_ap_password": "originalpass1"})
    # a blank PSK field must NOT wipe the stored secret
    ok, _, _, _ = m.save_mgmt_ap(cfg, {"mgmt_ap_ssid": "Renamed",
                                       "mgmt_ap_password": ""})
    assert ok
    reloaded = m.load_mgmt_ap(cfg)
    assert reloaded["mgmt_ap_password"] == "originalpass1"
    assert reloaded["mgmt_ap_ssid"] == "Renamed"


def test_cannot_enable_without_psk_via_save(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errs, _, _ = m.save_mgmt_ap(cfg, {"mgmt_ap_enabled": True,
                                          "mgmt_ap_ifname": "wlan1"})
    assert not ok and errs
    assert m.mgmt_ap_enabled(cfg) is False     # nothing persisted
