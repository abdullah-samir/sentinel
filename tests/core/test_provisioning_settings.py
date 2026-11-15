# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — provisioning SETTINGS: persistence, validation, default-off, PSK perms.

Pure/deterministic: no network, no nmcli. Live facts (interface capability, existing
shared subnets) are passed in as plain data, exactly as the dashboard will supply
them from read-only discovery.
"""
from __future__ import annotations

import stat

from core.config import Config
from core import provisioning as P


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


IFACE_OK = {"wlan0": {"exists": True, "ap_capable": True, "reserved_reason": ""}}


def _valid_updates(**over):
    u = {"ap_ssid": "Sentinel-Setup", "ap_password": "correct horse 8+",
         "ap_ifname": "wlan0", "ap_ip": "10.42.0.1", "ap_prefix": 24}
    u.update(over)
    return u


# ── defaults / default-off ─────────────────────────────────────────────────────
def test_defaults_and_master_switch_off(tmp_path):
    cfg = _cfg(tmp_path)
    s = P.load_provisioning(cfg)
    assert s["provisioning_enabled"] is False
    assert P.provisioning_enabled(cfg) is False
    assert s["ap_ssid"] == "Sentinel-Setup" and s["ap_password"] == ""
    assert s["ap_ip"] == "10.42.0.1" and s["dashboard_on_ap"] is False
    # no file yet -> pure defaults, never raises
    assert not P.provisioning_path(cfg).exists()


def test_persistence_roundtrip_keeps_off_by_default(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errors, _, red = P.save_provisioning(cfg, _valid_updates(), iface_info=IFACE_OK)
    assert ok and not errors
    s = P.load_provisioning(cfg)
    assert s["ap_password"] == "correct horse 8+"
    # saving config without touching the switch leaves it OFF
    assert s["provisioning_enabled"] is False and P.provisioning_enabled(cfg) is False
    # redacted view never carries the PSK
    assert "ap_password" not in red and red["ap_password_set"] is True


# ── PSK validation ─────────────────────────────────────────────────────────────
def test_psk_length_bounds(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(ap_password="short"),
                                           iface_info=IFACE_OK)
    assert not ok and any("8–63" in e for e in errors)
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(ap_password="x" * 64),
                                           iface_info=IFACE_OK)
    assert not ok and any("8–63" in e for e in errors)
    ok, _, _, _ = P.save_provisioning(cfg, _valid_updates(ap_password="x" * 8),
                                      iface_info=IFACE_OK)
    assert ok


def test_cannot_enable_without_psk(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errors, _, _ = P.save_provisioning(
        cfg, {"provisioning_enabled": True, "ap_password": ""}, iface_info=IFACE_OK)
    assert not ok and any("before enabling" in e for e in errors)
    # with a PSK, enabling validates
    ok, errors, _, _ = P.save_provisioning(
        cfg, _valid_updates(provisioning_enabled=True), iface_info=IFACE_OK)
    assert ok and P.provisioning_enabled(cfg) is True


def test_blank_or_keep_secret_preserves_stored_psk(tmp_path):
    cfg = _cfg(tmp_path)
    P.save_provisioning(cfg, _valid_updates(), iface_info=IFACE_OK)
    # a later save with a BLANK psk field keeps the stored secret
    ok, _, _, _ = P.save_provisioning(cfg, {"ap_ssid": "Renamed", "ap_password": ""},
                                      iface_info=IFACE_OK)
    assert ok and P.load_provisioning(cfg)["ap_password"] == "correct horse 8+"
    # as does the explicit KEEP sentinel
    ok, _, _, _ = P.save_provisioning(cfg, {"ap_password": P.KEEP_SECRET},
                                      iface_info=IFACE_OK)
    assert ok and P.load_provisioning(cfg)["ap_password"] == "correct horse 8+"
    assert P.load_provisioning(cfg)["ap_ssid"] == "Renamed"


# ── interface capability / reservation ─────────────────────────────────────────
def test_interface_must_exist_and_be_ap_capable(tmp_path):
    cfg = _cfg(tmp_path)
    info = {"wlan9": {"exists": False, "ap_capable": False, "reserved_reason": ""}}
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(ap_ifname="wlan9"),
                                           iface_info=info)
    assert not ok and any("not found" in e for e in errors)
    info = {"wlan0": {"exists": True, "ap_capable": False, "reserved_reason": ""}}
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(), iface_info=info)
    assert not ok and any("not AP-capable" in e for e in errors)


def test_reserved_interface_is_a_warning_not_an_error(tmp_path):
    cfg = _cfg(tmp_path)
    info = {"wlan0": {"exists": True, "ap_capable": True,
                      "reserved_reason": "held by run abc (monitor)"}}
    ok, errors, warnings, _ = P.save_provisioning(cfg, _valid_updates(), iface_info=info)
    assert ok and not errors
    assert any("reserved" in w for w in warnings)


# ── subnet clash ───────────────────────────────────────────────────────────────
def test_ap_subnet_clash_with_existing_shared(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errors, _, _ = P.save_provisioning(
        cfg, _valid_updates(ap_ip="10.42.0.1"), iface_info=IFACE_OK,
        shared_subnets=["10.42.0.0/24"])
    assert not ok and any("clashes" in e for e in errors)
    # a non-overlapping subnet is fine
    ok, _, _, _ = P.save_provisioning(
        cfg, _valid_updates(ap_ip="10.77.0.1"), iface_info=IFACE_OK,
        shared_subnets=["10.42.0.0/24"])
    assert ok


def test_ap_ip_rejects_network_and_broadcast(tmp_path):
    cfg = _cfg(tmp_path)
    for bad in ("10.42.0.0", "10.42.0.255"):
        ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(ap_ip=bad),
                                               iface_info=IFACE_OK)
        assert not ok and any("host address" in e for e in errors), bad


def test_bad_ip_and_prefix_and_bounds(tmp_path):
    cfg = _cfg(tmp_path)
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(ap_ip="not.an.ip"),
                                           iface_info=IFACE_OK)
    assert not ok and any("valid IPv4" in e for e in errors)
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(grace_seconds=1),
                                           iface_info=IFACE_OK)
    assert not ok and any("grace_seconds" in e for e in errors)
    ok, errors, _, _ = P.save_provisioning(cfg, _valid_updates(dashboard_port=99999),
                                           iface_info=IFACE_OK)
    assert not ok and any("dashboard_port" in e for e in errors)


# ── file perms (holds the PSK) ─────────────────────────────────────────────────
def test_psk_file_is_not_world_readable(tmp_path):
    cfg = _cfg(tmp_path)
    ok, _, _, _ = P.save_provisioning(cfg, _valid_updates(), iface_info=IFACE_OK)
    assert ok
    path = P.provisioning_path(cfg)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, oct(mode)        # owner-only; no group/other access


def test_redacted_hides_secret():
    s = dict(P.DEFAULTS, ap_password="supersecretpsk")
    red = P.redacted(s)
    assert "ap_password" not in red
    assert red["ap_password_set"] is True
    assert P.redacted(dict(P.DEFAULTS))["ap_password_set"] is False


# ── junk tolerance ─────────────────────────────────────────────────────────────
def test_load_tolerates_corrupt_file(tmp_path):
    cfg = _cfg(tmp_path)
    P.provisioning_path(cfg).write_text("{not json", encoding="utf-8")
    s = P.load_provisioning(cfg)                    # never raises -> defaults
    assert s["provisioning_enabled"] is False and s["ap_ssid"] == "Sentinel-Setup"
