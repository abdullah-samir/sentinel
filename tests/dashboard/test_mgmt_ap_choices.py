# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P2 — the dedicated-NIC chooser (mgmt_ap_interface_choices).

Any AP-capable Wi-Fi interface that is NOT wlan0 and NOT the live uplink/SSH is
selectable — a spare USB dongle OR the onboard chip when it is free. wlan0, the
uplink/SSH interface, and a busy interface are listed but non-selectable. Host
probes are stubbed so the test is deterministic on any machine."""
from __future__ import annotations

import pytest

from dashboard import interfaces as I


class FakeReg:
    def __init__(self, reservations=None):
        self._res = reservations or {}

    def reservations(self):
        return dict(self._res)


@pytest.fixture
def host(monkeypatch):
    # wlan0 = uplink (USB dongle here), wlan1 = free USB, wlan2 = free onboard, eth0 = wired
    monkeypatch.setattr(I, "present_interfaces",
                        lambda: ["eth0", "lo", "wlan0", "wlan1", "wlan2"])
    monkeypatch.setattr(I, "is_wifi", lambda i: i.startswith("wlan"))
    monkeypatch.setattr(I, "is_usb", lambda i: i in ("wlan0", "wlan1"))
    monkeypatch.setattr(I, "iface_mac", lambda i: "00:11:22:33:44:" + i[-1])
    monkeypatch.setattr(I, "usb_path", lambda i: "1-1." + i[-1] if i in ("wlan0", "wlan1") else "")
    monkeypatch.setattr(I.core_state, "default_route_iface", lambda: "wlan0")
    monkeypatch.setattr(I.core_state, "ssh_iface", lambda: "")


def _by(rows):
    return {r["iface"]: r for r in rows}


def test_onboard_free_ap_capable_is_selectable(host):
    info = {"wlan1": {"ap_capable": True}, "wlan2": {"ap_capable": True}}
    rows = _by(I.mgmt_ap_interface_choices(None, FakeReg(), iface_info=info))
    # spare USB dongle: selectable
    assert rows["wlan1"]["selectable"] is True
    # onboard chip, free + AP-capable, NOT the uplink: now selectable too
    assert rows["wlan2"]["selectable"] is True
    assert rows["wlan2"]["usb"] is False
    # wlan0 (uplink + the reserved-by-convention name): never selectable
    assert rows["wlan0"]["selectable"] is False
    # MAC is surfaced for identification
    assert rows["wlan1"]["mac"].endswith(":1")


def test_not_ap_capable_is_not_selectable(host):
    info = {"wlan1": {"ap_capable": False}, "wlan2": {"ap_capable": True}}
    rows = _by(I.mgmt_ap_interface_choices(None, FakeReg(), iface_info=info))
    assert rows["wlan1"]["selectable"] is False
    assert "not AP-capable" in rows["wlan1"]["note"]


def test_busy_interface_not_selectable(host):
    reg = FakeReg({"wlan2": {"mode": "ap", "run_id": "mgmt-ap",
                             "label": "management AP", "alive": True}})
    info = {"wlan1": {"ap_capable": True}, "wlan2": {"ap_capable": True}}
    rows = _by(I.mgmt_ap_interface_choices(None, reg, iface_info=info))
    assert rows["wlan2"]["selectable"] is False and rows["wlan2"]["busy"] is True


def test_uplink_and_ssh_protected(host, monkeypatch):
    monkeypatch.setattr(I.core_state, "ssh_iface", lambda: "wlan1")
    info = {"wlan1": {"ap_capable": True}, "wlan2": {"ap_capable": True}}
    rows = _by(I.mgmt_ap_interface_choices(None, FakeReg(), iface_info=info))
    # wlan1 now carries SSH -> protected, non-selectable
    assert rows["wlan1"]["selectable"] is False and rows["wlan1"]["unsafe"] is True
    # wlan2 still fine
    assert rows["wlan2"]["selectable"] is True
