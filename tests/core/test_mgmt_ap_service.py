# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P2 — management-AP supervisor: strict no-op when disabled (NO reservation),
raises ONLY on the dedicated NIC, refuses uplink/wlan0/absent/busy with NO fallback,
reserves in "ap" mode + releases on disable, is NOT offline-gated, and re-raises a
dropped AP. MockBackend + fake registry; no real networking."""
from __future__ import annotations

from core import provisioning_net as net
from core.config import Config
from core.mgmt_ap import MGMT_AP_CON_NAME, profile_settings
from core.mgmt_ap_service import MgmtApSupervisor
from core.provisioning_backend import MockBackend
from core.state import VALID_MODES


class FakeReg:
    """Records claims/releases; `busy` forces claim to refuse."""
    def __init__(self, busy=False):
        self.claims = []
        self.releases = []
        self.busy = busy

    def claim(self, iface, run_id, mode="monitor", label=""):
        self.claims.append((iface, run_id, mode, label))
        if self.busy:
            return (False, "held by run xyz")
        return (True, "")

    def release(self, iface, run_id=None):
        self.releases.append((iface, run_id))
        return True


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


def _settings(**over):
    s = {"mgmt_ap_enabled": True, "mgmt_ap_ifname": "wlan1", "mgmt_ap_ssid": "Sentinel",
         "mgmt_ap_password": "x" * 12, "mgmt_ap_ip": "10.42.1.1", "mgmt_ap_prefix": 24,
         "mgmt_ap_hidden": False, "mgmt_ap_hostname": "sentinel.local",
         "share_internet": False}
    s.update(over)
    return s


def _sup(tmp_path, settings, *, backend=None, registry=None, present=("wlan1",)):
    be = backend or MockBackend()
    reg = registry if registry is not None else FakeReg()
    sup = MgmtApSupervisor(be, _cfg(tmp_path), settings_fn=lambda: settings,
                           registry=reg, present_fn=lambda: set(present),
                           dns_path=None)
    return sup, be, reg


# ── disabled = strict no-op, no reservation ─────────────────────────────────────
def test_disabled_is_strict_noop(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings(mgmt_ap_enabled=False))
    snap = sup.step()
    assert snap["enabled"] is False and snap["action"] == "noop"
    assert be.calls == []                      # no network action at all
    assert reg.claims == []                    # NO reservation held while disabled


# ── raises only on the dedicated NIC, reserved in "ap" mode ─────────────────────
def test_enable_raises_on_dongle(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings())
    snap = sup.step()
    assert snap["action"] == "ap_raised" and sup.ap_active is True
    assert "ap_up" in be.names()
    assert reg.claims == [("wlan1", "mgmt-ap", "ap", "management AP")]


def test_ap_is_a_valid_reservation_mode():
    # "ap" must be a representable reservation mode (so the registry preserves it)...
    assert "ap" in VALID_MODES
    # ...but it is NEVER user-selectable via the privileged mode switch.
    from dashboard.interfaces import set_interface_mode
    ok, msg = set_interface_mode("wlan1", "ap")
    assert not ok and "invalid mode" in msg


# ── NOT offline-gated (unlike P1): raises even when fully online ─────────────────
def test_not_offline_gated(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings(), backend=MockBackend(online=True))
    snap = sup.step()
    assert snap["action"] == "ap_raised" and sup.ap_active is True


# ── refusals: NO fallback, nothing reserved ─────────────────────────────────────
def test_refuses_uplink_self_link(tmp_path):
    be = MockBackend(self_link={"wlan1": "wlan1 carries the default route"})
    sup, be, reg = _sup(tmp_path, _settings(), backend=be)
    snap = sup.step()
    assert snap["action"] == "refused_self_link" and not sup.ap_active
    assert "ap_up" not in be.names()
    assert reg.claims == []


def test_refuses_wlan0(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings(mgmt_ap_ifname="wlan0"),
                        present=("wlan0", "wlan1"))
    snap = sup.step()
    assert snap["action"] == "refused_wlan0" and not sup.ap_active
    assert reg.claims == []


def test_refuses_absent_nic(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings(mgmt_ap_ifname="wlan9"),
                        present=("wlan1",))
    snap = sup.step()
    assert snap["action"] == "iface_absent" and not sup.ap_active
    assert "ap_up" not in be.names()
    assert reg.claims == []


def test_refuses_busy_nic(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings(), registry=FakeReg(busy=True))
    snap = sup.step()
    assert snap["action"] == "iface_busy" and not sup.ap_active
    assert "ap_up" not in be.names()


# ── reservation released on disable; AP torn down ───────────────────────────────
def test_disable_tears_down_and_releases(tmp_path):
    settings = _settings()
    sup, be, reg = _sup(tmp_path, settings)
    sup.step()
    assert sup.ap_active is True
    settings["mgmt_ap_enabled"] = False
    snap = sup.step()
    assert snap["action"] == "disabled_teardown" and sup.ap_active is False
    assert "ap_down" in be.names()
    assert reg.releases == [("wlan1", "mgmt-ap")]


# ── supervise: re-raise a dropped AP ────────────────────────────────────────────
def test_re_raises_dropped_ap(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings())
    sup.step()
    assert sup.ap_active is True
    be.ap_active = False                       # simulate the AP dropping underneath us
    snap = sup.step()
    assert snap["action"] == "re_raised" and sup.ap_active is True


def test_holds_while_up(tmp_path):
    sup, be, reg = _sup(tmp_path, _settings())
    sup.step()
    snap = sup.step()
    assert snap["action"] == "holding" and sup.ap_active is True


# ── distinct con-name + subnet from P1 ──────────────────────────────────────────
def test_distinct_con_name_and_subnet_from_p1():
    assert MGMT_AP_CON_NAME != net.AP_CON_NAME
    args = net.build_ap_profile_args(profile_settings(_settings()),
                                     con_name=MGMT_AP_CON_NAME)
    assert args["con_name"] == MGMT_AP_CON_NAME
    # the PSK is an argument in the modify list, never shell-interpolated
    assert "x" * 12 in args["modify"]
    # pinned to a different gateway/subnet than P1's 10.42.0.1/24
    assert "10.42.1.1/24" in args["modify"]
