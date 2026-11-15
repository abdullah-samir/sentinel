# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — monitor service: no-op when disabled, grace, hysteresis, flapping,
disable-teardown, self-link refusal, reservation. Fake clock + MockBackend; no net.

The first step() each test establishes offline_since; grace is measured from there.
"""
from __future__ import annotations

from core.config import Config
from core.provisioning_backend import MockBackend
from core.provisioning_monitor import ProvisioningMonitor


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def tick(self, dt): self.t += dt


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


def _mon(tmp_path, settings, backend=None, registry=None, stable=8.0):
    be = backend or MockBackend()
    clk = Clock()
    mon = ProvisioningMonitor(be, _cfg(tmp_path), settings_fn=lambda: settings,
                              now_fn=clk, registry=registry,
                              stable_online_seconds=stable)
    return mon, be, clk


def _settings(**over):
    s = {"provisioning_enabled": True, "ap_ifname": "wlan0", "grace_seconds": 45,
         "ap_ssid": "Sentinel-Setup", "ap_password": "x" * 10, "ap_ip": "10.42.0.1",
         "ap_prefix": 24}
    s.update(over)
    return s


def test_strict_noop_when_disabled(tmp_path):
    mon, be, _ = _mon(tmp_path, _settings(provisioning_enabled=False))
    snap = mon.step()
    assert snap["enabled"] is False and snap["action"] == "noop"
    assert be.calls == []                      # NO network action — not even a probe


def test_grace_before_ap_rises(tmp_path):
    mon, be, clk = _mon(tmp_path, _settings(grace_seconds=45),
                        MockBackend(full=False, probe_ok=False))
    assert mon.step()["action"] == "offline_grace" and not mon.ap_active  # sets t0
    clk.tick(44)
    assert mon.step()["action"] == "offline_grace" and not mon.ap_active
    clk.tick(2)                                # now > 45s offline
    assert mon.step()["action"] == "ap_raised" and mon.ap_active is True
    assert "ap_up" in be.names()


def test_hysteresis_teardown_only_after_stable_online(tmp_path):
    be = MockBackend(online=False)
    mon, _, clk = _mon(tmp_path, _settings(grace_seconds=1), be, stable=8.0)
    mon.step(); clk.tick(2); mon.step()        # AP up (offline past grace)
    assert mon.ap_active is True
    be.online = True
    assert mon.step()["action"] == "online_settling" and mon.ap_active is True
    clk.tick(5)
    assert mon.step()["action"] == "online_settling" and mon.ap_active is True
    clk.tick(5)                                # > 8s stable online
    assert mon.step()["action"] == "online_teardown" and mon.ap_active is False
    assert "ap_down" in be.names()


def test_flapping_online_does_not_flap_ap(tmp_path):
    be = MockBackend(online=False)
    mon, _, clk = _mon(tmp_path, _settings(grace_seconds=45), be)
    mon.step()                                 # offline t0
    clk.tick(44); be.online = True; mon.step()  # blip online before grace elapses
    clk.tick(2); be.online = False
    snap = mon.step()                          # offline_since reset -> grace restarts
    assert not mon.ap_active and snap["action"] == "offline_grace"


def test_disable_tears_down_running_ap(tmp_path):
    be = MockBackend(online=False)
    settings = _settings(grace_seconds=1)
    mon, _, clk = _mon(tmp_path, settings, be)
    mon.step(); clk.tick(2); mon.step()
    assert mon.ap_active is True
    settings["provisioning_enabled"] = False
    snap = mon.step()
    assert snap["action"] == "disabled_teardown" and mon.ap_active is False
    assert "ap_down" in be.names()


def test_refuses_ap_on_self_link_interface(tmp_path):
    be = MockBackend(online=False, self_link={"wlan0": "wlan0 carries the default route"})
    mon, _, clk = _mon(tmp_path, _settings(grace_seconds=1), be)
    mon.step(); clk.tick(2)
    assert mon.step()["action"] == "refused_self_link" and not mon.ap_active
    assert "ap_up" not in be.names()


def test_reservation_busy_blocks_ap(tmp_path):
    be = MockBackend(online=False)

    class BusyReg:
        def claim(self, *a, **k): return (False, "held by run xyz")
        def release(self, *a, **k): return True

    mon, _, clk = _mon(tmp_path, _settings(grace_seconds=1), be, registry=BusyReg())
    mon.step(); clk.tick(2)
    assert mon.step()["action"] == "iface_busy" and not mon.ap_active
    assert "ap_up" not in be.names()
