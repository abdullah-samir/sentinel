# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — root service IPC dispatch. MockBackend + synchronous spawn + fake join;
no sockets, no nmcli, no captive-DNS writes to the real system (tmp path).
"""
from __future__ import annotations

from core.config import Config
from core import provisioning_state as pstate
from core.provisioning_backend import MockBackend
from core.provisioning_service import ProvisioningService


def _cfg(tmp_path):
    cfg = Config(root=tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)
    return cfg


def _svc(tmp_path, join_fn=None, backend=None):
    cfg = _cfg(tmp_path)
    be = backend or MockBackend()
    # synchronous spawn so handle() completes the worker inline; captive path in tmp
    svc = ProvisioningService(
        cfg, backend=be, join_fn=join_fn or (lambda *a, **k: {"kind": pstate.OK}),
        spawn_fn=lambda fn, *a: fn(*a),
        captive_dns_path=str(tmp_path / "captive.conf"))
    return svc, be, cfg


def test_ping_and_status(tmp_path):
    svc, _, cfg = _svc(tmp_path)
    assert svc.handle({"action": "ping"}) == {"ok": True}
    pstate.set_last_result(cfg, pstate.WRONG_CRED, "X", "nope")
    pstate.set_networks(cfg, [{"ssid": "A"}])
    st = svc.handle({"action": "status"})
    assert st["ok"] and st["result"]["ssid"] == "X" and st["networks"] == [{"ssid": "A"}]


def test_join_dispatch_calls_join_fn_and_acks(tmp_path):
    seen = {}

    def fake_join(backend, settings, ssid, password, config):
        seen["ssid"] = ssid
        seen["password"] = password
        return {"kind": pstate.OK}

    svc, be, _ = _svc(tmp_path, join_fn=fake_join)
    resp = svc.handle({"action": "join", "ssid": "Home", "password": "secret-1234"})
    assert resp == {"ok": True, "state": "attempting"}
    assert seen == {"ssid": "Home", "password": "secret-1234"}
    # success -> AP reflected down
    assert svc.monitor.ap_active is False


def test_join_failure_reflects_ap_up(tmp_path):
    svc, be, _ = _svc(tmp_path, join_fn=lambda *a, **k: {"kind": pstate.WRONG_CRED})
    svc.handle({"action": "join", "ssid": "Home", "password": "secret-1234"})
    assert svc.monitor.ap_active is True            # join re-raised the AP


def test_rescan_cycles_ap_and_caches(tmp_path):
    be = MockBackend(scan_networks=[{"ssid": "Seen", "signal": 50,
                                     "security": "WPA2", "in_use": False}])
    svc, _, cfg = _svc(tmp_path, backend=be)
    resp = svc.handle({"action": "rescan"})
    assert resp == {"ok": True, "state": "rescanning"}
    names = be.names()
    assert "ap_down" in names and "scan" in names and "ap_up" in names
    assert pstate.get_networks(cfg)["networks"][0]["ssid"] == "Seen"


def test_unknown_action(tmp_path):
    svc, _, _ = _svc(tmp_path)
    assert svc.handle({"action": "frobnicate"})["ok"] is False
