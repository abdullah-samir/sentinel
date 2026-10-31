"""Tests for core.state: the interface reservation registry + central safety
check. No real radios/interfaces are touched — detection is stubbed."""
from __future__ import annotations

import os
import subprocess
import threading

import pytest

from core import state
from core.state import InterfaceRegistry, interface_safety_check


def make_reg(tmp_path, lock=None) -> InterfaceRegistry:
    return InterfaceRegistry(tmp_path / "data" / "state" / "interfaces.json",
                             lock=lock or threading.RLock())


def _dead_pid() -> int:
    """A deterministically-dead PID: spawn a trivial process and reap it."""
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


# --- claim / busy-reject / release ----------------------------------------
def test_claim_busy_reject_release(tmp_path):
    reg = make_reg(tmp_path)
    ok, reason = reg.claim("wlan1", "runA", "monitor")
    assert ok and reason == ""
    # a different, still-alive run is refused with a clear busy reason
    ok2, reason2 = reg.claim("wlan1", "runB", "monitor")
    assert not ok2 and "busy" in reason2 and "runA" in reason2
    # release frees it, then runB can claim
    assert reg.release("wlan1", "runA") is True
    ok3, reason3 = reg.claim("wlan1", "runB", "monitor")
    assert ok3 and reason3 == ""


def test_reclaim_by_same_run_is_idempotent(tmp_path):
    reg = make_reg(tmp_path)
    assert reg.claim("wlan1", "runA")[0] is True
    assert reg.busy_reason("wlan1", "runA") == ""        # never busy to its owner
    ok, reason = reg.claim("wlan1", "runA")              # re-claim same run
    assert ok and reason == ""


def test_release_only_by_owner(tmp_path):
    reg = make_reg(tmp_path)
    reg.claim("wlan1", "runA")
    assert reg.release("wlan1", "runB") is False         # not the owner -> no-op
    assert reg.busy_reason("wlan1", "runC") != ""        # still held
    assert reg.release("wlan1", "runA") is True


def test_release_runs_on_task_exception(tmp_path):
    """A claim guarded by try/finally is released even when the body raises."""
    reg = make_reg(tmp_path)
    with pytest.raises(RuntimeError):
        ok, _ = reg.claim("wlan1", "runX")
        assert ok
        try:
            raise RuntimeError("boom")
        finally:
            reg.release("wlan1", "runX")
    assert reg.busy_reason("wlan1", "other") == ""       # freed despite the error


# --- persistence + tolerance ----------------------------------------------
def test_persistence_across_instances(tmp_path):
    path = tmp_path / "data" / "state" / "interfaces.json"
    InterfaceRegistry(path).claim("wlan1", "runA")
    reloaded = InterfaceRegistry(path)                   # reads the persisted file
    assert reloaded.busy_reason("wlan1", "runB") != ""


def test_corrupt_state_file_loads_empty(tmp_path):
    path = tmp_path / "data" / "state" / "interfaces.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json ][", encoding="utf-8")
    assert InterfaceRegistry(path).reservations() == {}  # tolerant, no crash


def test_busy_reason_ignores_dead_holder(tmp_path):
    reg = make_reg(tmp_path)
    with reg.lock:
        reg._res["wlan1"] = {"mode": "monitor", "run_id": "ghost",
                             "pid": _dead_pid(), "ts": "t"}
        reg._save()
    assert reg.busy_reason("wlan1", "new") == ""         # dead holder -> free


# --- startup reset: free dead, keep live ----------------------------------
def test_reset_dead_frees_dead_keeps_live_injected(tmp_path):
    reg = make_reg(tmp_path)
    with reg.lock:
        reg._res["wlan1"] = {"mode": "monitor", "run_id": "dead", "pid": 42, "ts": "t"}
        reg._res["wlan2"] = {"mode": "monitor", "run_id": "live", "pid": 43, "ts": "t"}
        reg._save()
    freed = reg.reset_dead(is_alive=lambda r: r["run_id"] == "live")
    assert freed == ["wlan1"]
    res = reg.reservations()
    assert "wlan1" not in res and "wlan2" in res          # live reservation intact


def test_reset_dead_default_pid_liveness(tmp_path):
    reg = make_reg(tmp_path)
    with reg.lock:
        reg._res["wlan1"] = {"mode": "monitor", "run_id": "dead",
                             "pid": _dead_pid(), "ts": "t"}
        reg._res["wlan2"] = {"mode": "monitor", "run_id": "mine",
                             "pid": os.getpid(), "ts": "t"}
        reg._save()
    freed = reg.reset_dead()                              # PID-based liveness
    assert "wlan1" in freed and "wlan2" not in freed
    assert "wlan2" in reg.reservations()                  # our live run is kept


# --- the central safety check (one reused function) -----------------------
def test_central_check_refuses_default_route(tmp_path, monkeypatch):
    reg = make_reg(tmp_path)
    monkeypatch.setattr(state, "default_route_iface", lambda: "wlan0")
    monkeypatch.setattr(state, "ssh_iface", lambda: "")
    ok, reason = interface_safety_check("wlan0", run_id="r", reg=reg)
    assert not ok and "default route" in reason


def test_central_check_refuses_ssh(tmp_path, monkeypatch):
    reg = make_reg(tmp_path)
    monkeypatch.setattr(state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(state, "ssh_iface", lambda: "wlan1")
    ok, reason = interface_safety_check("wlan1", run_id="r", reg=reg)
    assert not ok and "SSH" in reason


def test_central_check_refuses_busy(tmp_path, monkeypatch):
    reg = make_reg(tmp_path)
    monkeypatch.setattr(state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(state, "ssh_iface", lambda: "")
    reg.claim("wlan1", "runA")
    ok, reason = interface_safety_check("wlan1", run_id="runB", reg=reg)
    assert not ok and "busy" in reason
    # the holder itself is allowed through
    ok2, _ = interface_safety_check("wlan1", run_id="runA", reg=reg)
    assert ok2


def test_central_check_ok_when_free_and_safe(tmp_path, monkeypatch):
    reg = make_reg(tmp_path)
    monkeypatch.setattr(state, "default_route_iface", lambda: "eth0")
    monkeypatch.setattr(state, "ssh_iface", lambda: "")
    ok, reason = interface_safety_check("wlan1", run_id="r", reg=reg)
    assert ok and reason == ""


# --- capture_tshark is NOT subjected to the registry / default-route refusal
def test_capture_tshark_does_not_use_interface_registry():
    """blue.capture_tshark captures on the default interface by design and must
    not claim/release or be gated by the monitor-mode safety check."""
    import inspect
    from plugins.blue import capture_tshark
    src = inspect.getsource(capture_tshark)
    for token in ("get_interface_registry", "interface_safety_check",
                  "InterfaceRegistry", "self_link_reason"):
        assert token not in src, f"capture_tshark must not reference {token}"
