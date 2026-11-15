# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase P1 — provisioning IPC (the privilege boundary).

Uses a REAL AF_UNIX socket in a temp dir (local, deterministic — no networking) plus
a fake handler that records what it receives, proving the portal→service path only
ever forwards validated {action,ssid,password} and that malformed input is rejected
before the handler runs.
"""
from __future__ import annotations

import threading
import time

from core import provisioning_ipc as IPC


# ── validate_request (unit) ─────────────────────────────────────────────────────
def test_validate_known_actions_and_join_fields():
    ok, _, clean = IPC.validate_request({"action": "status"})
    assert ok and clean == {"action": "status"}
    ok, _, clean = IPC.validate_request(
        {"action": "join", "ssid": "Home", "password": "correcthorse", "hidden": True})
    assert ok and clean["ssid"] == "Home" and clean["password"] == "correcthorse"
    assert clean["hidden"] is True
    # open network: empty password allowed
    ok, _, clean = IPC.validate_request({"action": "join", "ssid": "Open", "password": ""})
    assert ok and clean["password"] == ""


def test_validate_rejects_bad_requests():
    assert IPC.validate_request("nope")[0] is False
    assert IPC.validate_request({"action": "reboot"})[0] is False     # unknown
    assert IPC.validate_request({"action": "join"})[0] is False       # no ssid
    assert IPC.validate_request({"action": "join", "ssid": "x" * 33,
                                 "password": "12345678"})[0] is False  # ssid too long
    assert IPC.validate_request({"action": "join", "ssid": "ok",
                                 "password": "x" * 64})[0] is False    # psk too long
    assert IPC.validate_request({"action": "join", "ssid": "ok",
                                 "password": "short"})[0] is False     # psk < 8
    assert IPC.validate_request({"action": "join", "ssid": "a\nb",
                                 "password": "12345678"})[0] is False  # ctrl char
    assert IPC.validate_request({"action": "join", "ssid": "ok",
                                 "password": "pass\x00word"})[0] is False


def test_safe_for_log_redacts_password():
    red = IPC.safe_for_log({"action": "join", "ssid": "Home", "password": "secret"})
    assert red["password"] == "***" and red["ssid"] == "Home"


# ── socket round-trip (real AF_UNIX, temp dir) ──────────────────────────────────
def _run_server(sock_path, handler, stop):
    t = threading.Thread(target=IPC.serve,
                         kwargs={"socket_path": sock_path, "handler": handler,
                                 "stop_event": stop}, daemon=True)
    t.start()
    for _ in range(100):                       # wait for bind
        import os
        if os.path.exists(sock_path):
            break
        time.sleep(0.01)
    return t


def test_valid_request_reaches_handler(tmp_path):
    received = []
    sp = str(tmp_path / "prov.sock")
    stop = threading.Event()
    t = _run_server(sp, lambda req: (received.append(req) or {"ok": True, "state": "ap"}), stop)
    try:
        resp = IPC.send_request(sp, {"action": "join", "ssid": "Net", "password": "12345678"},
                                timeout=5)
        assert resp["ok"] is True and resp["state"] == "ap"
        assert received == [{"action": "join", "ssid": "Net", "password": "12345678",
                             "hidden": False}]
    finally:
        stop.set(); t.join(timeout=3)


def test_malformed_request_rejected_without_calling_handler(tmp_path):
    called = []
    sp = str(tmp_path / "prov.sock")
    stop = threading.Event()
    t = _run_server(sp, lambda req: called.append(req) or {"ok": True}, stop)
    try:
        # unknown action -> error, handler NOT called
        resp = IPC.send_request(sp, {"action": "rm-rf"}, timeout=5)
        assert resp["ok"] is False and "action" in resp["error"]
        assert called == []
    finally:
        stop.set(); t.join(timeout=3)


def test_client_degrades_when_service_down(tmp_path):
    resp = IPC.send_request(str(tmp_path / "nope.sock"), {"action": "status"}, timeout=1)
    assert resp["ok"] is False and "unavailable" in resp["error"]


def test_handler_exception_does_not_crash_loop(tmp_path):
    sp = str(tmp_path / "prov.sock")
    stop = threading.Event()

    def boom(req):
        raise RuntimeError("kaboom")

    t = _run_server(sp, boom, stop)
    try:
        resp = IPC.send_request(sp, {"action": "status"}, timeout=5)
        assert resp["ok"] is False and resp["error"] == "internal error"
        # server still alive -> a second request still gets a response
        resp2 = IPC.send_request(sp, {"action": "ping"}, timeout=5)
        assert resp2["ok"] is False and resp2["error"] == "internal error"
    finally:
        stop.set(); t.join(timeout=3)
