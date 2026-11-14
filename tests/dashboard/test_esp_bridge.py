# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Tests for dashboard.esp_bridge.EspBridge — deterministic, NO real device.

A fake serial (injected via serial_factory) and a fake clock drive everything;
router/reassembly/getter tests call the synchronous helpers directly, and only the
reconnect test runs the actual reader thread (bounded, fast reconnect)."""
from __future__ import annotations

import asyncio
import json
import time

from core.config import Config
from dashboard import esp_bridge as mod
from dashboard.esp_bridge import EspBridge


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeSerial:
    """Minimal pyserial stand-in. Returns queued chunks from read(), can raise a
    serial error at the Nth read, and records writes."""
    def __init__(self, chunks=None, raise_at=None):
        self._chunks = list(chunks or [])
        self.raise_at = raise_at
        self._reads = 0
        self.written = []
        self.is_open = True

    @property
    def in_waiting(self):
        return len(self._chunks[0]) if self._chunks else 0

    def read(self, n=1):
        self._reads += 1
        if self.raise_at is not None and self._reads >= self.raise_at:
            raise OSError("simulated serial error")
        if self._chunks:
            return self._chunks.pop(0)
        time.sleep(0.005)          # emulate a read-timeout tick
        return b""

    def write(self, data):
        if not self.is_open:
            raise OSError("port closed")
        self.written.append(data)
        return len(data)

    def close(self):
        self.is_open = False


class FakeLoop:
    """Runs call_soon_threadsafe synchronously so a push is observable at once."""
    def call_soon_threadsafe(self, fn, *args):
        fn(*args)


def _bridge(tmp_path, **kw):
    cfg = Config(root=tmp_path, esp_serial_port="/dev/fake")
    return EspBridge(cfg, **kw)


# --- send_command ----------------------------------------------------------
def test_send_command_writes_verbatim_and_false_when_closed(tmp_path):
    b = _bridge(tmp_path)
    assert b.send_command("scan") is False          # no port open yet
    fake = FakeSerial()
    b._serial = fake
    assert b.send_command("scan") is True
    assert fake.written == [b"scan\n"]              # EXACTLY b"scan\n"
    fake.written.clear()
    assert b.send_command("setchannel 20\r\n") is True
    assert fake.written == [b"setchannel 20\n"]     # trailing ws stripped, one \n added
    fake.close()
    assert b.send_command("scan") is False          # closed -> write raises -> False


# --- router ----------------------------------------------------------------
def test_router_routes_by_t(tmp_path):
    b = _bridge(tmp_path, clock=FakeClock())
    b._route_line('{"t":"heartbeat","channel":6,"uptime_ms":5000}')
    assert b.latest_status()["channel"] == 6
    b._route_line('{"t":"detection","type":"deauth_flood_src","mac":"AA"}')
    assert len(b.recent_detections()) == 1
    assert b.latest_detection()["type"] == "deauth_flood_src"
    b._route_line('{"t":"scan_result","id":1,"channels":[]}')
    assert b.latest_result("scan_result")["id"] == 1
    b._route_line('{"t":"ack","id":1,"cmd":"scan"}')
    assert b.last_ack()["cmd"] == "scan"


def test_unknown_t_and_non_json_go_to_logs(tmp_path):
    b = _bridge(tmp_path)
    b._route_line('{"t":"weird","x":1}')            # unknown t
    b._route_line('{"nope":true}')                  # missing t
    b._route_line('[I] human log line')             # non-JSON
    b._route_line('{"t":"boot","sensor":"x"}')      # boot -> logs, not status
    logs = b.recent_logs()
    assert '{"t":"weird","x":1}' in logs
    assert '{"nope":true}' in logs
    assert '[I] human log line' in logs
    assert '{"t":"boot","sensor":"x"}' in logs
    assert b.latest_status() is None               # none of those are heartbeats


def test_line_reassembled_across_two_reads(tmp_path):
    b = _bridge(tmp_path)
    b._feed(b'{"t":"heart')
    assert b.latest_status() is None               # nothing complete yet
    b._feed(b'beat","channel":11}\n')
    assert b.latest_status()["channel"] == 11


# --- liveness --------------------------------------------------------------
def test_is_alive_tracks_heartbeat_window(tmp_path):
    clk = FakeClock()
    b = _bridge(tmp_path, clock=clk)
    assert b.is_alive() is False                   # no heartbeat yet
    b._route_line('{"t":"heartbeat","channel":1}')
    assert b.is_alive() is True
    clk.advance(14.9)
    assert b.is_alive() is True
    clk.advance(0.2)                               # now > 15 s
    assert b.is_alive() is False


# --- subscribers -----------------------------------------------------------
def test_listener_receives_frames(tmp_path):
    b = _bridge(tmp_path)
    loop, q = FakeLoop(), asyncio.Queue()
    b.add_listener(loop, q)
    b._route_line('{"t":"heartbeat","channel":9}')
    evt, payload = q.get_nowait()
    assert evt == "line" and payload == '{"t":"heartbeat","channel":9}'
    b.remove_listener(loop, q)
    b._route_line('{"t":"heartbeat","channel":10}')
    assert q.empty()                               # no frames after removal


# --- reader thread: reconnect on serial error ------------------------------
def test_thread_releases_claim_and_reconnects_on_error(tmp_path, monkeypatch):
    opens, releases = [], []

    def factory(**kw):
        fs = FakeSerial(chunks=[b'{"t":"heartbeat","channel":3}\n'], raise_at=2)
        opens.append(fs)
        return fs

    monkeypatch.setattr(mod, "claim_serial", lambda port, label="", config=None: None)
    monkeypatch.setattr(mod, "release_serial",
                        lambda port, config=None: releases.append(port) or True)

    b = _bridge(tmp_path, serial_factory=factory, reconnect_delay=0.01)
    b.start()
    deadline = time.time() + 3.0
    while time.time() < deadline and len(opens) < 2:
        time.sleep(0.02)
    alive_during = b._thread is not None and b._thread.is_alive()
    b.stop()

    assert len(opens) >= 2                          # re-opened after the error
    assert releases                                 # claim released on the error path
    assert alive_during                             # thread stayed alive through it
    assert b.latest_status()["channel"] == 3        # the pre-error heartbeat was routed
    assert not (b._thread and b._thread.is_alive())  # stopped cleanly


def test_start_stop_idempotent_without_device(tmp_path):
    # Absent/failing port must never raise from start(); thread just reconnects.
    def failing_factory(**kw):
        raise OSError("no such device")
    b = _bridge(tmp_path, serial_factory=failing_factory, reconnect_delay=0.01)
    b.start()
    b.start()                                       # idempotent
    time.sleep(0.05)
    b.stop()
    b.stop()                                        # idempotent
    assert not (b._thread and b._thread.is_alive())
