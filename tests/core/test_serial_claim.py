# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Tests for the core serial-port ownership claim and blue.esp_sensor standing
down for a live claim. No real device; another 'live' owner is simulated with a
real but unrelated alive PID (the parent), a dead one with a reaped subprocess."""
from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

from core.config import Config
from core.state import (claim_serial, release_serial, serial_claimed_by_other,
                        serial_state_path)

PORT = "/dev/ttyACM0"


def _write_claim(cfg, pid, label="x"):
    p = serial_state_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({PORT: {"label": label, "pid": pid}}), encoding="utf-8")


def _dead_pid() -> int:
    pr = subprocess.Popen(["true"])
    pr.wait()                      # reaped -> its PID is no longer a live process
    return pr.pid


# --- claim / release round-trip -------------------------------------------
def test_claim_release_roundtrip_same_process(tmp_path):
    cfg = Config(root=tmp_path)
    assert serial_claimed_by_other(PORT, config=cfg) == ""     # free
    claim_serial(PORT, label="dashboard ESP bridge", config=cfg)
    assert serial_state_path(cfg).exists()
    # our OWN claim is never "by other"
    assert serial_claimed_by_other(PORT, config=cfg) == ""
    assert release_serial(PORT, config=cfg) is True
    assert release_serial(PORT, config=cfg) is False           # idempotent


# --- by-other detection ----------------------------------------------------
def test_claimed_by_other_alive_pid(tmp_path):
    cfg = Config(root=tmp_path)
    _write_claim(cfg, os.getppid(), label="dashboard ESP bridge")  # alive, != us
    reason = serial_claimed_by_other(PORT, config=cfg)
    assert reason and "dashboard ESP bridge" in reason


def test_claimed_by_dead_pid_is_inert(tmp_path):
    cfg = Config(root=tmp_path)
    _write_claim(cfg, _dead_pid())
    assert serial_claimed_by_other(PORT, config=cfg) == ""


def test_no_claim_file_is_inert(tmp_path):
    cfg = Config(root=tmp_path)
    assert serial_claimed_by_other(PORT, config=cfg) == ""


# --- esp_sensor stands down for a live claim, unchanged otherwise ----------
def test_esp_sensor_stands_down_for_live_bridge_claim(tmp_path):
    from plugins.blue.esp_sensor import EspSensor
    cfg = Config(root=tmp_path, esp_serial_port=PORT)
    ctx = SimpleNamespace(config=cfg)

    # No claim -> normal availability path (device may be present or not, but the
    # reason is NEVER the bridge reason — existing behavior unchanged).
    _, reason = EspSensor().is_available(ctx)
    assert reason != "ESP serial owned by the dashboard bridge"

    # Live claim by another process -> stand down with the exact reason.
    _write_claim(cfg, os.getppid(), label="dashboard ESP bridge")
    ok, reason = EspSensor().is_available(ctx)
    assert ok is False and reason == "ESP serial owned by the dashboard bridge"

    # Dead-pid claim -> inert again (back to normal behavior).
    _write_claim(cfg, _dead_pid())
    _, reason3 = EspSensor().is_available(ctx)
    assert reason3 != "ESP serial owned by the dashboard bridge"
