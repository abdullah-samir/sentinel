# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""dashboard/esp_bridge.py — persistent ESP32-S3 serial bridge for the live dashboard.

**Single owner of the ESP serial port.** `blue.esp_sensor` opens the port only for
a bounded `esp_monitor` run and releases it; a live dashboard instead needs ONE
long-lived owner that both *sends* console commands and *reads everything back*.
Two owners cannot share an exclusive serial handle, so while this bridge is active
it is the sole owner: it records a port claim in core (`core.state.claim_serial`)
and `blue.esp_sensor` stands down (see its `is_available`).

Design notes
------------
* Fully opt-in: constructed always, but only `start()`-ed when
  `config.esp_bridge_enabled`. With it off, behaviour is unchanged.
* The reader runs in ONE daemon thread whose entire loop is wrapped so nothing —
  a serial glitch, an unplug, a decode error — can kill it; it just reconnects.
* `start()` never opens the port synchronously and never raises: an absent port
  simply enters reconnect mode.
* All shared state is guarded by a single lock; no getter or the thread ever
  raises out.
* SSE fan-out uses EXACTLY the mechanism in `dashboard/live.py`
  (`loop.call_soon_threadsafe(queue.put_nowait, (event, payload))`).

This module adds NO routes — E3 adds the control page, the SSE route, and rewires
the ESP panel.
"""
from __future__ import annotations

import collections
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

from core.state import claim_serial, release_serial

log = logging.getLogger("sentinel.dashboard.esp_bridge")

_DETECTIONS_MAX = 200
_LOG_MAX = 300
_ALIVE_WINDOW = 15.0       # a heartbeat within this many seconds == "alive"
_RECONNECT_DELAY = 2.0     # seconds between reconnect attempts
_READ_TIMEOUT = 0.5        # serial read timeout (also the stop-flag poll cadence)
_WRITE_TIMEOUT = 1.0       # never block a getter behind a stuck write

_RESULT_KINDS = ("scan_result", "search_result", "status_result")


def _default_serial_factory(**kwargs):
    """Default factory == ``serial.Serial(**kwargs)``, imported lazily so the
    dashboard still imports if pyserial is absent (the thread then just stays in
    reconnect mode). Tests inject a fake factory instead."""
    import serial  # type: ignore
    return serial.Serial(**kwargs)


class EspBridge:
    def __init__(self, config, *, serial_factory=_default_serial_factory,
                 clock=time.monotonic, reconnect_delay: float = _RECONNECT_DELAY) -> None:
        self._config = config
        self._port = getattr(config, "esp_serial_port", "") or "/dev/ttyACM0"
        self._baud = int(getattr(config, "esp_baud", 115200) or 115200)
        self._serial_factory = serial_factory
        self._clock = clock
        self._reconnect_delay = reconnect_delay

        self._lock = threading.Lock()         # guards ALL shared state below
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._serial = None                   # the open port, or None
        self._buffer = b""                    # partial-line accumulator (reader-only)

        # routed state
        self._latest_status: Optional[dict] = None
        self._last_heartbeat_ts: Optional[float] = None
        self._detections = collections.deque(maxlen=_DETECTIONS_MAX)
        self._latest_detection: Optional[dict] = None
        self._latest_result: Dict[str, dict] = {}
        self._last_ack: Optional[dict] = None
        self._last_nak: Optional[dict] = None
        self._logs = collections.deque(maxlen=_LOG_MAX)

        self._listeners: List[Tuple] = []     # (loop, queue)
        self._connected = False               # for disconnect/reconnect transition logs

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        """Idempotent. Spawn the reader thread and return immediately. Never
        opens the port synchronously, never raises."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            t = threading.Thread(target=self._run, name="esp-bridge", daemon=True)
            self._thread = t
        t.start()

    def stop(self) -> None:
        """Idempotent. Signal the thread, join with a timeout, close the port,
        release the core serial claim."""
        self._stop.set()
        with self._lock:
            t = self._thread
            self._thread = None
        if t is not None:
            t.join(timeout=self._read_timeout_join())
        # Ensure the port is closed and the claim released even if the thread was
        # already gone (both operations are idempotent / guarded).
        self._close_port()
        try:
            release_serial(self._port, config=self._config)
        except Exception:  # noqa: BLE001
            pass

    def _read_timeout_join(self) -> float:
        # Give the reader a little longer than one read timeout to unwind.
        return max(1.0, _READ_TIMEOUT * 2 + 0.5)

    # --- reader thread ----------------------------------------------------
    def _run(self) -> None:
        """The whole loop is wrapped: no error ever kills the thread."""
        while not self._stop.is_set():
            try:
                self._session()
            except Exception as e:  # noqa: BLE001 — belt and suspenders
                log.debug("esp_bridge: session error: %s", e)
                self._on_disconnect()
            if self._stop.is_set():
                break
            # retry opening every ~reconnect_delay (interruptible by stop())
            self._stop.wait(self._reconnect_delay)

    def _session(self) -> None:
        """One connect→read→(error/close) cycle. Opening may reset the ESP, so
        boot-ROM noise simply flows through as non-JSON log lines."""
        try:
            ser = self._serial_factory(port=self._port, baudrate=self._baud,
                                       timeout=_READ_TIMEOUT, write_timeout=_WRITE_TIMEOUT,
                                       exclusive=True)
        except Exception as e:  # noqa: BLE001 — absent/busy port -> reconnect mode
            self._on_disconnect()
            log.debug("esp_bridge: open %s failed: %s", self._port, e)
            return
        with self._lock:
            self._serial = ser
            self._buffer = b""
        try:
            claim_serial(self._port, label="dashboard ESP bridge", config=self._config)
        except Exception:  # noqa: BLE001
            pass
        self._on_connect()
        try:
            while not self._stop.is_set():
                data = self._read_available(ser)
                if data:
                    self._feed(data)
        finally:
            self._close_port()
            try:
                release_serial(self._port, config=self._config)
            except Exception:  # noqa: BLE001
                pass
            self._on_disconnect()

    @staticmethod
    def _read_available(ser) -> bytes:
        """Read buffered bytes without waiting for a full chunk; fall back to a
        1-byte timed read so the loop still wakes to check the stop flag. Any
        serial error propagates to end the session (then reconnect)."""
        try:
            waiting = ser.in_waiting
        except Exception:  # noqa: BLE001 — not all backends expose in_waiting
            waiting = 0
        return ser.read(waiting if waiting else 1)

    def _feed(self, data: bytes) -> None:
        """Accumulate bytes, split complete lines on b'\\n', keep the remainder."""
        self._buffer += data
        while b"\n" in self._buffer:
            raw, self._buffer = self._buffer.split(b"\n", 1)
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                self._route_line(line)

    def _route_line(self, line: str) -> None:
        """Route ONE decoded, non-empty line by its JSON "t"; push the raw line
        to subscribers. Never raises."""
        try:
            self._publish("line", line)
            obj = None
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    obj = parsed
            except (ValueError, TypeError):
                obj = None
            if obj is None:
                self._append_log(line)            # non-JSON (human logs, boot noise)
                return
            t = obj.get("t")
            with self._lock:
                if t == "heartbeat":
                    self._latest_status = obj
                    self._last_heartbeat_ts = self._clock()
                elif t == "detection":
                    self._detections.append(obj)
                    self._latest_detection = obj
                elif t in _RESULT_KINDS:
                    self._latest_result[t] = obj
                elif t == "ack":
                    self._last_ack = obj
                elif t == "nak":
                    self._last_nak = obj
                else:
                    # boot/info/error OR any unknown/missing "t" -> the log deque
                    self._logs.append(line)
        except Exception as e:  # noqa: BLE001 — a bad line must never kill the reader
            log.debug("esp_bridge: route error: %s", e)

    def _append_log(self, line: str) -> None:
        with self._lock:
            self._logs.append(line)

    def _close_port(self) -> None:
        with self._lock:
            ser = self._serial
            self._serial = None
        if ser is not None:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    def _on_connect(self) -> None:
        with self._lock:
            was = self._connected
            self._connected = True
        if not was:
            log.info("esp_bridge: connected to %s @ %d", self._port, self._baud)

    def _on_disconnect(self) -> None:
        with self._lock:
            was = self._connected
            self._connected = False
        if was:
            log.info("esp_bridge: disconnected from %s (will retry)", self._port)

    # --- commands ---------------------------------------------------------
    def send_command(self, text: str) -> bool:
        """Thread-safe write of exactly ``text.rstrip()+"\\n"`` VERBATIM — never
        inject an id or alter the command (the firmware console owns its syntax).
        Returns False if the port isn't currently open; never raises."""
        payload = (text.rstrip() + "\n").encode("utf-8", errors="replace")
        with self._lock:
            ser = self._serial
            if ser is None:
                return False
            try:
                ser.write(payload)
                return True
            except Exception as e:  # noqa: BLE001 — closed/unplugged mid-write
                log.debug("esp_bridge: write failed: %s", e)
                return False

    # --- getters (lock-guarded, return copies) ----------------------------
    def latest_status(self) -> Optional[dict]:
        with self._lock:
            return dict(self._latest_status) if self._latest_status is not None else None

    def recent_detections(self) -> List[dict]:
        with self._lock:
            return list(self._detections)

    def latest_detection(self) -> Optional[dict]:
        with self._lock:
            return dict(self._latest_detection) if self._latest_detection is not None else None

    def latest_result(self, kind: str) -> Optional[dict]:
        with self._lock:
            r = self._latest_result.get(kind)
            return dict(r) if r is not None else None

    def recent_logs(self) -> List[str]:
        with self._lock:
            return list(self._logs)

    def last_ack(self) -> Optional[dict]:
        with self._lock:
            return dict(self._last_ack) if self._last_ack is not None else None

    def last_nak(self) -> Optional[dict]:
        with self._lock:
            return dict(self._last_nak) if self._last_nak is not None else None

    def is_alive(self) -> bool:
        """True iff a heartbeat arrived within ~15 s (by the injected clock)."""
        with self._lock:
            ts = self._last_heartbeat_ts
        return ts is not None and (self._clock() - ts) <= _ALIVE_WINDOW

    # --- subscribers (SSE) ------------------------------------------------
    def add_listener(self, loop, queue) -> None:
        with self._lock:
            self._listeners.append((loop, queue))

    def remove_listener(self, loop, queue) -> None:
        with self._lock:
            self._listeners = [(l, q) for (l, q) in self._listeners if q is not queue]

    def _publish(self, event: str, payload) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for loop, queue in listeners:
            try:
                # EXACTLY dashboard/live.py's mechanism. call_soon_threadsafe never
                # blocks the reader; a full bounded queue drops the frame (put_nowait
                # raises QueueFull in the loop, not here).
                loop.call_soon_threadsafe(queue.put_nowait, (event, payload))
            except Exception:  # noqa: BLE001 — a dead listener must not break others
                pass
