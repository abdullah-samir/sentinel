# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""blue.esp_sensor — ingest wireless-attack detections from the ESP32-S3 node.

**DEFENSIVE / PASSIVE INGEST.** This module only *reads* from the ESP32-S3
Wi-Fi attack DETECTION sensor (see `esp32/`) and turns its reports into Sentinel
Findings. It never transmits anything to the air; the ESP itself is a passive
detector.

Transport (serial is PRIMARY — the flashed firmware defaults to MODE_SNIFFER =
serial only, Wi-Fi/HTTP disabled):
  * **Serial** (default `/dev/ttyACM0` @ 115200): read newline JSON for a bounded
    duration. The port is opened ONLY for that read, via a context-managed
    iterator that ALWAYS releases it — we never hold it open. If the port is
    busy/locked (e.g. a `pio monitor` is attached) we log + emit one info finding
    and exit cleanly; we never crash or hang.
  * **HTTP** (alternate, when `esp_url` is set — for a MODE_CONNECTED reflash):
    poll `GET /status` + `GET /detections`.

The ESP JSON schemas are matched EXACTLY (see `esp32/README.md`):
  detection: {"t":"detection","type":...,"severity":...,"mac":...,"ssid":...,
              "channel":int,"uptime_ms":int,"evidence":...}
  heartbeat: {"t":"heartbeat","mode":...,"channel":int,"uptime_ms":int,
              "frames_seen":int,"dropped":int,"wifi_connected":bool,
              "detections_total":int}
  GET /status:     {"uptime_ms":...,"mode":"connected","channel":...,"frames_seen":...,
                    "dropped":...,"wifi_connected":true,"detections_total":...}
  GET /detections: {"count":N,"detections":[<detection objects>]}

Findings: each detection maps straight through (ESP severities info/low/medium/
high/critical already match Sentinel). Repeated detections of the same
(type, mac, channel) within a run collapse into ONE finding with an occurrence
count (mirrors the ESP's own rate-limiting). Heartbeats/status are liveness only
— they NEVER create findings; the latest is stashed on the ESP Asset for the
dashboard panel. The Pi stamps its own ingestion time on each finding; the ESP's
relative `uptime_ms` is kept in the detail/evidence, never used as the time.
"""
from __future__ import annotations

import json
import logging
import os
import stat
import time
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

from core.module import Manifest, Module
from core.registry import register
from core.schema import Severity

log = logging.getLogger("sentinel.blue.esp_sensor")

# The five detection types the ESP emits (anything else is ignored defensively).
DETECTION_TYPES = {
    "deauth_flood_src",
    "deauth_flood_aggregate",
    "beacon_flood",
    "beacon_ssid_spam",
    "evil_twin",
}

# Pretty titles for the detection types.
_PRETTY = {
    "deauth_flood_src": "Deauth/disassoc flood (per-source)",
    "deauth_flood_aggregate": "Deauth/disassoc flood (aggregate)",
    "beacon_flood": "Beacon flood",
    "beacon_ssid_spam": "Beacon SSID spam",
    "evil_twin": "Evil twin (duplicate SSID)",
}

_HTTP_POLL_INTERVAL = 3.0      # seconds between HTTP polls
_HTTP_PROBE_TIMEOUT = 2.0      # is_available HTTP probe (short — called per module list)


class PortBusy(Exception):
    """The serial port could not be opened (busy/locked/unplugged). Handled
    gracefully by run() — never propagated."""


# --------------------------------------------------------------------------- #
# low-level helpers (module-level so tests can monkeypatch them)
# --------------------------------------------------------------------------- #
def _import_serial():
    """Import pyserial lazily so plugin discovery never fails if it is absent."""
    try:
        import serial  # type: ignore
        return serial
    except Exception:  # noqa: BLE001
        return None


def _serial_present(port: str) -> bool:
    """True if `port` exists and is a character device."""
    try:
        return os.path.exists(port) and stat.S_ISCHR(os.stat(port).st_mode)
    except OSError:
        return False


def _can_access(port: str) -> bool:
    return os.access(port, os.R_OK | os.W_OK)


def _username() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return os.environ.get("USER", "user")


def _in_group(name: str) -> bool:
    """True if the current user is a member of group `name` (primary or
    supplementary). Defensive — never raises."""
    try:
        import grp
        g = grp.getgrnam(name)
        if g.gr_gid in os.getgroups():
            return True
        return _username() in (g.gr_mem or [])
    except Exception:  # noqa: BLE001
        return False


@contextmanager
def _open_serial(port: str, baud: int, read_timeout: float = 0.5):
    """Open the serial port EXCLUSIVELY and guarantee it is released.

    Raises PortBusy if it cannot be opened (another reader attached, locked, or
    unplugged between the availability check and now)."""
    serial = _import_serial()
    if serial is None:
        raise PortBusy("pyserial not installed")
    try:
        ser = serial.Serial(port=port, baudrate=baud, timeout=read_timeout,
                            exclusive=True)
    except Exception as e:  # noqa: BLE001 — SerialException et al.
        raise PortBusy(f"could not open {port}: {e}")
    try:
        yield ser
    finally:
        try:
            ser.close()
        except Exception:  # noqa: BLE001
            pass


def _iter_serial_lines(port: str, baud: int, duration: float) -> Iterator[str]:
    """Yield decoded serial lines for up to `duration` seconds, then stop. The
    port is always released (see _open_serial). Raises PortBusy on open failure."""
    deadline = time.monotonic() + max(0.0, float(duration))
    with _open_serial(port, baud) as ser:
        while time.monotonic() < deadline:
            try:
                raw = ser.readline()
            except Exception as e:  # noqa: BLE001 — a mid-read error ends the read
                log.debug("esp_sensor: serial read error: %s", e)
                break
            if not raw:
                continue                       # read timeout tick — keep going
            yield raw.decode("utf-8", "replace").rstrip()


def _http_get_json(base: str, path: str, timeout: float) -> Optional[dict]:
    """GET base+path and parse JSON. Returns the parsed object or None on error."""
    import httpx
    url = base.rstrip("/") + path
    r = httpx.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _http_status_ok(base: str, timeout: float = _HTTP_PROBE_TIMEOUT) -> bool:
    try:
        return isinstance(_http_get_json(base, "/status", timeout), dict)
    except Exception:  # noqa: BLE001
        return False


def _http_collect(base: str, duration: float, timeout: float = 5.0
                  ) -> Tuple[dict, List[dict], int]:
    """Poll /status + /detections for up to `duration` seconds. Returns
    (latest_status, unique_raw_detections, polls). Defensive: per-poll errors are
    logged and skipped, never raised."""
    status: dict = {}
    raw: List[dict] = []
    seen = set()
    deadline = time.monotonic() + max(0.0, float(duration))
    polls = 0
    while True:
        try:
            st = _http_get_json(base, "/status", timeout)
            if isinstance(st, dict):
                status = st
        except Exception as e:  # noqa: BLE001
            log.debug("esp_sensor: /status poll failed: %s", e)
        try:
            d = _http_get_json(base, "/detections", timeout)
            items = d.get("detections") if isinstance(d, dict) else None
            for obj in items or []:
                if not isinstance(obj, dict):
                    continue
                key = (obj.get("type"), obj.get("mac"), obj.get("channel"),
                       obj.get("uptime_ms"), obj.get("evidence"))
                if key in seen:
                    continue               # overlapping recent lists across polls
                seen.add(key)
                raw.append(obj)
        except Exception as e:  # noqa: BLE001
            log.debug("esp_sensor: /detections poll failed: %s", e)
        polls += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(_HTTP_POLL_INTERVAL, remaining))
    return status, raw, polls


# --- pure parsing helpers -------------------------------------------------- #
def _parse_json_line(line: str) -> Optional[dict]:
    """Parse one serial line as a JSON object, or None if it isn't one."""
    s = (line or "").strip()
    if not s or s[0] != "{":
        return None
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _valid_detection(obj: dict) -> bool:
    return obj.get("type") in DETECTION_TYPES


def _status_from(obj: dict) -> dict:
    """Project a heartbeat or /status object down to the status fields the
    dashboard panel shows."""
    return {
        "mode": obj.get("mode", ""),
        "channel": obj.get("channel", ""),
        "frames_seen": obj.get("frames_seen", ""),
        "dropped": obj.get("dropped", ""),
        "uptime_ms": obj.get("uptime_ms", ""),
        "wifi_connected": obj.get("wifi_connected", ""),
        "detections_total": obj.get("detections_total", ""),
    }


# --------------------------------------------------------------------------- #
# the module
# --------------------------------------------------------------------------- #
@register
class EspSensor(Module):
    manifest = Manifest(
        name="blue.esp_sensor",
        category="blue",
        title="ESP wireless sensor",
        description="Ingest wireless-attack detections (deauth/beacon floods, evil "
                    "twins) from the ESP32-S3 detector node over serial or HTTP.",
        requires_hw=["esp_sensor"],
        provides=["wireless_detections"],
        phase="1",
        display="ESP wireless sensor",
    )

    # --- availability -----------------------------------------------------
    def is_available(self, ctx) -> Tuple[bool, str]:
        cfg = ctx.config
        port = (getattr(cfg, "esp_serial_port", "") or "/dev/ttyACM0")
        url = (getattr(cfg, "esp_url", "") or "").strip()
        try:
            if _serial_present(port):
                if _import_serial() is None:
                    return (False, "pyserial not installed (pip install pyserial)")
                if not _can_access(port) and not _in_group("dialout"):
                    user = _username()
                    return (False, f"{port} is present but not accessible — add "
                                   f"'{user}' to the dialout group: "
                                   f"sudo usermod -aG dialout {user} (then re-login)")
                return (True, "")
            if url and _http_status_ok(url):
                return (True, "")
        except Exception as e:  # noqa: BLE001 — probe must never raise
            return (False, f"ESP sensor probe failed: {e}")
        reason = f"ESP sensor not found: serial device {port} not present"
        reason += " and esp_url not set" if not url else f" and {url}/status did not respond"
        return (False, reason)

    # --- run --------------------------------------------------------------
    def run(self, ctx) -> None:
        cfg = ctx.config
        port = (getattr(cfg, "esp_serial_port", "") or "/dev/ttyACM0")
        baud = int(getattr(cfg, "esp_baud", 115200) or 115200)
        url = (getattr(cfg, "esp_url", "") or "").strip()
        duration = max(0, int(getattr(cfg, "esp_listen_seconds", 30) or 30))
        transport = "http" if url else "serial"
        source = url if transport == "http" else port

        status: dict = {}
        raw_detections: List[dict] = []
        heartbeats = 0
        malformed = 0
        busy = False
        read_error = ""

        try:
            if transport == "http":
                ctx.log.info("esp_sensor: polling %s for %ds (HTTP)", url, duration)
                status, raw_detections, heartbeats = _http_collect(url, duration)
            else:
                ctx.log.info("esp_sensor: reading %s @ %d for %ds (serial)",
                             port, baud, duration)
                for line in _iter_serial_lines(port, baud, duration):
                    obj = _parse_json_line(line)
                    if obj is None:
                        malformed += 1
                        ctx.log.debug("esp_sensor: skipped malformed line: %r", line)
                        continue
                    t = obj.get("t")
                    if t == "detection":
                        if _valid_detection(obj):
                            raw_detections.append(obj)
                        else:
                            malformed += 1
                            ctx.log.debug("esp_sensor: unknown detection type: %r",
                                          obj.get("type"))
                    elif t == "heartbeat":
                        heartbeats += 1
                        status = _status_from(obj)        # latest wins
                    # boot/info/error lines: ignore (not malformed, not findings)
        except PortBusy as e:
            busy = True
            read_error = str(e)
            ctx.log.info("esp_sensor: serial port busy/unavailable — %s", e)
        except Exception as e:  # noqa: BLE001 — a read failure must not crash the run
            read_error = str(e)
            ctx.log.error("esp_sensor: read failed: %s", e)

        # Detections -> deduplicated findings (never from heartbeats).
        emitted = self._emit_detections(ctx, raw_detections)

        if busy:
            ctx.store.add_finding(
                module=self.manifest.name, type="esp_sensor_busy",
                severity=Severity.INFO, target=f"esp:{source}",
                title="ESP serial port busy",
                detail=(f"The ESP serial port {port} is busy or unavailable — another "
                        "reader (e.g. a serial monitor) may be attached, or the device "
                        "was unplugged. Skipped this run cleanly without holding the port."),
                evidence=read_error, tags=["esp", "wireless", "skipped"])
        elif read_error:
            ctx.store.add_finding(
                module=self.manifest.name, type="module_error",
                severity=Severity.LOW, target=f"esp:{source}",
                title="ESP sensor read failed", detail=read_error,
                evidence=transport, tags=["esp", "wireless", "error"])

        alive = (not busy) and (heartbeats > 0 or bool(status) or bool(raw_detections))
        self._record_source(ctx, transport, source, status, alive, heartbeats,
                            malformed, emitted, busy)
        ctx.log.info("esp_sensor: %s — %d detection(s) -> %d finding(s), %d heartbeat(s), "
                     "%d malformed", transport, len(raw_detections), emitted, heartbeats,
                     malformed)

    # --- helpers ----------------------------------------------------------
    def _emit_detections(self, ctx, raw: List[dict]) -> int:
        """Collapse repeated (type, mac, channel) detections into one finding
        each (with an occurrence count). Returns the number of findings emitted."""
        acc: Dict[tuple, dict] = {}
        order: List[tuple] = []
        for d in raw:
            typ = d.get("type", "")
            mac = (d.get("mac") or "").strip()
            ch = str(d.get("channel", "")).strip()
            key = (typ, mac.lower(), ch)
            if key not in acc:
                acc[key] = {"count": 0, "first": d}
                order.append(key)
            acc[key]["count"] += 1
        for key in order:
            info = acc[key]
            d = info["first"]
            count = info["count"]
            typ, _, ch = key
            ssid = (d.get("ssid") or "").strip()
            mac = (d.get("mac") or "").strip()
            sev = d.get("severity", "info")
            uptime = d.get("uptime_ms", "")
            esp_evidence = (d.get("evidence") or "").strip()
            offender = mac or ssid or (f"ch{ch}" if ch else "(esp)")
            pretty = _PRETTY.get(typ, typ)
            title = f"ESP: {pretty}"
            if offender:
                title += f" — {offender}"
            detail = (f"{count} occurrence(s) collapsed within this run. "
                      f"SSID={ssid or '-'}, channel={ch or '-'}, "
                      f"offender MAC={mac or '-'}. ESP evidence: {esp_evidence or '-'}. "
                      f"ESP uptime_ms={uptime} (relative to ESP boot — not wall-clock).")
            evidence = (f"{count}x type={typ} mac={mac or '-'} ch={ch or '-'}; "
                        f"esp_evidence={esp_evidence or '-'}; esp_uptime_ms={uptime}")
            ctx.store.add_finding(
                module=self.manifest.name, type=typ, severity=sev,
                target=offender, title=title, detail=detail, evidence=evidence,
                tags=["wireless", "esp", "detection", typ])
        return len(order)

    def _record_source(self, ctx, transport: str, source: str, status: dict,
                        alive: bool, heartbeats: int, malformed: int,
                        emitted: int, busy: bool) -> None:
        """Record the ESP as an Asset, stashing its latest status on `extra` for
        the dashboard panel. Heartbeats never create findings — this is where
        their liveness/status lands instead."""
        extra = {
            "transport": transport,
            "source": source,
            "alive": alive,
            "busy": busy,
            "heartbeats": heartbeats,
            "malformed_lines": malformed,
            "findings_emitted": emitted,
            "mode": status.get("mode", ""),
            "channel": status.get("channel", ""),
            "frames_seen": status.get("frames_seen", ""),
            "dropped": status.get("dropped", ""),
            "uptime_ms": status.get("uptime_ms", ""),
            "wifi_connected": status.get("wifi_connected", ""),
            "detections_total": status.get("detections_total", ""),
        }
        ctx.store.add_asset(
            ip=f"esp:{source}", kind="esp_sensor", alive=alive,
            hostname="ESP32-S3 Wi-Fi detection sensor", vendor="Espressif",
            channel=str(status.get("channel", "") or ""), extra=extra)
