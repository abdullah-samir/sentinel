# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""View-model + helpers for the live ESP control page (Phase E3).

Pure, dependency-light helpers the routes and template share. No serial, no I/O,
no framework imports — trivially unit-testable.

  - COMMANDS / MODES  : data-driven convenience buttons (the free-text box is the
                        real extensibility path; these are only shortcuts).
  - sanitize_command(): the single input filter the POST route enforces.
  - esp_chart_series(): scan_result -> flat [{mhz,value}] for the spectrum chart,
                        built against the REAL firmware shape (modules[].hits[] of
                        {ch,freq,hits}); tolerant of an older flat channels[] shape.
  - normalize_stream_item(): one bridge listener item -> (raw_text, obj?).
  - catalog_from_logs(): newest help_result parsed out of recent log lines.

Field names here were taken from a live step-0 probe of the flashed firmware
(help_result/status_result/scan_result/heartbeat) — not assumed.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from dashboard.live import sse

# The firmware console silently truncates past CONSOLE_BUF-1 chars (a 48-byte
# buffer here -> 47) and past CONSOLE_MAX_TOKENS whitespace tokens. The dashboard
# enforces length only; the firmware enforces the token count. New commands must
# stay <= 4 tokens. Set this to match your firmware's CONSOLE_BUF - 1.
ESP_CMD_MAX_LEN = 47

# Data-driven convenience buttons. Adding an entry renders a button — nothing else
# changes. `arg` (optional) renders a bounded number input appended to `cmd`. These
# are shortcuts only: any command (current or future) works from the free-text box,
# so this list never has to be exhaustive.
COMMANDS: list[dict] = [
    {"label": "Start", "cmd": "start"},
    {"label": "Stop", "cmd": "stop"},
    {"label": "Status", "cmd": "status"},
    {"label": "Diag", "cmd": "diag"},
    {"label": "Self-test", "cmd": "selftest"},
    {"label": "Help", "cmd": "help"},
    {"label": "Scan", "cmd": "scan", "arg": {"min": 1, "max": 200, "default": 1}},
    {"label": "Search", "cmd": "search", "arg": {"min": 1, "max": 200, "default": 1}},
    {"label": "Channel", "cmd": "ch", "arg": {"min": 0, "max": 125, "default": 0}},
    {"label": "Power", "cmd": "power", "arg": {"min": 0, "max": 3, "default": 3}},
    {"label": "Dwell", "cmd": "dwell", "arg": {"min": 0, "max": 5000, "default": 60}},
    {"label": "Debug", "cmd": "debug", "arg": {"min": 0, "max": 4, "default": 0}},
]

# Scan-mode selectors (single letters) with human labels, from the firmware's
# help_result.modes. Overridden at runtime when live discovery succeeds; this is
# the offline fallback.
MODES: dict[str, str] = {
    "r": "random bluetooth odd/even",
    "w": "wifi",
    "b": "ble advertising",
    "u": "usb wireless",
    "v": "video streaming",
    "c": "rc toys/drones",
    "f": "full spectrum",
    "i": "ism band 2401-2483 MHz",
}

_PRINTABLE = frozenset(range(0x20, 0x7F))   # printable ASCII, space..'~'


def sanitize_command(raw: Any) -> str:
    """Reduce arbitrary input to ONE safe console line: drop CR/LF and every other
    control char, keep only printable ASCII (0x20-0x7E), then strip the ends.
    Returns '' for empty/all-filtered input. Never raises. The POST route rejects
    '' (400) and anything longer than ESP_CMD_MAX_LEN (400)."""
    if raw is None:
        return ""
    s = "".join(ch for ch in str(raw) if ord(ch) in _PRINTABLE)   # drops \r \n \t ...
    return s.strip()


def esp_chart_series(scan_result: Any) -> list[dict]:
    """Flatten a scan_result into [{'mhz': int, 'value': int}] sorted by mhz.

    Real firmware shape: {'modules':[{'hits':[{'ch','freq','hits'}, ...]}, ...]}.
    Also accepts an older flat {'channels':[{'mhz','rpd','hits'}, ...]}.
    value = hits if present, else rpd, else 0; duplicate freqs are summed.
    Missing/short/empty or non-dict input -> [] (the chart shows its placeholder)."""
    if not isinstance(scan_result, dict):
        return []
    rows: list[dict] = []
    mods = scan_result.get("modules")
    if isinstance(mods, list):
        for m in mods:
            hits = m.get("hits") if isinstance(m, dict) else None
            if isinstance(hits, list):
                rows.extend(h for h in hits if isinstance(h, dict))
    chans = scan_result.get("channels")
    if isinstance(chans, list):
        rows.extend(h for h in chans if isinstance(h, dict))
    agg: dict[int, int] = {}
    for h in rows:
        mhz = h.get("freq", h.get("mhz"))
        if mhz is None:
            continue
        try:
            mhz = int(mhz)
        except (TypeError, ValueError):
            continue
        val = h.get("hits", h.get("rpd", 0))
        try:
            val = int(val)
        except (TypeError, ValueError):
            val = 0
        agg[mhz] = agg.get(mhz, 0) + val
    return [{"mhz": k, "value": agg[k]} for k in sorted(agg)]


def normalize_stream_item(item: Any) -> tuple[str, Optional[dict]]:
    """Map one bridge listener item to (raw_text, obj?) for the SSE route.
      - a str                 -> raw=str; json.loads -> obj if it's a dict
      - (name, str)           -> raw=str; parse as above
      - (name, dict) / a dict -> obj=dict; raw=json.dumps(dict)
    Never raises; obj is None when the text is not a JSON object."""
    payload = item[1] if isinstance(item, tuple) and len(item) == 2 else item
    if isinstance(payload, dict):
        try:
            raw = json.dumps(payload)
        except (TypeError, ValueError):
            raw = str(payload)
        return raw, payload
    raw = payload if isinstance(payload, str) else str(payload)
    obj: Optional[dict] = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            obj = parsed
    except (ValueError, TypeError):
        obj = None
    return raw, obj


def stream_snapshot(bridge) -> dict:
    """The initial SSE payload: current status + last logs so a fresh page paints
    immediately, before any live frame arrives."""
    return {
        "status": bridge.latest_status(),
        "status_result": bridge.latest_result("status_result"),
        "scan_result": bridge.latest_result("scan_result"),
        "logs": list(bridge.recent_logs())[-200:],
        "alive": bridge.is_alive(),
    }


async def esp_stream_events(bridge, *, idle_timeout: float = 15.0):
    """Async SSE generator for /esp/stream. Registers a bounded listener BEFORE the
    snapshot, then for each bridge item emits sse('line', raw) always and, when the
    item is a JSON object with a 't', also sse('frame', obj). Idle beats send a
    'tick'. Always deregisters in finally. Kept at module scope so it is unit-tested
    directly (TestClient buffers streaming responses, so it can't drive it)."""
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    bridge.add_listener(loop, queue)
    try:
        yield sse("snapshot", stream_snapshot(bridge))
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=idle_timeout)
            except asyncio.TimeoutError:
                yield sse("tick", {"alive": bridge.is_alive()})
                continue
            raw, obj = normalize_stream_item(item)
            yield sse("line", raw)
            if isinstance(obj, dict) and "t" in obj:
                yield sse("frame", obj)
    finally:
        bridge.remove_listener(loop, queue)


def catalog_from_logs(log_lines) -> dict:
    """Best-effort command catalog from the newest help_result in recent logs.
    Returns {'commands':[...], 'modes':{...}, 'source':'firmware'|'static'}. The
    firmware's help_result is clean JSON (confirmed by the step-0 probe); when none
    has streamed yet, fall back to the static COMMANDS/MODES so buttons still work."""
    for line in reversed(list(log_lines or [])):
        if not isinstance(line, str) or '"help_result"' not in line:
            continue
        try:
            o = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(o, dict) and o.get("t") == "help_result":
            cmds = o.get("commands")
            modes = o.get("modes")
            return {
                "commands": cmds if isinstance(cmds, list) else [],
                "modes": modes if isinstance(modes, dict) else {},
                "source": "firmware",
            }
    return {
        "commands": [c["cmd"] for c in COMMANDS],
        "modes": dict(MODES),
        "source": "static",
    }
