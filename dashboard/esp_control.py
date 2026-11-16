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


# Human titles for the detector's five alert types (matches plugins/blue/esp_sensor).
_DETECTION_TITLES = {
    "deauth_flood_src": "Deauth flood (per-source)",
    "deauth_flood_aggregate": "Deauth flood (aggregate)",
    "beacon_flood": "Beacon flood",
    "beacon_ssid_spam": "Beacon SSID spam",
    "evil_twin": "Evil twin (duplicate SSID)",
}


def _modules_brief(obj: dict) -> str:
    out = []
    for m in obj.get("modules", []) or []:
        if isinstance(m, dict):
            st = m.get("state") or ("ok" if m.get("ok") else "?")
            out.append(f"M{m.get('id', '?')} {st}")
    return ", ".join(out)


def _scan_summary(obj: dict, kind: str) -> str:
    # Reuse esp_chart_series so the flatten logic lives in one place; ch == mhz-2400.
    series = esp_chart_series(obj)
    passes = obj.get("passes", "?")
    if not series:
        return f"{kind} done: {passes} pass(es), no activity detected"
    peak = max(series, key=lambda p: p["value"])
    return (f"{kind} done: {passes} pass(es), {len(series)} channel(s) active, "
            f"busiest ch {peak['mhz'] - 2400} ({peak['value']} hits)")


def humanize_frame(obj: Any) -> str:
    """One concise human sentence for a known frame; compact single-line JSON for an
    unknown/missing-`t` frame (so new commands stay visible with zero code change);
    a non-dict (already-human log / non-JSON) is passed through. Never raises."""
    if not isinstance(obj, dict):
        return str(obj)
    t = obj.get("t")
    try:
        if t == "ack":
            return f"✓ {obj.get('cmd', '?')} acknowledged"
        if t == "cmd_error":
            msg = obj.get("msg") or obj.get("error") or "error"
            cmd = obj.get("cmd")
            return f"✗ {msg}" + (f" (cmd: {cmd})" if cmd else "")
        if t == "heartbeat":                     # never logged, humanized for tests
            return (f"heartbeat: {obj.get('mode', '?')}, ch {obj.get('channel', '?')}, "
                    f"{obj.get('frames_seen', '?')} frames, "
                    f"{obj.get('detections_total', '?')} detections")
        if t == "status_result":
            mode = obj.get("mode_name") or obj.get("mode", "?")
            head = (f"status: {obj.get('state', '?')}, mode {mode}, "
                    f"power {obj.get('pa', '?')}, dwell {obj.get('dwell', '?')}, "
                    f"{obj.get('enabled', '?')} enabled")
            mb = _modules_brief(obj)
            return head + (f"; {mb}" if mb else "")
        if t == "diag_result":
            return (f"diag: {obj.get('state', '?')}, up {obj.get('uptime_s', '?')}s, "
                    f"heap {obj.get('free_heap', '?')}, power {obj.get('pa', '?')}, "
                    f"dwell {obj.get('dwell', '?')}")
        if t == "scan_result":
            return _scan_summary(obj, "scan")
        if t == "search_result":
            return _scan_summary(obj, "search")
        if t == "selftest_result":
            mb = _modules_brief(obj)
            return ("selftest " + ("ok" if obj.get("ok") else "issues")
                    + (f": {mb}" if mb else ""))
        if t == "config_result":
            cmd = obj.get("cmd", "?")
            if "mode" in obj:                         # a mode-alias naming its mode
                return f"✓ mode → {obj.get('mode')}"
            if cmd == "ch":
                return "✓ channel " + ("auto" if obj.get("auto")
                                       else f"locked to {obj.get('lock', '?')}")
            if cmd == "power":
                return f"✓ power → {obj.get('pa', '?')}"
            if cmd == "en":
                return f"✓ radios enabled → {obj.get('enabled', '?')}"
            if cmd == "dwell":
                return f"✓ dwell → {obj.get('dwell_us', '?')} µs"
            if cmd == "debug":
                return f"✓ debug verbosity → {obj.get('verbosity', '?')}"
            return f"✓ {cmd} updated"
        if t == "ctrl_result":
            cmd = obj.get("cmd", "?")
            if cmd == "start":
                return (f"▶ started ({obj.get('active', '?')}/{obj.get('total', '?')} "
                        f"modules active)")
            if cmd == "stop":
                return "■ stopped" + (f" — {obj.get('msg')}" if obj.get("msg") else "")
            return f"✓ {cmd}: {obj.get('state', '?')}"
        if t == "detection":
            title = _DETECTION_TITLES.get(obj.get("type"), obj.get("type", "detection"))
            where = obj.get("mac") or obj.get("ssid") or ""
            ch = obj.get("channel")
            loc = ((f" {where}" if where else "")
                   + (f" ch{ch}" if ch not in (None, "") else ""))
            ev = obj.get("evidence", "")
            return (f"⚠ DETECTION [{obj.get('severity', '?')}] {title}{loc}"
                    + (f": {ev}" if ev else ""))
        if t == "help_result":
            return "commands: " + ", ".join(str(c) for c in (obj.get("commands") or []))
        if t == "boot":
            return (f"booted: {obj.get('sensor', 'esp')} — "
                    f"{obj.get('note', '')}").rstrip(" —")
        if t == "info":
            extra = []
            if obj.get("mode") is not None:
                extra.append(f"mode {obj['mode']}")
            if obj.get("channel") is not None:
                extra.append(f"ch {obj['channel']}")
            return (obj.get("msg", "info")
                    + (f" ({', '.join(extra)})" if extra else ""))
        if t == "error":
            return f"⚠ {obj.get('msg') or obj.get('error') or 'error'}"
    except Exception:  # noqa: BLE001 — a humanizer must never raise
        pass
    return json.dumps(obj, separators=(",", ":"))   # unknown/missing t -> compact JSON


# Frame kinds that arrive as continuous TELEMETRY (high rate): they drive the live
# widgets in place and reach the scrolling log ONLY on a meaningful change (a new
# humanized line vs the last logged line of the same kind). Everything else — ack/nak/
# cmd_error, ctrl_result (start/stop/join completions), detections, boot/info/error,
# help/selftest, and ANY UNKNOWN frame — is a discrete EVENT that always logs (subject
# to identical-line coalescing). heartbeat is telemetry too, but it never reaches the
# log at all (routed to the Live widget upstream).
TELEMETRY_TYPES = frozenset({
    "heartbeat", "status_result", "config_result", "scan_result",
    "search_result", "diag_result",
})


def log_class(obj) -> str:
    """Classify a frame for the scrolling log: 'telemetry' (continuous; log only on a
    meaningful change) or 'event' (discrete; always log). A non-dict, a missing `t`, or
    any UNKNOWN `t` is an EVENT — so new/unknown command output is never hidden (E4
    extensibility). Pure; mirrored by the page JS."""
    if not isinstance(obj, dict):
        return "event"
    return "telemetry" if obj.get("t") in TELEMETRY_TYPES else "event"


class LogReducer:
    """Decide, per incoming frame, whether it becomes a NEW log row, COALESCES into the
    previous identical row (dmesg-style ×N), or is SKIPPED (a telemetry repeat). Pure
    and deterministic so it is unit-tested here and mirrored verbatim in the page JS.

    feed(obj, text) -> 'new_row' | 'increment' | 'skip'. ``text`` defaults to
    humanize_frame(obj) (the humanizer's text is never changed by this).

    verbose=True disables both the telemetry-skip and the coalescing, so EVERY frame
    logs — the debugging escape hatch (nothing is ever permanently hidden)."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.rows: list[dict] = []          # [{text, count, obj}] — for tests/mirror
        self._prev_row_text = None
        self._last_by_kind: dict = {}

    def feed(self, obj, text: Optional[str] = None) -> str:
        if text is None:
            text = humanize_frame(obj)
        kind = obj.get("t") if isinstance(obj, dict) else None
        if self.verbose:
            return self._append(text, kind, obj)
        # telemetry repeat vs the last LOGGED line of the same kind -> skip (no row)
        if log_class(obj) == "telemetry" and self._last_by_kind.get(kind) == text:
            return "skip"
        # coalesce consecutive identical lines (any kind) -> ×N on the previous row
        if self.rows and self._prev_row_text == text:
            self.rows[-1]["count"] += 1
            if kind is not None:
                self._last_by_kind[kind] = text
            return "increment"
        return self._append(text, kind, obj)

    def _append(self, text, kind, obj) -> str:
        self.rows.append({"text": text, "count": 1,
                          "obj": obj if isinstance(obj, dict) else None})
        self._prev_row_text = text
        if kind is not None:
            self._last_by_kind[kind] = text
        return "new_row"


def snapshot_log(bridge) -> list[dict]:
    """Rebuild the initial log the SAME way the live stream renders frames: humanize
    known frames, compact-JSON unknowns, pass non-JSON through; DROP heartbeats.
    Entries are {text, obj?} so the client can reveal the raw JSON per line."""
    entries: list[dict] = []
    for line in list(bridge.recent_logs())[-200:]:
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            if obj.get("t") == "heartbeat":
                continue
            entries.append({"text": humanize_frame(obj), "obj": obj})
        else:
            entries.append({"text": line if isinstance(line, str) else str(line)})
    return entries


def run_state_of(state: Any) -> str:
    """Normalize a status_result/ctrl_result `state` to one of running/stopped/idle.
    The run-state chip and the panel 'state' field both go through this ONE mapping
    (server + mirrored in the page JS) so they can never disagree."""
    s = str(state or "").lower()
    if s == "running":
        return "running"
    if s in ("standby", "stopped"):
        return "stopped"
    return "idle"


_PANEL_FIELDS = ("run_state", "state", "mode", "enabled", "power", "dwell",
                 "channel", "modules_ready", "modules")


def _empty_panel() -> dict:
    return {"run_state": "idle", "state": "", "mode": "", "enabled": "",
            "power": None, "dwell": None, "channel": "", "modules_ready": "", "modules": []}


def scanner_panel(status_result: Any) -> dict:
    """ACTIVE MODE panel view-model (the seed) from a REAL status_result. state/mode
    come straight from the frame; 'enabled' is the firmware radios flag and
    'modules_ready' is how many modules are healthy (from modules[]); power/dwell are
    the reported pa/dwell; channel is 'auto' when locked to -1 else the lock value.
    power/dwell are None when absent (never a permanent dash — once a status_result
    arrives these populate). Tolerant of missing/extra fields; the page JS and
    merge_panel() apply the same per-field mapping live."""
    if not isinstance(status_result, dict):
        return _empty_panel()
    mods = [m for m in (status_result.get("modules") or []) if isinstance(m, dict)]
    ready = sum(1 for m in mods if m.get("state") == "ready"
                or m.get("bus") == "up" or m.get("ok") is True)
    lock = status_result.get("lock")
    return {
        "run_state": run_state_of(status_result.get("state")),
        "state": status_result.get("state", ""),
        "mode": status_result.get("mode_name") or status_result.get("mode", ""),
        "enabled": "" if status_result.get("enabled") is None else str(status_result.get("enabled")),
        "power": status_result.get("pa"),
        "dwell": status_result.get("dwell"),
        "channel": "auto" if lock in (-1, None) else lock,
        "modules_ready": f"{ready}/{len(mods)}" if mods else "",
        "modules": mods,
    }


def merge_panel(model: Any, frame: Any) -> dict:
    """Last-writer-wins per-field merge of ONE live frame into the ACTIVE MODE panel
    model. status_result replaces the whole snapshot; ctrl_result updates run/state;
    config_result updates only the field(s) it reports (power←pa, dwell←dwell_us,
    enabled←enabled, channel←auto/lock, mode←mode). Reflects exactly what the device
    reports — alias semantics are never guessed. The page JS mirrors this. Never
    raises. Returns a new dict."""
    out = dict(model) if isinstance(model, dict) else _empty_panel()
    for k in _PANEL_FIELDS:
        out.setdefault(k, _empty_panel()[k])
    if not isinstance(frame, dict):
        return out
    t = frame.get("t")
    if t == "status_result":
        out.update(scanner_panel(frame))          # authoritative full snapshot
    elif t == "ctrl_result":
        if "state" in frame:
            out["state"] = frame.get("state", out["state"])
            out["run_state"] = run_state_of(frame.get("state"))
    elif t == "config_result":
        if "pa" in frame:
            out["power"] = frame["pa"]
        if "dwell_us" in frame:
            out["dwell"] = frame["dwell_us"]
        if "enabled" in frame:
            out["enabled"] = str(frame["enabled"])
        if "mode" in frame:                        # a mode-alias that names its mode
            out["mode"] = frame["mode"]
        if frame.get("cmd") == "ch":
            out["channel"] = "auto" if frame.get("auto") else frame.get("lock")
    return out


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
        "logs": snapshot_log(bridge),            # humanized, heartbeat-free, {text, obj?}
        "alive": bridge.is_alive(),
    }


async def esp_stream_events(bridge, *, idle_timeout: float = 15.0):
    """Async SSE generator for /esp/stream. Registers a bounded listener BEFORE the
    snapshot. Contract: a JSON frame with a `t` -> sse('frame', {t, obj, text, heartbeat})
    (heartbeat frames are flagged so the client keeps them OUT of the log); anything
    else (non-JSON, or JSON with no `t`) -> sse('line', raw). Idle beats send a 'tick'.
    Always deregisters in finally. Kept at module scope so it is unit-tested directly
    (TestClient buffers streaming responses, so it can't drive it)."""
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
            if isinstance(obj, dict) and obj.get("t"):
                t = obj["t"]
                yield sse("frame", {"t": t, "obj": obj, "text": humanize_frame(obj),
                                    "heartbeat": t == "heartbeat"})
            else:
                yield sse("line", raw)
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
