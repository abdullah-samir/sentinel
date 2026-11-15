# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Provisioning IPC — the privilege boundary (Phase P1).

The unprivileged portal NEVER runs nmcli and never writes under /etc/NetworkManager.
It forwards strictly-validated requests ``{action, ssid?, password?, hidden?}`` to the
root provisioning service over a local Unix socket; the root service is the only thing
that touches the network. This module is the wire protocol + validation shared by both
sides:

  - validate_request(): the ONE gate — rejects anything that isn't a known action with
    well-formed, control-char-free fields. The handler only ever sees validated data.
  - newline-delimited JSON framing over AF_UNIX.
  - a tiny client (send_request) and a server loop (serve) with a stop Event.
  - safe_for_log(): redacts the password so it is NEVER logged or persisted.

No network calls here; this is pure IPC plumbing, unit-testable with a real AF_UNIX
socket in a temp dir (local, deterministic — no networking).
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
from typing import Any, Callable, Optional

log = logging.getLogger("sentinel.provisioning.ipc")

DEFAULT_SOCKET_PATH = "/run/sentinel-provisioning.sock"   # root service ⇄ portal

ACTIONS = frozenset({"status", "rescan", "join", "ping"})
MAX_SSID = 32            # 802.11 SSID max
MAX_PSK = 63            # WPA2 PSK max
_MAX_LINE = 8192        # a request line is tiny; cap to avoid unbounded reads


def _has_ctrl(s: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in s)


def validate_request(obj: Any) -> tuple[bool, str, dict]:
    """(ok, error, clean). ``clean`` contains ONLY whitelisted, type-checked,
    control-char-free fields for the known action. Never raises."""
    if not isinstance(obj, dict):
        return False, "request must be a JSON object", {}
    action = obj.get("action")
    if action not in ACTIONS:
        return False, "unknown or missing action", {}
    clean: dict = {"action": action}
    if action == "join":
        ssid = obj.get("ssid")
        if not isinstance(ssid, str) or not (1 <= len(ssid) <= MAX_SSID):
            return False, "ssid must be a string of 1–32 chars", {}
        if _has_ctrl(ssid):
            return False, "ssid contains control characters", {}
        pw = obj.get("password", "")
        if pw is None:
            pw = ""
        if not isinstance(pw, str) or len(pw) > MAX_PSK:
            return False, "password must be a string of at most 63 chars", {}
        if pw and len(pw) < 8:
            return False, "password must be at least 8 chars (or empty for an open network)", {}
        if _has_ctrl(pw):
            return False, "password contains control characters", {}
        clean["ssid"] = ssid
        clean["password"] = pw
        clean["hidden"] = bool(obj.get("hidden", False))
    return True, "", clean


def safe_for_log(req: dict) -> dict:
    """A copy with the password redacted — use this for any logging/persistence."""
    out = {k: v for k, v in req.items() if k != "password"}
    if "password" in req:
        out["password"] = "***"
    return out


def encode_message(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


def _read_line(conn: socket.socket, timeout: float) -> Optional[bytes]:
    conn.settimeout(timeout)
    buf = bytearray()
    while b"\n" not in buf:
        try:
            chunk = conn.recv(1024)
        except socket.timeout:
            return None
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > _MAX_LINE:
            return None
    if not buf:
        return None
    return bytes(buf).split(b"\n", 1)[0]


# ── client (portal side) ───────────────────────────────────────────────────────
def send_request(socket_path: str, req: dict, *, timeout: float = 35.0) -> dict:
    """Connect, send ONE request, read ONE response line, return the parsed dict.
    Returns an ``{"ok": False, "error": ...}`` dict on any transport failure —
    never raises, so the portal degrades gracefully when the service is down."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(timeout)
            c.connect(socket_path)
            c.sendall(encode_message(req))
            line = _read_line(c, timeout)
    except OSError as e:
        return {"ok": False, "error": f"provisioning service unavailable: {e}"}
    if not line:
        return {"ok": False, "error": "no response from provisioning service"}
    try:
        resp = json.loads(line.decode("utf-8"))
        return resp if isinstance(resp, dict) else {"ok": False, "error": "bad response"}
    except ValueError:
        return {"ok": False, "error": "unparseable response"}


# ── server (root service side) ─────────────────────────────────────────────────
def serve(socket_path: str, handler: Callable[[dict], dict], *,
          stop_event: Optional[threading.Event] = None,
          read_timeout: float = 5.0, mode: int = 0o660) -> None:
    """Accept loop over an AF_UNIX stream socket. Each connection carries ONE
    newline-delimited JSON request; it is validated here before `handler(clean)` is
    called, so the handler never sees unvalidated input. Response is `handler`'s dict
    (plus ok) or an error dict for a bad request. Passwords are never logged. Blocks
    until `stop_event` is set; always unlinks the socket on exit."""
    stop_event = stop_event or threading.Event()
    try:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(socket_path)
        try:
            os.chmod(socket_path, mode)
        except OSError:
            pass
        srv.listen(8)
        srv.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                _handle_one(conn, handler, read_timeout)
    finally:
        try:
            srv.close()
        finally:
            try:
                os.unlink(socket_path)
            except OSError:
                pass


def _handle_one(conn: socket.socket, handler: Callable[[dict], dict],
                read_timeout: float) -> None:
    line = _read_line(conn, read_timeout)
    if not line:
        _send(conn, {"ok": False, "error": "empty or oversized request"})
        return
    try:
        obj = json.loads(line.decode("utf-8"))
    except ValueError:
        _send(conn, {"ok": False, "error": "invalid JSON"})
        return
    ok, err, clean = validate_request(obj)
    if not ok:
        _send(conn, {"ok": False, "error": err})
        return
    log.info("provisioning IPC request: %s", safe_for_log(clean))
    try:
        resp = handler(clean)
    except Exception as e:  # noqa: BLE001 — a handler fault must not crash the loop
        log.error("provisioning handler failed: %s", e)
        _send(conn, {"ok": False, "error": "internal error"})
        return
    if not isinstance(resp, dict):
        resp = {"ok": False, "error": "handler returned non-dict"}
    resp.setdefault("ok", True)
    _send(conn, resp)


def _send(conn: socket.socket, obj: dict) -> None:
    try:
        conn.sendall(encode_message(obj))
    except OSError:
        pass
