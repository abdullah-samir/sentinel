# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Provisioning runtime state (Phase P1): the persisted LAST-ATTEMPT RESULT and the
current phase, written by the root service and read by the portal.

A single radio can't show a join result in-session (the AP drops to attempt), so the
outcome is persisted here and surfaced once the AP re-raises. NEVER stores a password.
Atomic writes, never raises.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.provisioning.state")

_LOCK = threading.Lock()

# result kinds the portal styles distinctly
OK = "success"
WRONG_CRED = "wrong_credentials"
NO_INTERNET = "joined_no_internet"
ERROR = "error"


def result_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "provisioning_result.json"


def phase_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "provisioning_phase.json"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as e:
        log.warning("provisioning state save failed (%s): %s", path, e)


def set_last_result(config, kind: str, ssid: str, message: str) -> dict:
    """Persist the last join outcome. ``message`` must never contain the password
    (callers pass only nmcli reasons / human text)."""
    data = {"kind": kind, "ssid": ssid, "message": message, "ts": _now()}
    with _LOCK:
        _write(result_path(config), data)
    return data


def get_last_result(config=None) -> Optional[dict]:
    with _LOCK:
        try:
            d = json.loads(result_path(config).read_text(encoding="utf-8"))
            return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None


def clear_last_result(config=None) -> None:
    with _LOCK:
        try:
            result_path(config).unlink()
        except OSError:
            pass


def networks_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "provisioning_networks.json"


def set_networks(config, networks: list) -> None:
    """Cache the nearby networks scanned just before the AP rose, so the portal can
    list them (the single radio can't scan while serving the AP without a brief drop)."""
    with _LOCK:
        _write(networks_path(config),
               {"networks": list(networks or []), "ts": _now()})


def get_networks(config=None) -> dict:
    with _LOCK:
        try:
            d = json.loads(networks_path(config).read_text(encoding="utf-8"))
            if isinstance(d, dict) and isinstance(d.get("networks"), list):
                return d
        except (OSError, ValueError):
            pass
    return {"networks": [], "ts": None}


def set_phase(config, phase: str, detail: str = "") -> None:
    """Coarse current phase for diagnostics: idle | ap_up | attempting | online."""
    with _LOCK:
        _write(phase_path(config), {"phase": phase, "detail": detail, "ts": _now()})


def get_phase(config=None) -> dict:
    with _LOCK:
        try:
            d = json.loads(phase_path(config).read_text(encoding="utf-8"))
            return d if isinstance(d, dict) else {"phase": "idle"}
        except (OSError, ValueError):
            return {"phase": "idle"}
