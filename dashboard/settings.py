# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Dashboard runtime settings (readonly + default scan options).

Stored in a gitignored `data/dashboard_settings.json`. Precedence is explicit
and documented (and surfaced in the UI so there is no silent revert):

    environment variable (if set)  >  stored setting  >  built-in default

So a value pinned by the env file (e.g. SENTINEL_DASH_READONLY in
deploy/sentinel.env) always wins and the UI marks it "env-pinned"; a value NOT
pinned by env is taken from stored settings and persists across restarts.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Dict

log = logging.getLogger("sentinel.dashboard.settings")

_ENV_PINS = {
    "readonly": "SENTINEL_DASH_READONLY",
    "nmap_timing": "SENTINEL_NMAP_TIMING",
    "nmap_top_ports": "SENTINEL_NMAP_TOP_PORTS",
    "nmap_timeout": "SENTINEL_NMAP_TIMEOUT",
    "wifi_iface": "SENTINEL_WIFI_IFACE",
}

_IFACE_RE = re.compile(r"^[A-Za-z0-9._:-]{0,32}$")   # "" = auto-detect


def path(config):
    return config.root / "data" / "dashboard_settings.json"


def env_pinned(field: str) -> bool:
    return os.environ.get(_ENV_PINS.get(field, "")) not in (None, "")


def load(config) -> Dict:
    p = path(config)
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception as e:  # noqa: BLE001 — corrupt settings must not crash startup
        log.warning("settings load failed (%s); ignoring", e)
        return {}


def save(config, data: Dict) -> None:
    p = path(config)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def apply_to(config, dash_config) -> None:
    """Apply stored settings at startup — env pins win, else stored overrides."""
    data = load(config)
    if "readonly" in data and not env_pinned("readonly"):
        dash_config.readonly = bool(data["readonly"])
    for field in ("nmap_timing", "nmap_top_ports", "nmap_timeout", "wifi_iface"):
        if field in data and not env_pinned(field):
            setattr(config, field, data[field])


def discovery_prefs(config) -> Dict:
    """Target-discovery preferences from the stored settings, with defaults:
    {"seconds": int (1-120), "mode": "on_demand"|"background"}."""
    data = load(config)
    seconds = data.get("discovery_seconds", 12)
    try:
        seconds = max(1, min(int(seconds), 120))
    except (TypeError, ValueError):
        seconds = 12
    mode = data.get("target_discovery_mode", "on_demand")
    if mode not in ("on_demand", "background"):
        mode = "on_demand"
    return {"seconds": seconds, "mode": mode}


def _as_int(value, lo: int, hi: int, label: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number")
    if n < lo or n > hi:
        raise ValueError(f"{label} must be between {lo} and {hi}")
    return n


def update(config, dash_config, changes: Dict) -> Dict:
    """Validate + persist runtime-config changes, then re-apply in-memory
    (respecting env pins). Raises ValueError on invalid input."""
    data = load(config)
    if "readonly" in changes:
        data["readonly"] = bool(changes["readonly"])
    if "nmap_timing" in changes:
        t = str(changes["nmap_timing"])
        if t not in ("1", "2", "3", "4", "5"):
            raise ValueError("timing must be 1–5")
        data["nmap_timing"] = t
    if "nmap_top_ports" in changes:
        data["nmap_top_ports"] = _as_int(changes["nmap_top_ports"], 0, 65535, "top-ports")
    if "nmap_timeout" in changes:
        data["nmap_timeout"] = _as_int(changes["nmap_timeout"], 0, 3600, "timeout")
    if "wifi_iface" in changes:
        iface = str(changes["wifi_iface"]).strip()
        if not _IFACE_RE.match(iface):
            raise ValueError("invalid interface name")
        data["wifi_iface"] = iface
    if "discovery_seconds" in changes:
        data["discovery_seconds"] = _as_int(changes["discovery_seconds"], 1, 120,
                                            "discovery duration")
    if "target_discovery_mode" in changes:
        m = str(changes["target_discovery_mode"])
        if m not in ("on_demand", "background"):
            raise ValueError("invalid target discovery mode")
        data["target_discovery_mode"] = m
    save(config, data)
    apply_to(config, dash_config)
    return data
