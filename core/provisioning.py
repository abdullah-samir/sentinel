# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Headless Wi-Fi provisioning + offline portal — PERSISTED SETTINGS (Phase P1).

SHIPS DISABLED. Every behavior is gated behind ``provisioning_enabled`` (default
False); while it is False nothing in this feature touches the Pi. This module is
pure config: the schema, validation, atomic persistence (the file is written 0600
because it holds the AP PSK), and a redacted view that never echoes the PSK back in
full. There are NO network calls here — the root provisioning service reads these
settings and is the only thing that runs nmcli. Mirrors the esp-bridge override
store in :mod:`core.state`.

The dashboard writes settings here (auth + CSRF + readonly); the monitor service and
portal read them. Validation that needs a live view of the hardware (does the
interface exist / is it AP-capable / is it reserved, and which subnets are already
shared) is passed IN as plain data (``iface_info`` / ``shared_subnets``) so this
module stays pure and unit-testable with a mocked backend.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.provisioning")

_LOCK = threading.RLock()

# NetworkManager's default shared-mode subnet. Our pinned AP IP must not land on a
# subnet that an existing shared connection already serves (discovery: none did).
NM_SHARED_DEFAULT_SUBNET = "10.42.0.0/24"

# A sentinel posted by the UI's masked PSK field meaning "leave the stored PSK as
# it is" — so the secret never has to round-trip through the browser.
KEEP_SECRET = "__KEEP__"

DEFAULTS: dict = {
    "provisioning_enabled": False,   # ── MASTER SWITCH, default OFF ──────────────
    "ap_ifname": "wlan0",            # onboard; selectable from AP-capable ifaces
    "ap_ssid": "Sentinel-Setup",
    "ap_password": "",               # NO usable default; UI blocks enable until set
    "ap_hidden": False,              # hidden is awkward for first-time setup
    "ap_ip": "10.42.0.1",            # pinned shared-mode gateway
    "ap_prefix": 24,
    "grace_seconds": 45,             # offline must persist this long before AP rises
    "probe_url": "http://connectivitycheck.gstatic.com/generate_204",
    "probe_timeout": 5,
    "join_timeout": 30,
    "friendly_hostname": "sentinel.local",
    "dashboard_port": 8000,          # discovery default (uvicorn 127.0.0.1:8000)
    "show_dashboard_link": True,
    "dashboard_on_ap": False,        # explicit opt-in to broaden the dashboard bind
}

_BOOL_KEYS = frozenset({"provisioning_enabled", "ap_hidden",
                        "show_dashboard_link", "dashboard_on_ap"})
_INT_KEYS = frozenset({"ap_prefix", "grace_seconds", "probe_timeout",
                       "join_timeout", "dashboard_port"})
_SECRET_KEYS = frozenset({"ap_password"})

_INT_BOUNDS = {
    "ap_prefix": (8, 30),
    "grace_seconds": (5, 3600),
    "probe_timeout": (1, 60),
    "join_timeout": (5, 300),
    "dashboard_port": (1, 65535),
}

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
                          r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$")


# ── paths / persistence ────────────────────────────────────────────────────────
def provisioning_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "provisioning.json"


def _coerce(key: str, value: Any) -> Any:
    """Best-effort coercion to the schema type; falls back to the default on junk."""
    try:
        if key in _BOOL_KEYS:
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("1", "true", "yes", "on")
        if key in _INT_KEYS:
            return int(value)
        return value
    except (TypeError, ValueError):
        return DEFAULTS.get(key)


def load_provisioning(config=None) -> dict:
    """Full settings = DEFAULTS merged with the persisted override file. Unknown
    keys in the file are ignored; bad types fall back to defaults. Never raises."""
    path = provisioning_path(config)
    stored: dict = {}
    with _LOCK:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                stored = data
        except (OSError, ValueError):
            stored = {}
    out = dict(DEFAULTS)
    for k in DEFAULTS:
        if k in stored:
            out[k] = _coerce(k, stored[k])
    return out


def provisioning_enabled(config=None) -> bool:
    """The master switch. Default False until explicitly persisted True."""
    return bool(load_provisioning(config).get("provisioning_enabled", False))


# ── validation (pure; live facts are passed in) ────────────────────────────────
def validate_settings(settings: dict, *, iface_info: Optional[dict] = None,
                      shared_subnets: Optional[list] = None) -> tuple[list, list]:
    """Return ``(errors, warnings)`` for a *fully merged* settings dict.

    ``iface_info``   : ``{ifname: {"exists": bool, "ap_capable": bool,
                         "reserved_reason": str}}`` from live discovery (or a fake in
                       tests). When None, interface existence/capability is not
                       checked here (the caller may defer to the service).
    ``shared_subnets``: list of ``ip_network`` strings already served by a shared
                        connection; the AP subnet must not overlap any of them.

    Errors block a save; warnings are advisory (e.g. a reserved interface).
    """
    errors: list = []
    warnings: list = []
    s = settings
    enabling = bool(s.get("provisioning_enabled"))

    # SSID
    ssid = str(s.get("ap_ssid", "") or "")
    if not ssid.strip():
        errors.append("AP SSID must not be empty.")
    elif len(ssid.encode("utf-8")) > 32:
        errors.append("AP SSID must be at most 32 bytes.")

    # PSK — 8..63 chars when set; required before enabling
    psk = s.get("ap_password", "") or ""
    if psk:
        if not (8 <= len(psk) <= 63):
            errors.append("AP password (WPA2 PSK) must be 8–63 characters.")
    elif enabling:
        errors.append("Set an AP password (8–63 chars) before enabling provisioning.")

    # AP IP / prefix
    prefix = s.get("ap_prefix", 24)
    try:
        prefix = int(prefix)
    except (TypeError, ValueError):
        prefix = -1
    if not (8 <= prefix <= 30):
        errors.append("AP subnet prefix must be between /8 and /30.")
    ap_net = None
    try:
        host = ipaddress.ip_address(str(s.get("ap_ip", "")))
        if host.version != 4:
            errors.append("AP IP must be an IPv4 address.")
        elif 8 <= prefix <= 30:
            ap_net = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
            if host == ap_net.network_address or host == ap_net.broadcast_address:
                errors.append("AP IP must be a host address, not the network or "
                              "broadcast address of its subnet.")
    except ValueError:
        errors.append("AP IP is not a valid IPv4 address.")

    # subnet clash with an existing shared connection
    if ap_net is not None and shared_subnets:
        for raw in shared_subnets:
            try:
                other = ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                continue
            if ap_net.overlaps(other):
                errors.append(f"AP subnet {ap_net} clashes with an existing shared "
                              f"network {other}; pick a different ap_ip/subnet.")

    # integer bounds
    for key, (lo, hi) in _INT_BOUNDS.items():
        if key == "ap_prefix":
            continue
        try:
            v = int(s.get(key))
        except (TypeError, ValueError):
            errors.append(f"{key} must be an integer.")
            continue
        if not (lo <= v <= hi):
            errors.append(f"{key} must be between {lo} and {hi}.")

    # hostname / probe url
    host = str(s.get("friendly_hostname", "") or "")
    if not host or not _HOSTNAME_RE.match(host):
        errors.append("Friendly hostname must be a valid hostname "
                      "(letters, digits, hyphens, dots).")
    probe = str(s.get("probe_url", "") or "")
    if not probe.startswith(("http://", "https://")):
        errors.append("Connectivity probe URL must start with http:// or https://.")

    # interface existence / AP-capability / reservation
    ifn = str(s.get("ap_ifname", "") or "")
    if not ifn:
        errors.append("AP interface must be set.")
    elif iface_info is not None:
        info = iface_info.get(ifn)
        if not info or not info.get("exists"):
            errors.append(f"AP interface '{ifn}' was not found on this device.")
        else:
            if not info.get("ap_capable"):
                errors.append(f"Interface '{ifn}' is not AP-capable.")
            rr = info.get("reserved_reason")
            if rr:
                warnings.append(f"Interface '{ifn}' is reserved: {rr}. The AP only "
                                f"rises when offline, but double-check this is intended.")

    return errors, warnings


# ── save (atomic, 0600; preserves the secret on a masked blank) ────────────────
def _merge_updates(current: dict, updates: dict) -> dict:
    """Apply posted updates onto the current settings. A missing PSK, a blank PSK,
    or the KEEP_SECRET sentinel keeps the stored PSK (so the masked field never has
    to round-trip the secret). Types are coerced to the schema."""
    out = dict(current)
    for k in DEFAULTS:
        if k not in updates:
            continue
        v = updates[k]
        if k in _SECRET_KEYS:
            sv = "" if v is None else str(v)
            if sv == "" or sv == KEEP_SECRET:
                continue                      # keep the stored secret
            out[k] = sv
        else:
            out[k] = _coerce(k, v)
    return out


def save_provisioning(config, updates: dict, *, iface_info: Optional[dict] = None,
                      shared_subnets: Optional[list] = None
                      ) -> tuple[bool, list, list, dict]:
    """Validate ``updates`` merged onto the current settings and, iff there are no
    errors, persist atomically with 0600 perms (it holds the PSK). Returns
    ``(ok, errors, warnings, redacted_settings)``. On error nothing is written."""
    with _LOCK:
        current = load_provisioning(config)
        merged = _merge_updates(current, updates)
        errors, warnings = validate_settings(
            merged, iface_info=iface_info, shared_subnets=shared_subnets)
        if errors:
            return False, errors, warnings, redacted(merged)
        path = provisioning_path(config)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            # create the temp file 0600 BEFORE writing the secret into it
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(merged, indent=2).encode("utf-8"))
            finally:
                os.close(fd)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        except OSError as e:
            log.warning("provisioning settings save failed (%s): %s", path, e)
            return False, [f"could not write settings file: {e}"], warnings, redacted(merged)
        return True, [], warnings, redacted(merged)


# ── redaction ──────────────────────────────────────────────────────────────────
def redacted(settings: dict) -> dict:
    """A view safe to send to the browser / logs: the PSK is replaced by a boolean
    ``ap_password_set`` and never echoed in full."""
    out = {k: v for k, v in settings.items() if k not in _SECRET_KEYS}
    out["ap_password_set"] = bool(settings.get("ap_password"))
    return out
