# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Always-on MANAGEMENT access point — PERSISTED SETTINGS (Phase P2).

A second, independent Wi-Fi feature that lets the maintainer reach the dashboard
from a phone at any time — even when the Pi has no internet — by raising a small
WPA2 hotspot on a **dedicated USB NIC**. It is deliberately NOT the P1 provisioning
AP: P1's AP only appears when the Pi goes offline and runs a captive portal; this
one is a normal, persistent management network that stays up regardless of internet
and does NOT hijack DNS.

SHIPS DISABLED. Every behavior is gated behind ``mgmt_ap_enabled`` (default False);
while it is False the root supervisor is a strict no-op and holds no interface
reservation. This module is pure config — schema, validation, atomic 0600 persistence
(it holds the AP PSK), a redacted view — exactly like :mod:`core.provisioning`, and it
reuses that module's masked-secret and coercion conventions. There are NO network
calls here; the root service (:mod:`core.mgmt_ap_service`) is the only thing that runs
nmcli, and it reads these settings.

ZERO-RISK CONTRACT (enforced by the supervisor, constrained by validation here):
  * The AP runs ONLY on the configured dedicated NIC, which must NOT be ``wlan0``
    (the onboard adapter / usual uplink) and must NOT be the live default-route/SSH
    interface. There is NO fallback to another interface.
  * Its pinned subnet must not clash with P1's AP subnet or any existing shared
    connection (so the two hotspots coexist on separate radios + subnets).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

# Reuse P1's masked-secret sentinel + the generic AP-profile conventions so the two
# features share one vocabulary (and one nmcli profile builder downstream).
from core.provisioning import KEEP_SECRET

log = logging.getLogger("sentinel.mgmt_ap")

_LOCK = threading.RLock()

# Our dedicated NM profile name — DISTINCT from P1's "sentinel-ap" so the two never
# collide; this supervisor owns it exclusively.
MGMT_AP_CON_NAME = "sentinel-mgmt-ap"

# A single-host DNS snippet path (NOT a catch-all captive redirect): resolve only the
# friendly hostname to the AP IP for clients on this network. Distinct from P1's file.
MGMT_DNS_PATH = "/etc/NetworkManager/dnsmasq-shared.d/sentinel-mgmt.conf"

DEFAULTS: dict = {
    "mgmt_ap_enabled": False,        # ── MASTER SWITCH, default OFF ────────────────
    "mgmt_ap_ifname": "",            # dedicated USB NIC; MUST be chosen (never wlan0)
    "mgmt_ap_ssid": "Sentinel",
    "mgmt_ap_password": "",          # NO usable default; UI blocks enable until set
    "mgmt_ap_hidden": False,
    "mgmt_ap_ip": "10.42.1.1",       # pinned gateway; off P1's 10.42.0.0/24
    "mgmt_ap_prefix": 24,
    "mgmt_ap_hostname": "sentinel.local",
    # Management-only by default: the phone keeps its own data and just reaches the Pi
    # locally. When True the AP additionally NATs to the current uplink (internet
    # sharing). The NAT toggle itself is applied by the root service at the live layer.
    "share_internet": False,
}

_BOOL_KEYS = frozenset({"mgmt_ap_enabled", "mgmt_ap_hidden", "share_internet"})
_INT_KEYS = frozenset({"mgmt_ap_prefix"})
_SECRET_KEYS = frozenset({"mgmt_ap_password"})


# ── paths / persistence ────────────────────────────────────────────────────────
def mgmt_ap_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "mgmt_ap.json"


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


def load_mgmt_ap(config=None) -> dict:
    """Full settings = DEFAULTS merged with the persisted override file. Unknown keys
    are ignored; bad types fall back to defaults. Never raises."""
    path = mgmt_ap_path(config)
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


def mgmt_ap_enabled(config=None) -> bool:
    """The master switch. Default False until explicitly persisted True."""
    return bool(load_mgmt_ap(config).get("mgmt_ap_enabled", False))


def mgmt_ap_subnet(settings: dict) -> Optional[str]:
    """The AP's subnet as ``a.b.c.d/pre`` (network address), or None if invalid. Used
    to check for a clash against P1's subnet / existing shared connections."""
    try:
        prefix = int(settings.get("mgmt_ap_prefix", 24))
        net = ipaddress.ip_network(f"{settings.get('mgmt_ap_ip', '')}/{prefix}",
                                   strict=False)
        return str(net)
    except (ValueError, TypeError):
        return None


# ── validation (pure; live facts are passed in) ────────────────────────────────
def validate_settings(settings: dict, *, iface_info: Optional[dict] = None,
                      shared_subnets: Optional[list] = None,
                      uplink_iface: Optional[str] = None) -> tuple[list, list]:
    """Return ``(errors, warnings)`` for a *fully merged* settings dict.

    ``iface_info``   : ``{ifname: {"exists", "ap_capable", "reserved_reason"}}`` from
                       live discovery (or a fake in tests). When None, existence /
                       capability are not checked here.
    ``shared_subnets``: subnets already served by a shared connection — INCLUDING P1's
                        AP subnet — that this AP's subnet must not overlap.
    ``uplink_iface``  : the live default-route interface; the AP must never run on it
                        (self-lockout). When None this is not checked here (the
                        supervisor's own ``self_link`` guard still refuses it live).

    Errors block a save; warnings are advisory.
    """
    errors: list = []
    warnings: list = []
    s = settings
    enabling = bool(s.get("mgmt_ap_enabled"))

    # SSID
    ssid = str(s.get("mgmt_ap_ssid", "") or "")
    if not ssid.strip():
        errors.append("Hotspot SSID must not be empty.")
    elif len(ssid.encode("utf-8")) > 32:
        errors.append("Hotspot SSID must be at most 32 bytes.")

    # PSK — WPA2 8..63 chars when set; required before enabling
    psk = s.get("mgmt_ap_password", "") or ""
    if psk:
        if not (8 <= len(psk) <= 63):
            errors.append("Hotspot password (WPA2 PSK) must be 8–63 characters.")
    elif enabling:
        errors.append("Set a hotspot password (8–63 chars) before enabling the "
                      "management hotspot.")

    # AP IP / prefix
    prefix = s.get("mgmt_ap_prefix", 24)
    try:
        prefix = int(prefix)
    except (TypeError, ValueError):
        prefix = -1
    if not (8 <= prefix <= 30):
        errors.append("Hotspot subnet prefix must be between /8 and /30.")
    ap_net = None
    try:
        host = ipaddress.ip_address(str(s.get("mgmt_ap_ip", "")))
        if host.version != 4:
            errors.append("Hotspot IP must be an IPv4 address.")
        elif 8 <= prefix <= 30:
            ap_net = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
            if host == ap_net.network_address or host == ap_net.broadcast_address:
                errors.append("Hotspot IP must be a host address, not the network or "
                              "broadcast address of its subnet.")
    except ValueError:
        errors.append("Hotspot IP is not a valid IPv4 address.")

    # subnet clash with P1's subnet / an existing shared connection
    if ap_net is not None and shared_subnets:
        for raw in shared_subnets:
            try:
                other = ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                continue
            if ap_net.overlaps(other):
                errors.append(f"Hotspot subnet {ap_net} clashes with an existing "
                              f"network {other} (e.g. the provisioning AP); pick a "
                              f"different hotspot IP/subnet.")
                break

    # hostname (optional, advisory shape only — not enforced hard)
    host = str(s.get("mgmt_ap_hostname", "") or "")
    if not host:
        warnings.append("No friendly hostname set; reach the dashboard by IP.")

    # interface: required, never wlan0, never the live uplink, exists + AP-capable
    ifn = str(s.get("mgmt_ap_ifname", "") or "").strip()
    if not ifn:
        if enabling:
            errors.append("Choose a dedicated Wi-Fi interface before enabling the "
                          "management hotspot.")
        else:
            warnings.append("No dedicated interface chosen yet.")
    else:
        if ifn == "wlan0":
            errors.append("The management hotspot must NOT run on wlan0 (the onboard "
                          "adapter / usual uplink). Use a dedicated USB Wi-Fi adapter.")
        if uplink_iface and ifn == uplink_iface:
            errors.append(f"Interface '{ifn}' currently carries the default route "
                          f"(the Pi's uplink); refusing to avoid self-lockout.")
        if iface_info is not None:
            info = iface_info.get(ifn)
            if not info or not info.get("exists"):
                errors.append(f"Interface '{ifn}' was not found on this device.")
            else:
                if not info.get("ap_capable"):
                    errors.append(f"Interface '{ifn}' is not AP-capable.")
                rr = info.get("reserved_reason")
                if rr:
                    warnings.append(f"Interface '{ifn}' is reserved: {rr}. Double-check "
                                    f"this is intended before enabling.")

    return errors, warnings


# ── save (atomic, 0600; preserves the secret on a masked blank) ────────────────
def _merge_updates(current: dict, updates: dict) -> dict:
    """Apply posted updates onto current settings. A missing/blank PSK or the
    KEEP_SECRET sentinel keeps the stored PSK. Types coerced to the schema."""
    out = dict(current)
    for k in DEFAULTS:
        if k not in updates:
            continue
        v = updates[k]
        if k in _SECRET_KEYS:
            sv = "" if v is None else str(v)
            if sv == "" or sv == KEEP_SECRET:
                continue
            out[k] = sv
        else:
            out[k] = _coerce(k, v)
    return out


def save_mgmt_ap(config, updates: dict, *, iface_info: Optional[dict] = None,
                 shared_subnets: Optional[list] = None,
                 uplink_iface: Optional[str] = None
                 ) -> tuple[bool, list, list, dict]:
    """Validate ``updates`` merged onto current settings and, iff there are no errors,
    persist atomically with 0600 perms (holds the PSK). Returns
    ``(ok, errors, warnings, redacted_settings)``. On error nothing is written."""
    with _LOCK:
        current = load_mgmt_ap(config)
        merged = _merge_updates(current, updates)
        errors, warnings = validate_settings(
            merged, iface_info=iface_info, shared_subnets=shared_subnets,
            uplink_iface=uplink_iface)
        if errors:
            return False, errors, warnings, redacted(merged)
        path = mgmt_ap_path(config)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(merged, indent=2).encode("utf-8"))
            finally:
                os.close(fd)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        except OSError as e:
            log.warning("mgmt-ap settings save failed (%s): %s", path, e)
            return False, [f"could not write settings file: {e}"], warnings, redacted(merged)
        return True, [], warnings, redacted(merged)


# ── profile mapping + redaction ────────────────────────────────────────────────
def profile_settings(settings: dict) -> dict:
    """Map the ``mgmt_ap_*`` settings onto the GENERIC ``ap_*`` keys that
    :func:`core.provisioning_net.build_ap_profile_args` consumes, so the dedicated
    hotspot reuses the exact same nmcli profile builder as P1 — only the con-name and
    values differ. The PSK is carried through as an argument, never shell-interpolated."""
    return {
        "ap_ifname": str(settings.get("mgmt_ap_ifname", "")),
        "ap_ssid": str(settings.get("mgmt_ap_ssid", "Sentinel")),
        "ap_password": str(settings.get("mgmt_ap_password", "")),
        "ap_ip": str(settings.get("mgmt_ap_ip", "10.42.1.1")),
        "ap_prefix": int(settings.get("mgmt_ap_prefix", 24)),
        "ap_hidden": bool(settings.get("mgmt_ap_hidden", False)),
    }


def mgmt_dns_conf(ap_ip: str, hostname: str = "sentinel.local") -> str:
    """A SINGLE-HOST dnsmasq snippet (NOT a captive catch-all): resolve only the
    friendly hostname to the AP IP for clients on this network. Normal DNS otherwise
    — this is a management network, not a captive portal."""
    return (
        "# Sentinel management hotspot — single friendly-hostname entry (NOT captive).\n"
        f"address=/{hostname}/{ap_ip}\n"
    )


def redacted(settings: dict) -> dict:
    """A view safe to send to the browser / logs: the PSK is replaced by a boolean
    ``mgmt_ap_password_set`` and never echoed in full."""
    out = {k: v for k, v in settings.items() if k not in _SECRET_KEYS}
    out["mgmt_ap_password_set"] = bool(settings.get("mgmt_ap_password"))
    return out
