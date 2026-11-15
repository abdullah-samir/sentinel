# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Read-only discovery for the provisioning SETTINGS form (Phase P1).

The dashboard uses this to populate the interface dropdown and to validate a save
(interface exists + AP-capable; AP subnet vs existing shared subnets). Everything
here is READ-ONLY nmcli — no rescan, no connection/config changes — and every call
is wrapped so a failure degrades to a safe empty result rather than blocking a save
or raising. The privileged mutating actions live in the root service, never here.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Optional

log = logging.getLogger("sentinel.provisioning.discovery")


def _nmcli(args: list[str], timeout: float = 5.0) -> list[str]:
    """Run a read-only `nmcli -t ...` and return stdout lines; [] on any failure.
    Explicit arg list, never shell=True."""
    try:
        out = subprocess.run(["nmcli", "-t"] + args, capture_output=True, text=True,
                             timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("nmcli %s failed: %s", args, e)
        return []
    if out.returncode != 0:
        return []
    return [ln for ln in out.stdout.splitlines() if ln != ""]


def _unescape(field: str) -> str:
    # nmcli -t escapes ':' and '\' with a backslash; undo it for display fields.
    return field.replace("\\:", ":").replace("\\\\", "\\")


def ap_capable_interfaces(config=None) -> dict:
    """``{ifname: {"exists": True, "ap_capable": bool, "reserved_reason": str,
    "state": str}}`` for every Wi-Fi device NM knows. Read-only. Reserved-reason
    combines the interface registry and the self-link guard (default-route / SSH)
    so the UI can warn before a risky pick. Empty dict on any failure."""
    info: dict = {}
    devs: list[tuple[str, str]] = []
    for line in _nmcli(["-f", "DEVICE,TYPE,STATE", "device", "status"]):
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "wifi":
            devs.append((parts[0], parts[2] if len(parts) > 2 else ""))
    if not devs:
        return info

    # reserved-reason sources (best effort; never raise)
    busy = None
    self_link = None
    try:
        from core.state import InterfaceRegistry, self_link_reason
        reg = InterfaceRegistry(config) if config is not None else None
        busy = (lambda n: reg.busy_reason(n)) if reg is not None else (lambda n: "")
        self_link = self_link_reason
    except Exception:  # noqa: BLE001
        busy = lambda n: ""            # noqa: E731
        self_link = lambda n: ""       # noqa: E731

    for dev, state in devs:
        ap_capable = False
        for line in _nmcli(["-f", "WIFI-PROPERTIES.AP", "device", "show", dev]):
            if line.upper().endswith(":YES"):
                ap_capable = True
        reason = ""
        try:
            reason = self_link(dev) or busy(dev) or ""
        except Exception:  # noqa: BLE001
            reason = ""
        info[dev] = {"exists": True, "ap_capable": ap_capable,
                     "reserved_reason": reason, "state": state}
    return info


def existing_shared_subnets() -> list:
    """List of subnets (``a.b.c.d/pre``) already served by a shared-mode connection,
    so a new AP subnet can be checked for a clash. Read-only. [] on any failure."""
    subnets: list = []
    names: list[str] = []
    for line in _nmcli(["-f", "NAME", "connection", "show"]):
        names.append(_unescape(line))
    for name in names:
        method = _nmcli(["-g", "ipv4.method", "connection", "show", name])
        if not method or method[0].strip() != "shared":
            continue
        addrs = _nmcli(["-g", "ipv4.addresses", "connection", "show", name])
        got = False
        if addrs and addrs[0].strip():
            for a in addrs[0].split(","):
                a = a.strip()
                if a:
                    subnets.append(a)
                    got = True
        if not got:
            # shared with no pinned address -> NM's default subnet
            from core.provisioning import NM_SHARED_DEFAULT_SUBNET
            subnets.append(NM_SHARED_DEFAULT_SUBNET)
    return subnets


def settings_discovery(config=None) -> tuple[dict, list]:
    """Convenience: ``(iface_info, shared_subnets)`` for the save route. Returns
    ``({}, [])`` on failure so a save still proceeds (interface check is then
    deferred rather than wrongly blocking)."""
    try:
        return ap_capable_interfaces(config), existing_shared_subnets()
    except Exception as e:  # noqa: BLE001
        log.debug("settings_discovery failed: %s", e)
        return {}, []
