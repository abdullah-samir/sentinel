# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Read-only view-model for the live network-interfaces panel.

**Strictly read-only.** This never claims, releases, or reconfigures an
interface, and it never runs a command against an interface that is mid-capture
(one reserved in monitor mode by an alive run): for a busy interface the mode is
taken from the cached reservation, not probed. It reads the registry's cached
reservations plus lightweight ``/sys/class/net`` entries, and uses ``iw`` /
``lsusb`` sparingly — only to label a *free* Wi-Fi interface's mode and to
confirm USB attachment. All helpers are module-level so tests can stub the host.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional

from core import state as core_state


def _sys_net() -> Path:
    return Path("/sys/class/net")


def present_interfaces() -> List[str]:
    try:
        return sorted(d.name for d in _sys_net().iterdir())
    except OSError:
        return []


def iface_driver(iface: str) -> str:
    try:
        link = os.readlink(str(_sys_net() / iface / "device" / "driver"))
        return os.path.basename(link).lower()
    except OSError:
        return ""


def is_wifi(iface: str) -> bool:
    d = _sys_net() / iface
    return (d / "wireless").exists() or (d / "phy80211").exists()


def is_usb(iface: str) -> bool:
    """True if `iface`'s device chain is USB-attached (walks a few parents
    looking for a USB device node). Built-in NICs/Wi-Fi return False."""
    dev = _sys_net() / iface / "device"
    for _ in range(6):
        try:
            if (dev / "idVendor").exists():
                return True
        except OSError:
            pass
        try:
            nxt = dev.resolve().parent
        except OSError:
            break
        if nxt == dev:
            break
        dev = nxt
    return False


def operstate(iface: str) -> str:
    try:
        return (_sys_net() / iface / "operstate").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def iface_mac(iface: str) -> str:
    """The interface's MAC address, or "" on failure. Lets the UI tell two identical
    USB dongles apart when choosing the dedicated management-AP NIC."""
    try:
        return (_sys_net() / iface / "address").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def usb_path(iface: str) -> str:
    """The USB bus path for a USB-attached NIC (e.g. '1-1.3'), or "" otherwise. A
    stable, human-readable way to distinguish two identical dongles by the port they
    are plugged into."""
    dev = _sys_net() / iface / "device"
    for _ in range(6):
        try:
            if (dev / "idVendor").exists():
                name = dev.resolve().name
                # the usb *interface* dir looks like '1-1.3:1.0'; trim the ':x.y'
                return name.split(":")[0]
        except OSError:
            pass
        try:
            nxt = dev.resolve().parent
        except OSError:
            break
        if nxt == dev:
            break
        dev = nxt
    return ""


def iw_mode(iface: str) -> str:
    """Current 802.11 mode via `iw dev <iface> info` (e.g. managed/monitor).
    Only called for a FREE Wi-Fi interface (never one mid-capture). "" on any
    failure; never raises."""
    try:
        p = subprocess.run(["iw", "dev", iface, "info"], capture_output=True,
                           text=True, timeout=5, check=False)
        out = (p.stdout or "") + (p.stderr or "")
    except Exception:  # noqa: BLE001
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split(None, 1)[1].strip()
    return ""


def interfaces_panel(config, registry) -> dict:
    """Build the panel view-model from cached registry state + sysfs, touching
    the host as little as possible. Pure read."""
    reservations = registry.reservations()         # {iface: {mode,run_id,pid,ts,alive}}
    default_if = core_state.default_route_iface() or ""
    ssh_if = core_state.ssh_iface()

    rows = []
    for iface in present_interfaces():
        if iface == "lo":
            continue
        res = reservations.get(iface)
        busy = bool(res and res.get("alive"))
        wifi = is_wifi(iface)

        if res:
            # Reserved (busy or a stale-but-present entry): report the recorded
            # mode. NEVER probe a mid-capture interface with iw.
            mode = res.get("mode", "?")
        elif wifi:
            mode = iw_mode(iface) or "managed"      # free Wi-Fi: safe to probe
        else:
            mode = "—"

        # Busy attribution: a friendly holder name (the workflow), never a raw
        # run_id. Falls back to 'run <run_id>' for a reservation with no label.
        holder = ""
        if busy:
            holder = res.get("label") or ("run " + str(res.get("run_id", "")))

        rows.append({
            "iface": iface,
            "kind": "USB" if is_usb(iface) else "built-in",
            "usb": is_usb(iface),
            "wifi": wifi,
            "driver": iface_driver(iface) or "?",
            "mode": mode,
            "busy": busy,
            "holder": holder,
            "run_id": res.get("run_id", "") if busy else "",
            "pid": res.get("pid", "") if busy else "",
            "default_route": iface == default_if,
            "ssh": bool(ssh_if) and iface == ssh_if,
            "operstate": operstate(iface),
        })

    return {
        "interfaces": rows,
        "default_iface": default_if,
        "ssh_iface": ssh_if,
        "count": len(rows),
    }


def supports_monitor(iface: str) -> bool:
    """True if the adapter's phy advertises monitor mode (via `iw`). Only called
    for FREE Wi-Fi interfaces — never one mid-capture. Never raises."""
    try:
        phy = (_sys_net() / iface / "phy80211" / "name").read_text(encoding="utf-8").strip()
    except OSError:
        phy = ""
    args = ["iw", "phy", phy, "info"] if phy else ["iw", "dev", iface, "info"]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=6, check=False)
        return "monitor" in ((p.stdout or "") + (p.stderr or "")).lower()
    except Exception:  # noqa: BLE001
        return False


def monitor_interface_choices(config, registry, default: str = "") -> List[dict]:
    """Selectable Wi-Fi interfaces for a picker. Busy interfaces are listed but
    non-selectable, annotated with the holder's friendly name; the default-route
    / SSH interface is non-selectable (self-lockout). A busy monitor reservation
    is assumed monitor-capable (never probed with iw mid-capture)."""
    reservations = registry.reservations()
    default_if = core_state.default_route_iface() or ""
    ssh_if = core_state.ssh_iface()

    out = []
    for iface in present_interfaces():
        if iface == "lo" or not is_wifi(iface):
            continue
        res = reservations.get(iface)
        busy = bool(res and res.get("alive"))
        unsafe = (iface == default_if) or (bool(ssh_if) and iface == ssh_if)
        capable = True if busy else supports_monitor(iface)
        holder = ""
        if busy:
            holder = res.get("label") or ("run " + str(res.get("run_id", "")))
        selectable = capable and not busy and not unsafe
        if unsafe:
            note = "default-route / SSH — protected"
        elif busy:
            note = "busy — in use by " + holder
        elif not capable:
            note = "no monitor mode"
        else:
            note = ""
        out.append({
            "iface": iface, "busy": busy, "holder": holder, "unsafe": unsafe,
            "capable": capable, "selectable": selectable, "note": note,
            "is_default": iface == default,
        })
    return out


def mgmt_ap_interface_choices(config, registry, selected: str = "",
                              iface_info: Optional[dict] = None) -> List[dict]:
    """Candidate NICs for the DEDICATED management-AP interface picker (Phase P2).

    Lists Wi-Fi interfaces with the facts needed to pick safely: MAC + USB path (to
    tell two identical dongles apart), whether the NIC is USB-attached, AP-capable
    (from ``iface_info`` when supplied — live nmcli discovery — else unknown), busy
    (reserved by an alive run), and whether it is a protected interface. ``wlan0`` and
    the default-route/SSH interface are listed but NON-selectable: the management AP
    must never run on the onboard adapter or the uplink. Pure read."""
    reservations = registry.reservations()
    default_if = core_state.default_route_iface() or ""
    ssh_if = core_state.ssh_iface()
    info = iface_info or {}

    out = []
    for iface in present_interfaces():
        if iface == "lo" or not is_wifi(iface):
            continue
        res = reservations.get(iface)
        busy = bool(res and res.get("alive"))
        usb = is_usb(iface)
        unsafe = (iface == default_if) or (bool(ssh_if) and iface == ssh_if)
        is_onboard = iface == "wlan0"
        # AP-capability: honour live discovery when present; unknown (None) otherwise.
        cap = info.get(iface, {}).get("ap_capable") if iface in info else None
        ap_capable = (cap is not False)        # unknown is treated as "maybe"
        holder = ""
        if busy:
            holder = res.get("label") or ("run " + str(res.get("run_id", "")))
        # Any AP-capable Wi-Fi interface that is NOT wlan0 and NOT the live uplink/SSH
        # is selectable — a spare USB dongle OR the onboard chip when it is free (the
        # real safety rule is "not the uplink", which `unsafe` enforces). USB is still
        # surfaced (MAC + port) to tell identical dongles apart, just not required.
        selectable = ap_capable and not busy and not unsafe and not is_onboard
        if is_onboard:
            note = "wlan0 — reserved for the uplink by convention"
        elif unsafe:
            note = "default-route / SSH — protected"
        elif busy:
            note = "busy — in use by " + holder
        elif cap is False:
            note = "not AP-capable"
        elif not usb:
            note = "onboard — free, usable as the AP"
        else:
            note = ""
        out.append({
            "iface": iface, "mac": iface_mac(iface), "usb_path": usb_path(iface),
            "usb": usb, "busy": busy, "holder": holder, "unsafe": unsafe,
            "onboard": is_onboard, "ap_capable": ap_capable, "selectable": selectable,
            "selected": iface == selected, "note": note,
        })
    return out


# --------------------------------------------------------------------------- #
# privileged mode switch (same scoped-sudo iw/ip approach as red.wifi_scan)
# --------------------------------------------------------------------------- #
def _priv(args: List[str]) -> List[str]:
    """Prefix `sudo -n` unless already root (the dashboard runs unprivileged;
    the scoped sudoers rule allows exactly iw/ip/airodump-ng)."""
    if os.geteuid() == 0:
        return list(args)
    return ["sudo", "-n", *args]


def _run(args: List[str], timeout: int = 10):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           check=False)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except Exception as e:  # noqa: BLE001
        return 127, str(e)


def set_interface_mode(iface: str, mode: str) -> tuple:
    """Set `iface` to 'monitor' or 'managed' via iw/ip (down → set type → up),
    the same approach red.wifi_scan uses. Returns (ok, message). Never raises.

    The CALLER must have passed the central interface_safety_check() first — this
    performs no safety gating of its own."""
    if mode not in ("monitor", "managed"):
        return (False, f"invalid mode {mode!r}")
    _run(_priv(["ip", "link", "set", iface, "down"]))
    rc, out = _run(_priv(["iw", "dev", iface, "set", "type", mode]))
    _run(_priv(["ip", "link", "set", iface, "up"]))
    if rc != 0:
        hint = ("needs root — the scoped sudoers rule for iw/ip may be missing "
                "(see deploy/sudoers.d/sentinel-wifi)") if os.geteuid() != 0 \
            else "iw rejected the mode change"
        detail = f": {out}" if out else ""
        return (False, f"could not set {iface} to {mode} mode (rc={rc}; {hint}){detail}")
    return (True, f"{iface} set to {mode} mode")
