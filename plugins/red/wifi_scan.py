"""red.wifi_scan — passive Wi-Fi reconnaissance with airodump-ng (Phase 1).

**PASSIVE / OBSERVE-ONLY.** This module listens for 802.11 beacons/probes and
lists the networks and clients in range. It never transmits, deauthenticates,
injects, or attacks — airodump-ng is invoked without any `--deauth`/injection
option, and no `aireplay`/`airmon-ng` is used.

Hardware: a monitor-capable USB adapter — the Alfa/TP-Link WN722N v2/v3
(Realtek RTL8188EUS). The adapter is found by **driver/chipset**, never by
interface name (we never assume `wlan1`). See `deploy/wifi-monitor-setup.sh` to
install the out-of-tree `rtl8188eus` DKMS driver and `sentinel wifi-check` to
verify it.

Safety:
  * We enable monitor mode with `iw`/`ip` on that ONE adapter. We do **not** run
    `airmon-ng check kill` or otherwise touch NetworkManager/wpa_supplicant, so
    the Pi's own networking and your SSH session are never dropped.
  * We refuse to use the interface that carries the default route or the active
    SSH connection (self-lockout guard).
  * The adapter is restored to managed mode on finish AND on any error, and the
    temporary airodump capture files are always deleted (even on error).
"""
from __future__ import annotations

import csv
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from shutil import which
from typing import List, Optional, Tuple

from core import state as _state
from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity
from core.state import get_interface_registry

# RTL8188EUS presents under one of these driver module names (new out-of-tree
# `rtl8188eus`, or the legacy in-kernel `r8188eu`) and these USB ids.
RTL_DRIVERS = {"rtl8188eus", "r8188eu", "8188eu"}
RTL_USB_IDS = {("0bda", "8179"), ("0bda", "0179"), ("2357", "010c"), ("0bda", "f179")}

# The Config default for wifi_iface (CLAUDE.md). It is NOT treated as an explicit
# pin — otherwise a stray `wlan1` would be assumed by name, which is exactly what
# this module must avoid. Only a deliberate override (env, or the dashboard/CLI
# option) counts as a pin.
_DEFAULT_WIFI_IFACE = "wlan1"

# Drivers known to provide monitor mode for the WN722N v2/v3: the out-of-tree
# `rtl8188eus` (what the setup helper installs on older kernels) AND the in-kernel
# `rtl8xxxu`, which supports monitor mode on kernel 6.13+ where the out-of-tree
# driver no longer builds. This set is ADVISORY (used only for clearer messaging);
# availability is decided by whether monitor mode actually works — verified live
# via `iw` supported-interface-modes (`_supports_monitor`) — not by a driver name.
MONITOR_DRIVERS = {"rtl8188eus", "rtl8xxxu"}


# --------------------------------------------------------------------------- #
# low-level helpers (module-level so tests can monkeypatch them)
# --------------------------------------------------------------------------- #
def _priv(args: List[str]) -> List[str]:
    """Prefix `sudo -n` to a privileged command when we are NOT already root.

    The app/dashboard runs as the unprivileged `sentinel` user, but putting the
    adapter into monitor mode (iw/ip) and capturing (airodump-ng) need root.
    `sudo -n` never prompts — a missing sudoers rule fails fast (rc 1) with a
    clear message instead of hanging. The tightly-scoped rule (exactly iw, ip,
    airodump-ng) lives in deploy/sudoers.d/sentinel-wifi."""
    if os.geteuid() == 0:
        return list(args)
    return ["sudo", "-n", *args]


def _run_cmd(args: List[str], timeout: int = 10) -> Tuple[int, str]:
    """Run a command with an explicit arg list (never shell=True). Returns
    (returncode, stdout+stderr). Never raises — a missing binary yields (127, "")."""
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))
    except Exception:  # noqa: BLE001 — detection/cleanup must never crash a run
        return 127, ""


def _sys_net() -> Path:
    return Path("/sys/class/net")


def _wifi_interfaces() -> List[str]:
    """Names of 802.11 interfaces (those with a wireless/phy80211 sysfs node)."""
    out = []
    try:
        for d in sorted(_sys_net().iterdir()):
            if (d / "wireless").exists() or (d / "phy80211").exists():
                out.append(d.name)
    except OSError:
        return []
    return out


def _iface_driver(iface: str) -> str:
    """The kernel driver module bound to `iface` (basename of the driver
    symlink), lowercased; "" if unknown."""
    try:
        link = os.readlink(str(_sys_net() / iface / "device" / "driver"))
        return os.path.basename(link).lower()
    except OSError:
        return ""


def _iface_usb_id(iface: str) -> Tuple[str, str]:
    """(idVendor, idProduct) for a USB-attached iface, walking up to the USB
    device node; ("", "") when not determinable."""
    dev = _sys_net() / iface / "device"
    for _ in range(5):                 # climb a few parents to the USB device
        try:
            vid = (dev / "idVendor").read_text().strip().lower()
            pid = (dev / "idProduct").read_text().strip().lower()
            if vid and pid:
                return vid, pid
        except OSError:
            pass
        try:
            dev = dev.resolve().parent
        except OSError:
            break
    return "", ""


def _is_rtl8188eus(iface: str) -> bool:
    if _iface_driver(iface) in RTL_DRIVERS:
        return True
    return _iface_usb_id(iface) in RTL_USB_IDS


# Default-route / SSH interface detection lives ONCE in core.state so the
# self-lockout guard here and the central interface-safety check share a single
# implementation. These module-level aliases keep the historic names (and keep
# them monkeypatchable in this module's tests); everything below calls them via
# the module global, so a test that rebinds them is honored.
_default_route_iface = _state.default_route_iface
_ssh_iface = _state.ssh_iface


def _iface_phy(iface: str) -> str:
    try:
        return (_sys_net() / iface / "phy80211" / "name").read_text().strip()
    except OSError:
        return ""


def _supports_monitor(iface: str) -> bool:
    """True if the adapter's phy advertises monitor mode (via `iw`)."""
    phy = _iface_phy(iface)
    args = ["iw", "phy", phy, "info"] if phy else ["iw", "list"]
    rc, out = _run_cmd(args, timeout=8)
    if rc != 0 and not out:
        return False
    return "monitor" in out.lower()


def _explicit_pin(config) -> str:
    """A deliberately-chosen interface override, or "". Honors env
    SENTINEL_WIFI_IFACE and a dashboard/CLI `config.wifi_iface` that was set to
    something other than the baked-in default — but never the default itself, so
    we don't assume `wlan1` by name."""
    env = (os.environ.get("SENTINEL_WIFI_IFACE") or "").strip()
    if env:
        return env
    cfgif = (getattr(config, "wifi_iface", "") or "").strip()
    if cfgif and cfgif != _DEFAULT_WIFI_IFACE:
        return cfgif
    return ""


def detect_adapter(config) -> Optional[str]:
    """The USB RTL8188EUS interface to scan with, found by **driver/chipset**,
    not by name. A deliberate operator override (`_explicit_pin`) wins when it
    names a present interface; otherwise auto-detect by chipset, skipping the
    default-route (built-in) interface so we never target the Pi's own uplink.
    Returns None if none found."""
    wifis = _wifi_interfaces()
    pin = _explicit_pin(config)
    if pin and pin in wifis:
        return pin
    default_if = _default_route_iface()
    for iface in wifis:
        if iface == default_if:
            continue
        if _is_rtl8188eus(iface):
            return iface
    return None


def _self_link_reason(iface: str) -> str:
    """Non-empty reason to REFUSE `iface` because using it would drop the Pi's
    own connectivity (default route or active SSH).

    Delegates to the shared guard in core.state, passing this module's
    (patchable) detectors so there is one implementation, not two."""
    return _state.self_link_reason(iface, route_fn=_default_route_iface,
                                   ssh_fn=_ssh_iface)


# --- driver diagnostics (for `sentinel wifi-check`) ------------------------ #
def _module_loaded() -> str:
    """Which RTL8188EUS driver is loaded: "rtl8188eus" (new), "r8188eu" (old
    in-kernel), or "" (none)."""
    try:
        text = Path("/proc/modules").read_text()
    except OSError:
        return ""
    names = {ln.split()[0] for ln in text.splitlines() if ln.split()}
    if "rtl8188eus" in names:
        return "rtl8188eus"
    if "r8188eu" in names or "8188eu" in names:
        return "r8188eu"
    return ""


def _dkms_has_rtl() -> bool:
    if which("dkms") is None:
        return False
    rc, out = _run_cmd(["dkms", "status"], timeout=8)
    return "rtl8188eus" in out.lower()


def wifi_check(config) -> dict:
    """Diagnostics for the Wi-Fi monitor adapter (driver / module / interface /
    monitor capability). Pure data; the CLI formats it."""
    wifis = _wifi_interfaces()
    default_if = _default_route_iface() or ""
    adapter = detect_adapter(config)
    # The driver actually bound to the detected adapter is the precise signal of
    # readiness (more reliable than scanning /proc/modules).
    bound = _iface_driver(adapter) if adapter else ""
    monitor_ok = bool(adapter) and _supports_monitor(adapter)
    known_driver = bound in MONITOR_DRIVERS
    notes: List[str] = []
    if adapter and not monitor_ok:
        if bound == "r8188eu":
            notes.append("the legacy r8188eu owns the adapter and does not support "
                         "monitor mode — run deploy/wifi-monitor-setup.sh then reboot")
        else:
            notes.append(f"the '{bound or 'unknown'}' driver on the adapter does not "
                         "advertise monitor mode — run deploy/wifi-monitor-setup.sh "
                         "(and reboot if it says to)")
    elif adapter and monitor_ok and not known_driver:
        notes.append(f"monitor mode works via the '{bound}' driver (not a recognised "
                     "name, but accepted because it supports monitor mode)")
    if adapter and adapter == default_if:
        notes.append(f"{adapter} is the default-route interface — it will be refused "
                     "as a scan target (self-lockout guard)")
    # Readiness is driven by ACTUAL monitor capability (iw), not the driver name.
    ready = bool(adapter) and adapter != default_if and monitor_ok
    return {
        "driver_dkms": _dkms_has_rtl(),
        "module_loaded": bound or _module_loaded(),
        "known_driver": known_driver,
        "wifi_interfaces": wifis,
        "default_iface": default_if,
        "adapter_iface": adapter or "",
        "monitor_ok": monitor_ok,
        "ready": ready,
        "notes": notes,
    }


# --------------------------------------------------------------------------- #
# airodump CSV parsing (pure function — easy to unit-test)
# --------------------------------------------------------------------------- #
def _row(line: str) -> List[str]:
    try:
        return [c.strip() for c in next(csv.reader([line]))]
    except StopIteration:
        return []


def _norm_enc(privacy: str) -> str:
    p = (privacy or "").strip().upper()
    if p in ("", "OPN", "OPEN", "NONE"):
        return "OPEN"
    return p


def _parse_airodump_csv(text: str) -> Tuple[List[dict], List[dict]]:
    """Parse an airodump-ng CSV into (access_points, clients).

    The file has an AP table (header starts "BSSID,") then a blank line then a
    station table (header starts "Station MAC,"). Columns are matched by name so
    minor airodump version differences are tolerated. A column whose name
    contains "wps" (some builds) flags WPS."""
    lines = [ln.rstrip("\r") for ln in (text or "").splitlines()]
    ap_hdr = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("BSSID,")), None)
    st_hdr = next((i for i, ln in enumerate(lines)
                   if ln.lstrip().startswith("Station MAC,")), None)

    def section(start: int) -> List[dict]:
        if start is None:
            return []
        header = [h.lower() for h in _row(lines[start])]
        rows = []
        for ln in lines[start + 1:]:
            if not ln.strip():
                break                  # blank line terminates the table
            vals = _row(ln)
            if not vals:
                continue
            vals += [""] * (len(header) - len(vals))
            rows.append(dict(zip(header, vals)))
        return rows

    aps = []
    for r in section(ap_hdr):
        bssid = r.get("bssid", "")
        if not bssid:
            continue
        wps_col = next((v for k, v in r.items() if "wps" in k), "")
        wps = bool(wps_col) and wps_col.strip().lower() not in ("", "0", "no", "n")
        aps.append({
            "bssid": bssid,
            "essid": r.get("essid", ""),
            "channel": (r.get("channel", "") or "").strip(),
            "encryption": _norm_enc(r.get("privacy", "")),
            "cipher": r.get("cipher", ""),
            "auth": r.get("authentication", ""),
            "signal": (r.get("power", "") or "").strip(),
            "wps": wps,
        })

    clients = []
    for r in section(st_hdr):
        mac = r.get("station mac", "")
        if not mac:
            continue
        clients.append({
            "mac": mac,
            "bssid": r.get("bssid", ""),
            "signal": (r.get("power", "") or "").strip(),
        })
    return aps, clients


# --------------------------------------------------------------------------- #
# the module
# --------------------------------------------------------------------------- #
@register
class WifiScan(Module):
    manifest = Manifest(
        name="red.wifi_scan",
        category="red",
        title="Wi-Fi scan (airodump-ng)",
        description="Passive 802.11 reconnaissance: list APs and clients in range "
                    "(observe only — never transmits, deauths, or injects).",
        requires_tools=["airodump-ng"],
        requires_hw=["wifi_monitor"],
        provides=["wifi_aps", "wifi_clients"],
        phase="1",
        display="Wi-Fi scan (airodump-ng)",
    )

    # --- availability -----------------------------------------------------
    def is_available(self, ctx) -> Tuple[bool, str]:
        if which("airodump-ng") is None:
            return (False, "airodump-ng not installed (apt install aircrack-ng)")
        try:
            iface = detect_adapter(ctx.config)
        except Exception as e:  # noqa: BLE001 — probe must never raise
            return (False, f"adapter detection failed: {e}")
        if not iface:
            return (False, "no RTL8188EUS monitor adapter detected "
                           "(run `sentinel wifi-check`)")
        reason = _self_link_reason(iface)
        if reason:
            return (False, reason)
        # Availability is decided by whether monitor mode ACTUALLY works (checked
        # live via `iw` supported-interface-modes), not by a hardcoded driver
        # name — so both the out-of-tree `rtl8188eus` and the in-kernel `rtl8xxxu`
        # (monitor-capable on kernel 6.13+) are accepted.
        if not _supports_monitor(iface):
            drv = _iface_driver(iface)
            return (False, f"{iface} (driver '{drv or 'unknown'}') does not support "
                           "monitor mode — run deploy/wifi-monitor-setup.sh "
                           "(and reboot if it says to), then `sentinel wifi-check`")
        return (True, "")

    # --- monitor-mode control (iw/ip via sudo -n; NEVER airmon-ng) --------
    def _enable_monitor(self, ctx, iface: str) -> None:
        ctx.log.info("wifi_scan: enabling monitor mode on %s via iw/ip "
                     "(NOT airmon-ng; the Pi's networking is untouched)", iface)
        _run_cmd(_priv(["ip", "link", "set", iface, "down"]))
        rc, out = _run_cmd(_priv(["iw", "dev", iface, "set", "type", "monitor"]))
        _run_cmd(_priv(["ip", "link", "set", iface, "up"]))
        if rc != 0:
            hint = ("needs root — the sudoers rule for iw/ip is missing "
                    "(see deploy/sudoers.d/sentinel-wifi)") if os.geteuid() != 0 \
                else "iw rejected the mode change"
            raise RuntimeError(f"could not set {iface} to monitor mode (rc={rc}; {hint})"
                               + (f": {out.strip()}" if out.strip() else ""))

    def _set_channel(self, ctx, iface: str, channel: str) -> None:
        _run_cmd(_priv(["iw", "dev", iface, "set", "channel", channel]))

    def _restore_managed(self, ctx, iface: str) -> None:
        """Guaranteed cleanup — return the adapter to managed mode. Defensive:
        never raises, so it is safe to call from a finally block."""
        try:
            _run_cmd(_priv(["ip", "link", "set", iface, "down"]))
            _run_cmd(_priv(["iw", "dev", iface, "set", "type", "managed"]))
            _run_cmd(_priv(["ip", "link", "set", iface, "up"]))
            ctx.log.info("wifi_scan: restored %s to managed mode", iface)
        except Exception as e:  # noqa: BLE001
            ctx.log.error("wifi_scan: failed to restore %s to managed: %s", iface, e)

    def _run_airodump(self, ctx, iface: str, outdir: Path, duration: int,
                      channel: str) -> None:
        """Run airodump-ng PASSIVELY for `duration` seconds, writing CSV to
        `outdir`. No injection/deauth options are ever passed."""
        prefix = str(outdir / "scan")
        args = ["airodump-ng", "--output-format", "csv", "--write-interval", "1",
                "-w", prefix]
        if channel:
            args += ["-c", channel]
        args.append(iface)
        args = _priv(args)            # airodump needs root to capture on the monitor iface
        try:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            raise RuntimeError("airodump-ng not found")
        try:
            proc.wait(timeout=duration)          # normally times out (we want the full run)
        except subprocess.TimeoutExpired:
            # SIGINT (not SIGTERM/SIGKILL): airodump handles it, writes a final CSV,
            # and exits cleanly. Under `sudo` this is forwarded to airodump, so the
            # root process does not linger holding the interface in monitor mode.
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.send_signal(signal.SIGINT)  # second nudge, then give up gracefully
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()

    def _read_csv(self, outdir: Path) -> str:
        """Return the airodump AP/station CSV text (not the .kismet/.log CSVs)."""
        best = ""
        try:
            for p in sorted(outdir.glob("*.csv")):
                if ".kismet" in p.name or ".log" in p.name:
                    continue
                txt = p.read_text(encoding="utf-8", errors="replace")
                if "BSSID," in txt and len(txt) >= len(best):
                    best = txt
        except OSError:
            return best
        return best

    # --- run --------------------------------------------------------------
    def run(self, ctx) -> None:
        cfg = ctx.config

        if which("airodump-ng") is None:
            self._skip(ctx, "airodump-ng not installed")
            return
        try:
            iface = detect_adapter(cfg)
        except Exception as e:  # noqa: BLE001
            self._skip(ctx, f"adapter detection failed: {e}")
            return
        if not iface:
            self._skip(ctx, "no RTL8188EUS monitor adapter detected")
            return
        reason = _self_link_reason(iface)
        if reason:
            ctx.log.warning("wifi_scan: %s", reason)
            self._skip(ctx, reason)
            return

        # Reserve the monitor interface through the central registry so a
        # concurrent run (or a CLI holding it) can't fight over the adapter.
        # The reservation is released in the finally below, on finish AND error.
        reg = get_interface_registry(cfg)
        run_id = getattr(getattr(ctx.store, "run", None), "run_id", "") or "wifi_scan"
        claimed, busy = reg.claim(iface, run_id, mode="monitor")
        if not claimed:
            ctx.log.warning("wifi_scan: %s", busy)
            self._skip(ctx, busy)
            return

        duration = max(1, int(getattr(cfg, "wifi_scan_seconds", 30) or 30))
        channel = (getattr(cfg, "wifi_scan_channel", "") or "").strip()
        outdir = self._make_outdir(cfg)
        attempted = False
        try:
            self._enable_monitor(ctx, iface)
            attempted = True
            if channel:
                self._set_channel(ctx, iface, channel)
            ctx.log.info("wifi_scan: capturing on %s for %ds (%s)", iface, duration,
                         f"channel {channel}" if channel else "channel-hopping")
            self._run_airodump(ctx, iface, outdir, duration, channel)
            aps, clients = _parse_airodump_csv(self._read_csv(outdir))
            self._emit(ctx, aps, clients)
            if not aps and not clients:
                # Monitor mode was accepted but airodump saw nothing. In a populated
                # area this usually means the driver's monitor RX does not actually
                # deliver frames — a known limitation of the in-kernel rtl8xxxu for
                # the RTL8188EU/EUS (iw advertises monitor, but no packets arrive).
                drv = _iface_driver(iface)
                ctx.store.add_finding(
                    module=self.manifest.name, type="module_status",
                    severity=Severity.INFO, target=iface,
                    title="Wi-Fi scan captured no frames",
                    detail=(f"Monitor mode enabled on {iface} (driver '{drv or '?'}') but "
                            f"airodump-ng captured 0 APs/clients in {duration}s. If networks "
                            "are in range this points to the driver not delivering monitor "
                            "frames — the in-kernel rtl8xxxu does not capture for this chip; "
                            "install the out-of-tree rtl8188eus driver (see "
                            "deploy/wifi-monitor-setup.sh)."),
                    evidence=f"0 APs after {duration}s on driver {drv or '?'}",
                    tags=["wireless", "diagnostic"])
            ctx.log.info("wifi_scan: complete — %d AP(s), %d client(s)",
                         len(aps), len(clients))
        except Exception as e:  # noqa: BLE001 — a scan failure must not crash the run
            ctx.log.error("wifi_scan failed: %s", e)
            ctx.store.add_finding(
                module=self.manifest.name, type="module_error",
                severity=Severity.LOW, target=iface, title="Wi-Fi scan failed",
                detail=str(e), evidence="airodump-ng", tags=["wireless", "error"],
            )
        finally:
            if attempted:
                self._restore_managed(ctx, iface)   # guaranteed restore
            reg.release(iface, run_id)               # guaranteed release
            self._cleanup(outdir)                    # guaranteed temp cleanup

    # --- helpers ----------------------------------------------------------
    def _make_outdir(self, config) -> Path:
        base = getattr(config, "captures_dir", None)
        try:
            base = Path(base)
            base.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa: BLE001
            base = Path(tempfile.gettempdir())
        return Path(tempfile.mkdtemp(prefix="wifiscan-", dir=str(base)))

    def _cleanup(self, outdir: Path) -> None:
        shutil.rmtree(outdir, ignore_errors=True)    # removes csv/cap/netxml droppings

    def _skip(self, ctx, reason: str) -> None:
        ctx.log.info("wifi_scan: skipped (%s)", reason)
        ctx.store.add_finding(
            module=self.manifest.name, type="module_status",
            severity=Severity.INFO, target="(wifi)",
            title="Wi-Fi scan skipped", detail=reason,
            evidence="", tags=["wireless", "skipped"],
        )

    def _emit(self, ctx, aps: List[dict], clients: List[dict]) -> None:
        for ap in aps:
            bssid = ap["bssid"]
            enc = ap["encryption"]
            label = ap["essid"] or "<hidden>"
            ctx.store.add_asset(
                ip=bssid, kind="wifi_ap", mac=bssid, alive=True,
                hostname=ap["essid"], ssid=ap["essid"], channel=ap["channel"],
                encryption=enc, signal=ap["signal"],
            )
            ev = f"BSSID {bssid} ch {ap['channel'] or '?'} enc {enc}"
            if enc == "OPEN":
                ctx.store.add_finding(
                    module=self.manifest.name, type="wifi_open",
                    severity=Severity.MEDIUM, target=bssid,
                    title=f"Open Wi-Fi network: {label}",
                    detail="No encryption — any client's traffic is observable.",
                    evidence=ev, tags=["wireless", "open", "wifi_ap"],
                )
            elif "WEP" in enc:
                ctx.store.add_finding(
                    module=self.manifest.name, type="wifi_wep",
                    severity=Severity.MEDIUM, target=bssid,
                    title=f"WEP Wi-Fi network: {label}",
                    detail="WEP is broken/legacy encryption and trivially cracked.",
                    evidence=ev, tags=["wireless", "wep", "wifi_ap"],
                )
            if ap["wps"]:
                ctx.store.add_finding(
                    module=self.manifest.name, type="wifi_wps",
                    severity=Severity.LOW, target=bssid,
                    title=f"WPS enabled: {label}",
                    detail="WPS PIN registration is vulnerable to brute force.",
                    evidence=ev + " WPS", tags=["wireless", "wps", "wifi_ap"],
                )
        for cl in clients:
            ctx.store.add_asset(
                ip=cl["mac"], kind="wifi_client", mac=cl["mac"], alive=True,
                signal=cl["signal"],
            )
