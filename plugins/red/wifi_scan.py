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
import subprocess
import tempfile
from pathlib import Path
from shutil import which
from typing import List, Optional, Tuple

from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity

# RTL8188EUS presents under one of these driver module names (new out-of-tree
# `rtl8188eus`, or the legacy in-kernel `r8188eu`) and these USB ids.
RTL_DRIVERS = {"rtl8188eus", "r8188eu", "8188eu"}
RTL_USB_IDS = {("0bda", "8179"), ("0bda", "0179"), ("2357", "010c"), ("0bda", "f179")}

# The Config default for wifi_iface (CLAUDE.md). It is NOT treated as an explicit
# pin — otherwise a stray `wlan1` would be assumed by name, which is exactly what
# this module must avoid. Only a deliberate override (env, or the dashboard/CLI
# option) counts as a pin.
_DEFAULT_WIFI_IFACE = "wlan1"

# The monitor-grade out-of-tree driver the setup helper installs. The WN722N
# v2/v3 is otherwise claimed by the generic in-kernel `rtl8xxxu` (or legacy
# `r8188eu`), whose monitor support is unreliable — so the module is "available"
# only once this driver owns the adapter (install it + reboot; see
# deploy/wifi-monitor-setup.sh).
MONITOR_DRIVER = "rtl8188eus"


# --------------------------------------------------------------------------- #
# low-level helpers (module-level so tests can monkeypatch them)
# --------------------------------------------------------------------------- #
def _run_cmd(args: List[str], timeout: int = 10) -> Tuple[int, str]:
    """Run a command with an explicit arg list (never shell=True). Returns
    (returncode, stdout). Never raises — a missing binary yields (127, "")."""
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, (p.stdout or "")
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


def _default_route_iface() -> Optional[str]:
    """Interface carrying the default route (the Pi's uplink)."""
    rc, out = _run_cmd(["ip", "route"], timeout=5)
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    return None


def _ssh_iface() -> str:
    """Interface that owns the local IP of the active SSH connection, so we can
    refuse to tear it down. "" when not under SSH / not determinable."""
    conn = os.environ.get("SSH_CONNECTION", "")
    parts = conn.split()
    if len(parts) < 3:
        return ""
    server_ip = parts[2]
    rc, out = _run_cmd(["ip", "-o", "addr", "show"], timeout=5)
    for line in out.splitlines():
        toks = line.split()
        # "<idx>: <iface> <family> <ip>/<prefix> ..."
        if len(toks) >= 4 and toks[3].split("/")[0] == server_ip:
            return toks[1]
    return ""


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
    own connectivity (default route or active SSH)."""
    if iface and iface == _default_route_iface():
        return (f"{iface} carries the default route (the Pi's uplink); refusing "
                "to avoid self-lockout")
    ssh_if = _ssh_iface()
    if ssh_if and iface == ssh_if:
        return (f"{iface} carries the active SSH connection; refusing to avoid "
                "self-lockout")
    return ""


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
    notes: List[str] = []
    if bound == "r8188eu":
        notes.append("the OLD in-kernel r8188eu owns the adapter — reboot so the "
                     f"blacklist takes effect and {MONITOR_DRIVER} loads instead")
    elif adapter and bound and bound != MONITOR_DRIVER:
        notes.append(f"the adapter is bound to the generic '{bound}' driver, not the "
                     f"monitor-grade {MONITOR_DRIVER} — run deploy/wifi-monitor-setup.sh "
                     "then reboot")
    if adapter and adapter == default_if:
        notes.append(f"{adapter} is the default-route interface — it will be refused "
                     "as a scan target (self-lockout guard)")
    monitor_ok = bool(adapter) and _supports_monitor(adapter)
    correct_driver = bound == MONITOR_DRIVER
    ready = (bool(adapter) and adapter != default_if and monitor_ok and correct_driver)
    return {
        "driver_dkms": _dkms_has_rtl(),
        "module_loaded": bound or _module_loaded(),
        "correct_driver": correct_driver,
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
        drv = _iface_driver(iface)
        if drv != MONITOR_DRIVER:
            return (False, f"adapter on {iface} uses the '{drv or 'unknown'}' driver, "
                           f"not the monitor-grade {MONITOR_DRIVER} — run "
                           "deploy/wifi-monitor-setup.sh then reboot "
                           "(`sentinel wifi-check` to verify)")
        if not _supports_monitor(iface):
            return (False, f"{iface} cannot enter monitor mode "
                           "(driver not ready? reboot after setup)")
        return (True, "")

    # --- monitor-mode control (all via iw/ip; NEVER airmon-ng) ------------
    def _enable_monitor(self, ctx, iface: str) -> None:
        ctx.log.info("wifi_scan: enabling monitor mode on %s via iw/ip "
                     "(NOT airmon-ng; the Pi's networking is untouched)", iface)
        _run_cmd(["ip", "link", "set", iface, "down"])
        rc, _ = _run_cmd(["iw", "dev", iface, "set", "type", "monitor"])
        _run_cmd(["ip", "link", "set", iface, "up"])
        if rc != 0:
            raise RuntimeError(f"could not set {iface} to monitor mode (rc={rc})")

    def _set_channel(self, ctx, iface: str, channel: str) -> None:
        _run_cmd(["iw", "dev", iface, "set", "channel", channel])

    def _restore_managed(self, ctx, iface: str) -> None:
        """Guaranteed cleanup — return the adapter to managed mode. Defensive:
        never raises, so it is safe to call from a finally block."""
        try:
            _run_cmd(["ip", "link", "set", iface, "down"])
            _run_cmd(["iw", "dev", iface, "set", "type", "managed"])
            _run_cmd(["ip", "link", "set", iface, "up"])
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
        try:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            raise RuntimeError("airodump-ng not found")
        try:
            proc.wait(timeout=duration)          # normally times out (we want the full run)
        except subprocess.TimeoutExpired:
            proc.terminate()                     # SIGTERM -> airodump flushes CSV + exits
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

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
