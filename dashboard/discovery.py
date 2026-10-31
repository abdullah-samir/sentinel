"""On-demand + background target discovery for the scan launcher.

Two modes (chosen by a Settings toggle):
  (a) **on-demand** (default): a bounded Wi-Fi sweep (airodump-ng) or a
      lightweight ``nmap -sn`` ping sweep, run when the operator clicks "scan
      for targets"; returns a selectable list that fills the target field.
  (b) **background**: a dedicated monitor adapter continuously refreshes a live
      target list (shown busy in the interfaces panel). This REQUIRES a second
      monitor adapter; with only one present it falls back to mode (a) with a
      clear note — never a dead toggle, never blocking scans.

Every Wi-Fi operation claims its adapter through the Part A registry and the
central ``interface_safety_check()``, and releases it (restoring managed mode)
on finish AND on error — an abandoned discovery never holds the radio. The nmap
sweep is standalone and does NOT reuse/modify ``red.recon_nmap``.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from core.state import interface_safety_check
from dashboard import interfaces as interfaces_mod
from plugins.red.wifi_scan import _parse_airodump_csv   # pure CSV parser (reused)

DISCOVERY_DEFAULT_SECONDS = 12
DISCOVERY_MIN_SECONDS = 1
DISCOVERY_MAX_SECONDS = 120
DISCOVERY_RUN_ID = "target-discovery"
DISCOVERY_LABEL = "Target discovery (Wi-Fi)"
BACKGROUND_RUN_ID = "background-monitor"
BACKGROUND_LABEL = "Background target monitor"
BACKGROUND_STALE_S = 15


# --------------------------------------------------------------------------- #
# interface selection helpers (built on the Part A / B1 registry + panel)
# --------------------------------------------------------------------------- #
def monitor_capable_ifaces(config, registry) -> List[dict]:
    """Present, monitor-capable Wi-Fi interfaces that are NOT the default-route/
    SSH interface (either free-selectable or busy)."""
    return [c for c in interfaces_mod.monitor_interface_choices(config, registry)
            if c["capable"] and not c["unsafe"]]


def pick_free_monitor_iface(config, registry, exclude=()) -> Optional[str]:
    for c in interfaces_mod.monitor_interface_choices(config, registry):
        if c["selectable"] and c["iface"] not in exclude:
            return c["iface"]
    return None


def clamp_seconds(seconds) -> int:
    try:
        n = int(seconds)
    except (TypeError, ValueError):
        return DISCOVERY_DEFAULT_SECONDS
    return max(DISCOVERY_MIN_SECONDS, min(n, DISCOVERY_MAX_SECONDS))


def effective_discovery_mode(mode: str, config, registry):
    """Resolve the configured mode against the hardware actually present.

    background requires 2+ monitor adapters; otherwise it falls back to
    on-demand with a note (so the toggle is never dead and scans never block).
    Returns (effective_mode, note)."""
    caps = monitor_capable_ifaces(config, registry)
    if mode == "background":
        if len(caps) >= 2:
            return ("background", "")
        return ("on_demand",
                "Background monitor requires a second monitor adapter "
                f"({len(caps)} present) — using on-demand discovery.")
    return ("on_demand", "")


# --------------------------------------------------------------------------- #
# Wi-Fi discovery (bounded airodump sweep)
# --------------------------------------------------------------------------- #
def _disc_base(config) -> Path:
    base = Path(getattr(config, "captures_dir", ".") )
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        base = Path(tempfile.gettempdir())
    return base


def _run_airodump(iface: str, outdir: Path, seconds: int) -> None:
    """Bounded, PASSIVE airodump-ng sweep writing CSV to `outdir`. No injection/
    deauth options. Stopped with SIGINT so airodump writes a final CSV and frees
    the interface."""
    prefix = str(outdir / "disc")
    args = interfaces_mod._priv(["airodump-ng", "--output-format", "csv",
                                 "--write-interval", "1", "-w", prefix, iface])
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("airodump-ng not found")
    try:
        proc.wait(timeout=max(1, seconds))
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.terminate()


def _read_csv(outdir: Path) -> str:
    best = ""
    try:
        for p in sorted(Path(outdir).glob("*.csv")):
            if ".kismet" in p.name or ".log" in p.name:
                continue
            txt = p.read_text(encoding="utf-8", errors="replace")
            if "BSSID," in txt and len(txt) >= len(best):
                best = txt
    except OSError:
        return best
    return best


def _shape_wifi_targets(aps: List[dict], clients: List[dict]) -> List[dict]:
    """Shape parsed APs/clients into selectable target rows (value fills the
    target field; display is human-readable)."""
    out = []
    for ap in aps:
        bssid = ap.get("bssid", "")
        if not bssid:
            continue
        ssid = ap.get("essid", "") or "<hidden>"
        out.append({
            "kind": "ap", "value": bssid,
            "display": f"{ssid}  ·  {bssid}  ·  ch {ap.get('channel', '?') or '?'}"
                       f"  ·  {ap.get('encryption', '')}  ·  {ap.get('signal', '')} dBm",
            "ssid": ap.get("essid", ""), "bssid": bssid,
            "channel": ap.get("channel", ""), "signal": ap.get("signal", ""),
        })
    for cl in clients:
        mac = cl.get("mac", "")
        if not mac:
            continue
        out.append({
            "kind": "client", "value": mac,
            "display": f"client  ·  {mac}  ·  {cl.get('signal', '')} dBm",
            "signal": cl.get("signal", ""),
        })
    return out


def discover_wifi(config, registry, seconds, iface: Optional[str] = None, *,
                  run_id: str = DISCOVERY_RUN_ID, label: str = DISCOVERY_LABEL,
                  airodump_fn: Optional[Callable] = None,
                  set_mode_fn: Optional[Callable] = None) -> dict:
    """Claim a free monitor adapter, set monitor, sweep for `seconds`, parse the
    discovered APs/clients, then restore managed + release (ALWAYS). Returns
    {ok, iface, seconds, targets, error}. Never raises."""
    seconds = clamp_seconds(seconds)
    airodump_fn = airodump_fn or _run_airodump
    set_mode_fn = set_mode_fn or interfaces_mod.set_interface_mode

    iface = iface or pick_free_monitor_iface(config, registry)
    if not iface:
        return {"ok": False, "iface": "", "seconds": seconds, "targets": [],
                "error": "no free monitor-capable adapter available"}

    ok, reason = interface_safety_check(iface, run_id=run_id, reg=registry)
    if not ok:
        return {"ok": False, "iface": iface, "seconds": seconds, "targets": [],
                "error": reason}
    claimed, busy = registry.claim(iface, run_id, "monitor", label=label)
    if not claimed:
        return {"ok": False, "iface": iface, "seconds": seconds, "targets": [],
                "error": busy}

    outdir = Path(tempfile.mkdtemp(prefix="disc-", dir=str(_disc_base(config))))
    try:
        mok, mmsg = set_mode_fn(iface, "monitor")   # idempotent if already monitor
        if not mok:
            return {"ok": False, "iface": iface, "seconds": seconds, "targets": [],
                    "error": mmsg}
        airodump_fn(iface, outdir, seconds)
        aps, clients = _parse_airodump_csv(_read_csv(outdir))
        return {"ok": True, "iface": iface, "seconds": seconds, "error": "",
                "targets": _shape_wifi_targets(aps, clients)}
    except Exception as e:  # noqa: BLE001 — discovery must never crash the request
        return {"ok": False, "iface": iface, "seconds": seconds, "targets": [],
                "error": str(e)}
    finally:
        try:
            set_mode_fn(iface, "managed")            # restore managed (guaranteed)
        except Exception:  # noqa: BLE001
            pass
        registry.release(iface, run_id)              # release (guaranteed)
        shutil.rmtree(outdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# nmap host discovery (standalone -sn ping sweep; NOT red.recon_nmap)
# --------------------------------------------------------------------------- #
def default_subnet() -> str:
    """Best-effort local /24 (route lookup only, no packets). "" on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:  # noqa: BLE001
        return ""


_NMAP_HOST_RE = re.compile(r"Nmap scan report for (?:.*\()?([0-9]{1,3}(?:\.[0-9]{1,3}){3})")


def _nmap_sn(subnet: str, seconds: int):
    """Run a standalone `nmap -sn -n` ping sweep. Returns (rc, output). Never
    raises. This is a small, dedicated sweep — it does not touch red.recon_nmap."""
    try:
        p = subprocess.run(["nmap", "-sn", "-n", "--host-timeout", "3s", subnet],
                           capture_output=True, text=True,
                           timeout=max(5, int(seconds)), check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "nmap not installed"
    except subprocess.TimeoutExpired as e:
        return 0, (e.stdout or "") if isinstance(e.stdout, str) else ""
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def _parse_nmap_sn(output: str) -> List[str]:
    seen, out = set(), []
    for ip in _NMAP_HOST_RE.findall(output or ""):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def discover_hosts(subnet: str, seconds: int = 30, *,
                   runner: Optional[Callable] = None) -> dict:
    """Standalone nmap -sn ping sweep of `subnet` → selectable live-host list."""
    runner = runner or _nmap_sn
    subnet = (subnet or "").strip() or default_subnet()
    if not subnet:
        return {"ok": False, "subnet": "", "targets": [],
                "error": "could not determine a subnet; enter one (e.g. 10.0.0.0/24)"}
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return {"ok": False, "subnet": subnet, "targets": [],
                "error": f"invalid subnet: {subnet}"}
    rc, out = runner(str(net), seconds)
    if rc == 127:
        return {"ok": False, "subnet": str(net), "targets": [], "error": out or "nmap missing"}
    hosts = _parse_nmap_sn(out)
    return {"ok": True, "subnet": str(net), "error": "",
            "targets": [{"kind": "host", "value": ip, "display": ip} for ip in hosts]}


# --------------------------------------------------------------------------- #
# background monitor (mode b) — dedicates ONE adapter, leaves others free
# --------------------------------------------------------------------------- #
class BackgroundMonitor:
    """Holds a dedicated monitor adapter and refreshes a target list on poll.
    Only active when 2+ monitor adapters are present (checked by the caller via
    effective_discovery_mode); with one adapter it is never engaged."""

    def __init__(self, config, registry, sweep_fn: Optional[Callable] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._config = config
        self._registry = registry
        self._clock = clock
        # sweep_fn(iface, seconds) -> {targets: [...]}; defaults to a real sweep
        # that keeps the adapter (no per-call claim/release — we hold it).
        self._sweep_fn = sweep_fn or self._default_sweep
        self._lock = threading.Lock()
        self._iface = ""
        self._targets: List[dict] = []
        self._ts = 0.0

    def _default_sweep(self, iface: str, seconds: int) -> dict:
        outdir = Path(tempfile.mkdtemp(prefix="bgmon-", dir=str(_disc_base(self._config))))
        try:
            _run_airodump(iface, outdir, seconds)
            aps, clients = _parse_airodump_csv(_read_csv(outdir))
            return {"targets": _shape_wifi_targets(aps, clients)}
        except Exception:  # noqa: BLE001
            return {"targets": []}
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def refresh(self, seconds: int = 5) -> dict:
        """Ensure a dedicated adapter is claimed (leaving others free) and refresh
        the target list if stale. Returns {iface, targets, active}."""
        with self._lock:
            if not self._iface:
                iface = pick_free_monitor_iface(self._config, self._registry)
                if not iface:
                    return {"iface": "", "targets": list(self._targets), "active": False}
                claimed, _busy = self._registry.claim(
                    iface, BACKGROUND_RUN_ID, "monitor", label=BACKGROUND_LABEL)
                if not claimed:
                    return {"iface": "", "targets": list(self._targets), "active": False}
                self._iface = iface
            if (self._clock() - self._ts) >= BACKGROUND_STALE_S or not self._targets:
                result = self._sweep_fn(self._iface, seconds) or {}
                self._targets = list(result.get("targets", []))
                self._ts = self._clock()
            return {"iface": self._iface, "targets": list(self._targets), "active": True}

    def targets(self) -> List[dict]:
        with self._lock:
            return list(self._targets)

    def stop(self) -> None:
        """Release the dedicated adapter (on mode switch or shutdown)."""
        with self._lock:
            if self._iface:
                self._registry.release(self._iface, BACKGROUND_RUN_ID)
                self._iface = ""
