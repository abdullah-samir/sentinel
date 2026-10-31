"""Interface reservation registry + the central interface-safety check.

This lives in **core** on purpose: both a plugin (``red.wifi_scan``) and the
dashboard need it, and plugins must never import ``dashboard`` (that would
invert the layering). Keeping it here lets wifi_scan claim/release an interface
and lets the dashboard render a read-only view of the same state.

What it guarantees
------------------
* **One monitor-mode op per interface.** A monitor-mode Wi-Fi operation
  *claims* an interface before it touches it and *releases* it on finish AND
  on error. A second claimant of an interface already held by a still-alive
  run is refused with a clear "busy" reason; the holder re-claiming its own
  interface is idempotent (never "busy").
* **Survives a restart without stomping live work.** Reservations are
  persisted to ``data/state/interfaces.json``. On dashboard start
  :meth:`InterfaceRegistry.reset_dead` releases only the reservations whose
  owning process is no longer alive — a reservation held by a genuinely
  running CLI/scheduler process (a different, live PID) is left intact. This
  is deliberately keyed off run/process liveness, never a blanket wipe.
* **One reused safety gate.** :func:`interface_safety_check` is the single
  function that governs monitor-mode operations: it refuses an interface that
  carries the Pi's default route or the active SSH connection (the same
  self-lockout guard wifi_scan already used) and refuses a busy interface.
  It is NOT applied to ordinary capture on the default interface.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.schema import utcnow_iso

log = logging.getLogger("sentinel.state")

VALID_MODES = ("managed", "monitor")


# --------------------------------------------------------------------------- #
# process liveness
# --------------------------------------------------------------------------- #
def pid_alive(pid: Optional[int]) -> bool:
    """True if `pid` names a live process. Signal 0 probes without delivering
    a signal; EPERM means it exists but we don't own it (still alive)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------- #
# network-safety primitives (the SINGLE source; wifi_scan aliases these so its
# self-lockout guard and this central check share one implementation)
# --------------------------------------------------------------------------- #
def _ip(args: List[str]) -> str:
    """Run `ip <args>` and return combined output; "" on any failure. Never
    raises (detection must never crash a run or a page render)."""
    try:
        p = subprocess.run(["ip", *args], capture_output=True, text=True,
                           timeout=5, check=False)
        return (p.stdout or "") + (p.stderr or "")
    except Exception:  # noqa: BLE001
        return ""


def default_route_iface() -> Optional[str]:
    """Interface carrying the default route (the Pi's uplink), or None."""
    for line in _ip(["route"]).splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    return None


def ssh_iface() -> str:
    """Interface owning the local IP of the active SSH connection, or "" when
    not under SSH / not determinable — so a caller can refuse to tear it down."""
    conn = os.environ.get("SSH_CONNECTION", "")
    parts = conn.split()
    if len(parts) < 3:
        return ""
    server_ip = parts[2]
    for line in _ip(["-o", "addr", "show"]).splitlines():
        toks = line.split()
        # "<idx>: <iface> <family> <ip>/<prefix> ..."
        if len(toks) >= 4 and toks[3].split("/")[0] == server_ip:
            return toks[1]
    return ""


def self_link_reason(iface: str,
                     route_fn: Optional[Callable[[], Optional[str]]] = None,
                     ssh_fn: Optional[Callable[[], str]] = None) -> str:
    """Non-empty reason to REFUSE `iface` because using it would drop the Pi's
    own connectivity (it carries the default route or the active SSH session).

    `route_fn`/`ssh_fn` let a caller inject its own (patchable) detectors so one
    implementation serves both this central check and wifi_scan's guard."""
    route = route_fn or default_route_iface
    ssh = ssh_fn or ssh_iface
    if iface and iface == route():
        return (f"{iface} carries the default route (the Pi's uplink); refusing "
                "to avoid self-lockout")
    ssh_if = ssh()
    if ssh_if and iface == ssh_if:
        return (f"{iface} carries the active SSH connection; refusing to avoid "
                "self-lockout")
    return ""


# --------------------------------------------------------------------------- #
# the reservation registry
# --------------------------------------------------------------------------- #
class InterfaceRegistry:
    """Thread-safe, file-backed per-interface reservations.

    A reservation is ``{iface: {"mode", "run_id", "pid", "ts"}}``. All mutating
    ops take a single re-entrant lock and persist atomically, so a crashed
    process leaves a readable file for the next start to reconcile.
    """

    def __init__(self, path, lock=None) -> None:
        self._path = Path(path)
        self._lock = lock or threading.RLock()
        self._res: Dict[str, dict] = {}
        self._load()

    @property
    def lock(self):
        return self._lock

    # --- persistence ------------------------------------------------------
    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            self._res = {k: v for k, v in data.items() if isinstance(v, dict)}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(self._path.name + ".tmp")
            tmp.write_text(json.dumps(self._res, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as e:  # a save failure must never crash a run
            log.warning("interface registry save failed (%s): %s", self._path, e)

    # --- queries ----------------------------------------------------------
    def _busy(self, iface: str, run_id: Optional[str]) -> str:
        r = self._res.get(iface)
        if not r:
            return ""
        if run_id is not None and r.get("run_id") == run_id:
            return ""                                   # already ours
        if not pid_alive(r.get("pid")):
            return ""                                   # dead holder -> not busy
        who = r.get("label") or f"run {r.get('run_id', '?')}"
        return f"{iface} is busy — in use by {who}"

    def busy_reason(self, iface: str, run_id: Optional[str] = None) -> str:
        """Non-empty "busy" reason iff `iface` is held by a *different, alive*
        run. "" if free, held by a dead run, or held by `run_id` itself."""
        with self._lock:
            return self._busy(iface, run_id)

    def reservations(self) -> Dict[str, dict]:
        """Snapshot of current reservations, each annotated with `alive`. For
        read-only display — never mutates."""
        with self._lock:
            return {iface: {**r, "alive": pid_alive(r.get("pid"))}
                    for iface, r in self._res.items()}

    # --- mutations --------------------------------------------------------
    def claim(self, iface: str, run_id: str, mode: str = "monitor",
              label: str = "") -> Tuple[bool, str]:
        """Atomically reserve `iface` for `run_id`. Returns (True, "") on
        success; (False, reason) if a different, still-alive run holds it.
        Re-claiming an interface this run already holds succeeds (idempotent).

        `label` is a human-readable name for the holder (e.g. the workflow) so
        the UI can attribute "busy" state to a task, never a raw run_id."""
        if mode not in VALID_MODES:
            mode = "monitor"
        with self._lock:
            reason = self._busy(iface, run_id)
            if reason:
                return (False, reason)
            self._res[iface] = {"mode": mode, "run_id": run_id, "label": label,
                                "pid": os.getpid(), "ts": utcnow_iso()}
            self._save()
            return (True, "")

    def holder_label(self, iface: str) -> str:
        """Friendly name of an interface's *alive* holder, or "" if free/dead.
        Resolves the stored label, falling back to 'run <run_id>'."""
        with self._lock:
            r = self._res.get(iface)
            if not r or not pid_alive(r.get("pid")):
                return ""
            return r.get("label") or f"run {r.get('run_id', '?')}"

    def release(self, iface: str, run_id: Optional[str] = None) -> bool:
        """Free `iface`. If `run_id` is given, only release when this run holds
        it (never free another run's reservation). With `run_id=None` it is a
        forced release (used by the operator's "force-release" control). Returns
        True if a reservation was removed."""
        with self._lock:
            r = self._res.get(iface)
            if not r:
                return False
            if run_id is not None and r.get("run_id") != run_id:
                return False
            del self._res[iface]
            self._save()
            return True

    def release_run(self, run_id: str) -> List[str]:
        """Release every interface held by `run_id` (safety net on run finish /
        stop, so a crashed or stopped run never leaves a stuck reservation).
        Returns the freed interfaces."""
        freed: List[str] = []
        with self._lock:
            for iface in list(self._res):
                if self._res[iface].get("run_id") == run_id:
                    del self._res[iface]
                    freed.append(iface)
            if freed:
                self._save()
        return freed

    def reset_dead(self, is_alive: Optional[Callable[[dict], bool]] = None) -> List[str]:
        """Startup reconciliation: release reservations whose owning run/process
        is no longer alive, and KEEP those still alive (a genuinely-running
        CLI/scheduler still using the adapter). Returns the freed interfaces.

        `is_alive` defaults to a PID-liveness check; it is injectable for tests.
        """
        alive = is_alive or (lambda r: pid_alive(r.get("pid")))
        freed: List[str] = []
        with self._lock:
            for iface in list(self._res):
                if not alive(self._res[iface]):
                    del self._res[iface]
                    freed.append(iface)
            if freed:
                self._save()
        return freed


# --------------------------------------------------------------------------- #
# one registry instance per state-file path per process
# --------------------------------------------------------------------------- #
_INSTANCES: Dict[str, InterfaceRegistry] = {}
_INSTANCES_LOCK = threading.Lock()


def state_path(config=None) -> Path:
    if config is None:
        from core.config import Config
        config = Config.from_env()
    return Path(config.root) / "data" / "state" / "interfaces.json"


def get_interface_registry(config=None, lock=None) -> InterfaceRegistry:
    """The process-wide registry for `config`'s root (one per state-file path,
    so the dashboard and an in-process run share the same object + lock). A
    separate process coordinates through the persisted file."""
    path = state_path(config)
    key = str(path)
    with _INSTANCES_LOCK:
        inst = _INSTANCES.get(key)
        if inst is None:
            inst = InterfaceRegistry(path, lock=lock)
            _INSTANCES[key] = inst
        return inst


# --------------------------------------------------------------------------- #
# the central safety check (one reused function)
# --------------------------------------------------------------------------- #
def interface_safety_check(iface: str, run_id: Optional[str] = None,
                           reg: Optional[InterfaceRegistry] = None,
                           route_fn: Optional[Callable[[], Optional[str]]] = None,
                           ssh_fn: Optional[Callable[[], str]] = None,
                           config=None) -> Tuple[bool, str]:
    """Governs MONITOR-MODE Wi-Fi operations only (never ordinary capture on the
    default interface). Refuses an interface that carries the default route or
    the active SSH connection, and refuses a busy interface. Does NOT claim —
    a caller that intends to use the interface then calls ``reg.claim`` to
    atomically reserve it. Returns (ok, reason)."""
    reason = self_link_reason(iface, route_fn=route_fn, ssh_fn=ssh_fn)
    if reason:
        return (False, reason)
    reg = reg or get_interface_registry(config)
    busy = reg.busy_reason(iface, run_id)
    if busy:
        return (False, busy)
    return (True, "")
