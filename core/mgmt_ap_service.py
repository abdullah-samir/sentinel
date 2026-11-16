# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Root MANAGEMENT-AP supervisor (Phase P2) — the privileged half.

Runs as root (systemd ``sentinel-mgmt-ap.service``). It is the ONLY thing that
touches the network for this feature: a tiny decision loop that, while enabled,
keeps a WPA2 hotspot up on the configured **dedicated USB NIC** so the dashboard is
reachable from a phone at any time — online or offline. Unlike P1's provisioning
monitor it is NOT offline-gated: the hotspot is held up regardless of internet.

ABSOLUTE SAFETY CONTRACT (why this is zero-risk):
  * While ``mgmt_ap_enabled`` is FALSE → strict NO-OP: no network action, and NO
    interface reservation is held. The one exception is the enabled→disabled
    transition: an AP we raised is torn down and its reservation released.
  * The AP rises ONLY on the configured NIC, and only after the same guarantees as
    :func:`core.state.interface_safety_check`: it is refused if that NIC is the live
    default-route / SSH interface (self-lockout) or is busy (held by another run).
    There is NEVER a fallback to ``wlan0`` or any other interface — if the NIC is
    absent, unsafe, or reserved, the AP simply does not come up.
  * The NIC is reserved in ``mode="ap"`` for the AP's lifetime and released on
    teardown / process exit, so the interfaces panel attributes it correctly and no
    scan can fight it.

Pure-ish and testable: all network effects go through a :class:`NetworkBackend`, so
``step()`` is driven deterministically with a ``MockBackend`` + a fake registry — no
real networking in the suite. The real nmcli path (:class:`MgmtApBackend`) runs only
on the Pi, never in the test suite or this build.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional

from core import mgmt_ap as cfgmod
from core import provisioning_net as net
from core.mgmt_ap import MGMT_AP_CON_NAME, MGMT_DNS_PATH, profile_settings

log = logging.getLogger("sentinel.mgmt_ap.service")

RUN_ID = "mgmt-ap"
AP_LABEL = "management AP"


# ── single-host DNS snippet I/O (live only; path is None in tests) ──────────────
def write_mgmt_dns(path, ap_ip: str, hostname: str = "sentinel.local") -> bool:
    """Write the single friendly-hostname dnsmasq snippet (idempotent). True on
    success. NOT a captive catch-all — normal DNS otherwise."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(cfgmod.mgmt_dns_conf(ap_ip, hostname), encoding="utf-8")
        os.replace(tmp, p)
        return True
    except OSError as e:
        log.warning("mgmt dns write failed (%s): %s", path, e)
        return False


def remove_mgmt_dns(path) -> bool:
    """Remove the snippet when the AP goes down. True if removed or already absent."""
    try:
        Path(path).unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError as e:
        log.warning("mgmt dns remove failed (%s): %s", path, e)
        return False


# ── real backend (LIVE ONLY — never run in the suite) ───────────────────────────
class MgmtApBackend(net.NmcliBackend):
    """Reuses P1's :class:`NmcliBackend` nmcli plumbing but targets the DISTINCT
    management con-name, so the two AP profiles never collide. Only ``ap_up`` /
    ``ap_down`` / ``ap_is_up`` differ from the base (which is hard-wired to P1's
    ``sentinel-ap``); everything else (``_nmcli``, ``self_link_reason`` fail-closed,
    ``profile_exists``) is inherited unchanged."""

    CON_NAME = MGMT_AP_CON_NAME

    def ap_up(self, settings: dict) -> bool:
        args = net.build_ap_profile_args(settings, con_name=self.CON_NAME)
        try:
            if self.profile_exists(args["con_name"]):
                self._nmcli(["connection", "delete", args["con_name"]], timeout=10)
            if self._nmcli(args["add"], timeout=15).returncode != 0:
                return False
            if self._nmcli(args["modify"], timeout=15).returncode != 0:
                return False
            return self._nmcli(args["up"], timeout=25).returncode == 0
        except (OSError, subprocess.SubprocessError) as e:
            log.error("mgmt ap_up failed: %s", e)
            return False

    def ap_down(self) -> bool:
        try:
            self._nmcli(["connection", "down", self.CON_NAME], timeout=15)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def ap_is_up(self, con_name: str = "") -> bool:
        name = con_name or self.CON_NAME
        try:
            out = self._nmcli(["-t", "-f", "NAME", "connection", "show", "--active"],
                              timeout=8)
            if out.returncode != 0:
                return False
            return name in [net._split_terse(ln)[0]
                            for ln in out.stdout.splitlines() if ln]
        except (OSError, subprocess.SubprocessError):
            return False


def _present_interfaces() -> set:
    """Interfaces currently present per /sys/class/net; empty set on failure."""
    try:
        return {d.name for d in Path("/sys/class/net").iterdir()}
    except OSError:
        return set()


# ── the supervisor ──────────────────────────────────────────────────────────────
class MgmtApSupervisor:
    def __init__(self, backend, config, *,
                 settings_fn: Optional[Callable[[], dict]] = None,
                 registry=None,
                 present_fn: Callable[[], set] = _present_interfaces,
                 dns_path: Optional[str] = None,
                 con_name: str = MGMT_AP_CON_NAME):
        self.backend = backend
        self.config = config
        self._settings_fn = settings_fn or (lambda: cfgmod.load_mgmt_ap(config))
        self._reg = registry
        self._present = present_fn
        self._dns = dns_path
        self.con_name = con_name
        # internal state
        self.ap_active = False
        self._reserved_iface: Optional[str] = None
        self._lock = threading.RLock()

    # ── one decision iteration ─────────────────────────────────────────────────
    def step(self) -> dict:
        with self._lock:
            try:
                return self._step_locked()
            except Exception as e:  # noqa: BLE001 — a supervisor must never die
                log.error("mgmt-ap step error: %s", e)
                return {"enabled": None, "error": str(e), "ap": self.ap_active}

    def _step_locked(self) -> dict:
        settings = self._settings_fn()
        enabled = bool(settings.get("mgmt_ap_enabled"))

        if not enabled:
            action = "noop"
            if self.ap_active:                 # transition enabled->disabled: tear down
                self._teardown_ap()
                action = "disabled_teardown"
            # strict no-op: hold no reservation, take no network action
            return {"enabled": False, "ap": self.ap_active, "action": action}

        ifn = str(settings.get("mgmt_ap_ifname", "") or "").strip()

        # live NIC change while up: drop the old AP so we re-raise on the new one
        if self.ap_active and self._reserved_iface and ifn != self._reserved_iface:
            self._teardown_ap()

        if not self.ap_active:
            action = self._raise_ap(settings)
        elif not self.backend.ap_is_up(self.con_name):
            # the AP dropped underneath us — re-raise on the same NIC (idempotent claim)
            action = self._raise_ap(settings)
            if action == "ap_raised":
                action = "re_raised"
        else:
            action = "holding"
        return {"enabled": True, "ap": self.ap_active, "action": action, "iface": ifn}

    # ── AP raise / teardown ────────────────────────────────────────────────────
    def _raise_ap(self, settings: dict) -> str:
        """Gate (same guarantees as interface_safety_check) then raise. NO fallback:
        any refusal leaves the AP down and nothing reserved."""
        ifn = str(settings.get("mgmt_ap_ifname", "") or "").strip()
        if not ifn:
            return "no_iface"
        if ifn == "wlan0":                      # belt-and-suspenders; never the onboard NIC
            log.warning("refusing mgmt AP on wlan0 (onboard/uplink)")
            return "refused_wlan0"
        if ifn not in self._present():
            log.warning("mgmt AP interface %s is absent; not raising", ifn)
            return "iface_absent"
        # self-lockout guard (fail-closed in the backend): never the uplink / SSH iface
        reason = self.backend.self_link_reason(ifn)
        if reason:
            log.warning("refusing to raise mgmt AP on %s: %s", ifn, reason)
            return "refused_self_link"
        # busy check + atomic reservation in "ap" mode (idempotent if we already hold it)
        if self._reg is not None:
            ok, why = self._reg.claim(ifn, RUN_ID, mode="ap", label=AP_LABEL)
            if not ok:
                log.warning("mgmt AP interface %s busy: %s", ifn, why)
                return "iface_busy"
            self._reserved_iface = ifn
        if self.backend.ap_up(profile_settings(settings)):
            self.ap_active = True
            self._write_dns(settings)
            log.info("management AP raised on %s (ssid=%s share_internet=%s)",
                     ifn, settings.get("mgmt_ap_ssid"), settings.get("share_internet"))
            return "ap_raised"
        # ap_up failed -> release the reservation, stay inert (loop retries next tick)
        self._release_iface()
        log.error("mgmt ap_up failed on %s", ifn)
        return "ap_raise_failed"

    def _teardown_ap(self) -> None:
        try:
            self.backend.ap_down()
        finally:
            self.ap_active = False
            self._remove_dns()
            self._release_iface()
            log.info("management AP torn down")

    def _write_dns(self, settings: dict) -> None:
        if not self._dns:
            return
        try:
            write_mgmt_dns(self._dns, str(settings.get("mgmt_ap_ip", "10.42.1.1")),
                           str(settings.get("mgmt_ap_hostname", "sentinel.local")))
        except Exception as e:  # noqa: BLE001
            log.debug("mgmt dns write skipped: %s", e)

    def _remove_dns(self) -> None:
        if not self._dns:
            return
        try:
            remove_mgmt_dns(self._dns)
        except Exception as e:  # noqa: BLE001
            log.debug("mgmt dns remove skipped: %s", e)

    def _release_iface(self) -> None:
        if self._reg is not None and self._reserved_iface is not None:
            try:
                self._reg.release(self._reserved_iface, RUN_ID)
            except Exception:  # noqa: BLE001
                pass
        self._reserved_iface = None

    # ── blocking loop (used by the systemd service) ────────────────────────────
    def run(self, stop_event: threading.Event, poll_interval: float = 5.0) -> None:
        log.info("management-AP supervisor loop started")
        try:
            while not stop_event.is_set():
                self.step()
                stop_event.wait(poll_interval)
        finally:
            # cleanup on ANY exit: leave the interface usable
            try:
                if self.ap_active:
                    self._teardown_ap()
                else:
                    self._release_iface()
            except Exception as e:  # noqa: BLE001
                log.error("mgmt-ap cleanup error: %s", e)
            log.info("management-AP supervisor loop stopped")


# ── systemd entrypoint ──────────────────────────────────────────────────────────
def main(argv=None) -> int:
    """systemd ExecStart. Fail-safe: ships disabled (strict no-op until the master
    switch is turned on in the dashboard), and on ANY exit the loop's cleanup leaves
    the interface usable and removes the DNS snippet."""
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    from core.config import Config
    from core.state import get_interface_registry
    config = Config.from_env()
    backend = MgmtApBackend(lambda: cfgmod.load_mgmt_ap(config), config)
    sup = MgmtApSupervisor(backend, config,
                           registry=get_interface_registry(config),
                           dns_path=MGMT_DNS_PATH)
    stop = threading.Event()
    try:
        sup.run(stop)
        return 0
    except KeyboardInterrupt:
        stop.set()
        return 0
    finally:
        try:
            remove_mgmt_dns(MGMT_DNS_PATH)
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main())
