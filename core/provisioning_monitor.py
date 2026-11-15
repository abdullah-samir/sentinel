# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Provisioning monitor (Phase P1) — the long-running, root decision loop.

Rules (ABSOLUTE SAFETY CONTRACT):
  * While ``provisioning_enabled`` is FALSE → strict NO-OP. The loop takes NO network
    action and does not even probe; it only reads the setting. (The one exception is a
    transition: if an AP we raised is still up when the switch goes off, tear it down.)
  * While enabled → raise the AP only after offline PERSISTS past ``grace_seconds``;
    tear it down only after internet is confirmed STABLE for a short window — so
    flapping connectivity cannot flap the AP (hysteresis).
  * Never raise the AP on an interface that carries the default route or SSH
    (``self_link_reason``), and reserve the AP interface while up.

Pure-ish and testable: all time comes from ``now_fn`` and all network effects go
through a :class:`NetworkBackend`, so ``step()`` is driven deterministically with a
fake clock and a ``MockBackend`` — no real networking in the suite.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from core import provisioning as prov
from core import provisioning_state as pstate
from core.provisioning_backend import NetworkBackend

log = logging.getLogger("sentinel.provisioning.monitor")

RUN_ID = "provisioning"
STABLE_ONLINE_SECONDS = 8.0        # internet must hold this long before AP teardown


class ProvisioningMonitor:
    def __init__(self, backend: NetworkBackend, config, *,
                 settings_fn: Optional[Callable[[], dict]] = None,
                 now_fn: Callable[[], float] = time.monotonic,
                 registry=None,
                 stable_online_seconds: float = STABLE_ONLINE_SECONDS,
                 captive_dns_path: Optional[str] = None):
        self.backend = backend
        self.config = config
        self._settings_fn = settings_fn or (lambda: prov.load_provisioning(config))
        self._now = now_fn
        self._reg = registry
        self._stable = stable_online_seconds
        self._captive = captive_dns_path
        # internal state
        self.ap_active = False
        self._paused = False
        self._offline_since: Optional[float] = None
        self._online_since: Optional[float] = None
        self._reserved_iface: Optional[str] = None
        self._lock = threading.RLock()

    # ── coordination with join/rescan (same process, shared radio) ─────────────
    def pause(self) -> None:
        """Stop the loop from acting on the radio while a join/rescan runs."""
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        with self._lock:
            self._paused = False
            # a join/rescan just changed reality; re-arm the hysteresis timers
            self._offline_since = self._online_since = None

    def set_ap_active(self, active: bool, reserved_iface: Optional[str] = None) -> None:
        """Let a join/rescan report the post-attempt AP reality back to the monitor."""
        with self._lock:
            self.ap_active = bool(active)
            if reserved_iface is not None:
                self._reserved_iface = reserved_iface

    # ── one decision iteration ─────────────────────────────────────────────────
    def step(self) -> dict:
        """Run one iteration; returns a small snapshot for logging/tests. Never
        raises."""
        with self._lock:
            try:
                return self._step_locked()
            except Exception as e:  # noqa: BLE001 — a monitor must never die
                log.error("monitor step error: %s", e)
                return {"enabled": None, "error": str(e), "ap": self.ap_active}

    def _step_locked(self) -> dict:
        if self._paused:
            return {"enabled": None, "action": "paused", "ap": self.ap_active}
        settings = self._settings_fn()
        enabled = bool(settings.get("provisioning_enabled"))

        if not enabled:
            action = "noop"
            if self.ap_active:                 # transition enabled->disabled: tear down
                self._teardown_ap(settings)
                action = "disabled_teardown"
            # strict no-op: no probe, no network reads at all
            self._offline_since = self._online_since = None
            return {"enabled": False, "online": None, "ap": self.ap_active, "action": action}

        now = self._now()
        online = self.backend.is_online()
        action = "idle"

        if online:
            self._offline_since = None
            if self._online_since is None:
                self._online_since = now
            if self.ap_active and (now - self._online_since) >= self._stable:
                self._teardown_ap(settings)
                pstate.set_phase(self.config, "online", "internet stable; AP down")
                action = "online_teardown"
            elif not self.ap_active:
                action = "online_idle"
            else:
                action = "online_settling"      # waiting out the stable window
        else:
            self._online_since = None
            if self._offline_since is None:
                self._offline_since = now
            waited = now - self._offline_since
            if not self.ap_active and waited >= int(settings.get("grace_seconds", 45)):
                action = self._raise_ap(settings)
            elif self.ap_active:
                action = "offline_ap_up"
            else:
                action = "offline_grace"        # counting down grace before AP
        return {"enabled": True, "online": online, "ap": self.ap_active,
                "action": action, "offline_for": (now - self._offline_since)
                if self._offline_since else 0}

    # ── AP raise / teardown ────────────────────────────────────────────────────
    def _raise_ap(self, settings: dict) -> str:
        ifn = str(settings.get("ap_ifname", "wlan0"))
        reason = self.backend.self_link_reason(ifn)
        if reason:                              # never hijack the uplink / SSH iface
            log.warning("refusing to raise AP on %s: %s", ifn, reason)
            return "refused_self_link"
        if self._reg is not None:
            ok, why = self._reg.claim(ifn, RUN_ID, mode="ap", label="provisioning AP")
            if not ok:
                log.warning("AP interface %s busy: %s", ifn, why)
                return "iface_busy"
            self._reserved_iface = ifn
        # scan + cache BEFORE the AP rises (unconnected radio can scan)
        try:
            nets = self.backend.scan(ifn)
            pstate.set_networks(self.config, nets)
        except Exception as e:  # noqa: BLE001
            log.debug("pre-AP scan failed: %s", e)
        if self.backend.ap_up(settings):
            self.ap_active = True
            self._write_captive(settings)
            pstate.set_phase(self.config, "ap_up", f"offline; AP on {ifn}")
            log.info("provisioning AP raised on %s", ifn)
            return "ap_raised"
        # ap_up failed -> release the reservation, stay inert (monitor retries)
        self._release_iface()
        log.error("ap_up failed on %s", ifn)
        return "ap_raise_failed"

    def _teardown_ap(self, settings: dict) -> None:
        try:
            self.backend.ap_down()
        finally:
            self.ap_active = False
            self._remove_captive()
            self._release_iface()
            pstate.set_phase(self.config, "idle", "AP down")
            log.info("provisioning AP torn down")

    def _write_captive(self, settings: dict) -> None:
        if not self._captive:
            return
        try:
            from core.provisioning_net import write_captive_dns
            write_captive_dns(self._captive, str(settings.get("ap_ip", "10.42.0.1")),
                              str(settings.get("friendly_hostname", "sentinel.local")))
        except Exception as e:  # noqa: BLE001
            log.debug("captive dns write skipped: %s", e)

    def _remove_captive(self) -> None:
        if not self._captive:
            return
        try:
            from core.provisioning_net import remove_captive_dns
            remove_captive_dns(self._captive)
        except Exception as e:  # noqa: BLE001
            log.debug("captive dns remove skipped: %s", e)

    def _release_iface(self) -> None:
        if self._reg is not None and self._reserved_iface is not None:
            try:
                self._reg.release(self._reserved_iface, RUN_ID)
            except Exception:  # noqa: BLE001
                pass
        self._reserved_iface = None

    # ── blocking loop (used by the systemd service) ────────────────────────────
    def run(self, stop_event: threading.Event, poll_interval: float = 5.0) -> None:
        log.info("provisioning monitor loop started")
        try:
            while not stop_event.is_set():
                self.step()
                stop_event.wait(poll_interval)
        finally:
            # cleanup on ANY exit: leave the interface usable
            try:
                if self.ap_active:
                    self._teardown_ap(self._settings_fn())
                else:
                    self._release_iface()
            except Exception as e:  # noqa: BLE001
                log.error("monitor cleanup error: %s", e)
            log.info("provisioning monitor loop stopped")
