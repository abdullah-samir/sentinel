# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Root provisioning SERVICE (Phase P1) — the privileged half.

Runs as root (systemd ``sentinel-provisioning.service``). It owns the only things that
touch the network: the monitor loop (:class:`ProvisioningMonitor`) and the IPC handler
that the unprivileged portal calls. The portal forwards only validated
``{action, ssid, password}`` over the Unix socket; this service dispatches them.

Because the single radio drops the AP during a join/rescan (which would kill the
portal's HTTP connection), those actions are FIRE-AND-FORGET: the handler ACKs
immediately and does the work in a worker, coordinating with the monitor via
pause/resume so they never fight over the radio. The outcome is persisted for the
portal to read once the AP re-raises.

The IPC dispatch is unit-tested with a MockBackend + synchronous spawn + a fake join;
the real nmcli path runs only in the supervised live test.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from core import provisioning as prov
from core import provisioning_ipc as ipc
from core import provisioning_net as net
from core import provisioning_state as pstate
from core.provisioning_join import attempt_join
from core.provisioning_monitor import ProvisioningMonitor

log = logging.getLogger("sentinel.provisioning.service")


def _thread_spawn(fn: Callable, *args) -> None:
    def run():
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            log.error("provisioning worker failed: %s", e)
    threading.Thread(target=run, daemon=True).start()


class ProvisioningService:
    def __init__(self, config, *, backend=None, settings_fn=None, registry=None,
                 captive_dns_path: Optional[str] = net.CAPTIVE_DNS_PATH,
                 join_fn: Callable = attempt_join,
                 spawn_fn: Callable = _thread_spawn,
                 now_fn: Callable[[], float] = time.monotonic):
        self.config = config
        self.settings_fn = settings_fn or (lambda: prov.load_provisioning(config))
        self.backend = backend or net.NmcliBackend(self.settings_fn, config)
        self.monitor = ProvisioningMonitor(
            self.backend, config, settings_fn=self.settings_fn, registry=registry,
            now_fn=now_fn, captive_dns_path=captive_dns_path)
        self._captive = captive_dns_path
        self._join_fn = join_fn
        self._spawn = spawn_fn
        self._radio_lock = threading.RLock()
        self._stop = threading.Event()

    # ── IPC handler (req is ALREADY validated by provisioning_ipc.serve) ───────
    def handle(self, req: dict) -> dict:
        action = req.get("action")
        if action == "ping":
            return {"ok": True}
        if action == "status":
            return {"ok": True,
                    "phase": pstate.get_phase(self.config),
                    "result": pstate.get_last_result(self.config),
                    "networks": pstate.get_networks(self.config).get("networks", [])}
        if action == "join":
            self._spawn(self._do_join, req["ssid"], req.get("password", ""))
            return {"ok": True, "state": "attempting"}
        if action == "rescan":
            self._spawn(self._do_rescan)
            return {"ok": True, "state": "rescanning"}
        return {"ok": False, "error": "unhandled action"}

    # ── workers (coordinate with the monitor over the shared radio) ────────────
    def _do_join(self, ssid: str, password: str) -> dict:
        with self._radio_lock:
            self.monitor.pause()
            result = {}
            try:
                result = self._join_fn(self.backend, self.settings_fn(), ssid,
                                       password, self.config)
            finally:
                online = (result or {}).get("kind") == pstate.OK
                if online:
                    # Pi is online, AP down -> remove captive snippet + free the iface
                    if self._captive:
                        net.remove_captive_dns(self._captive)
                    self.monitor.set_ap_active(False)
                    self.monitor._release_iface()
                else:
                    # join re-raised the AP -> it's up again; keep captive present
                    if self._captive:
                        s = self.settings_fn()
                        net.write_captive_dns(self._captive, s.get("ap_ip", "10.42.0.1"),
                                              s.get("friendly_hostname", "sentinel.local"))
                    self.monitor.set_ap_active(True)
                self.monitor.resume()
            return result

    def _do_rescan(self) -> None:
        with self._radio_lock:
            self.monitor.pause()
            try:
                s = self.settings_fn()
                ifn = str(s.get("ap_ifname", "wlan0"))
                self.backend.ap_down()
                nets = self.backend.scan(ifn)
                pstate.set_networks(self.config, nets)
                self.backend.ap_up(s)
                self.monitor.set_ap_active(True)
                if self._captive:
                    net.write_captive_dns(self._captive, s.get("ap_ip", "10.42.0.1"),
                                          s.get("friendly_hostname", "sentinel.local"))
            finally:
                self.monitor.resume()

    # ── lifecycle (systemd entrypoint) ─────────────────────────────────────────
    def run(self, socket_path: str = ipc.DEFAULT_SOCKET_PATH,
            poll_interval: float = 5.0) -> None:
        mon_thread = threading.Thread(
            target=self.monitor.run, args=(self._stop,),
            kwargs={"poll_interval": poll_interval}, daemon=True)
        mon_thread.start()
        try:
            ipc.serve(socket_path, self.handle, stop_event=self._stop)
        finally:
            self._stop.set()
            mon_thread.join(timeout=10)

    def stop(self) -> None:
        self._stop.set()


def main(argv=None) -> int:
    """systemd ExecStart. Fail-safe: on ANY exit, the monitor's cleanup leaves the
    interface usable; here we also remove the captive DNS snippet."""
    import os
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    from core.config import Config
    from core.state import InterfaceRegistry
    config = Config.from_env()
    svc = ProvisioningService(config, registry=InterfaceRegistry(config))
    sock = os.environ.get("SENTINEL_PROV_SOCKET", ipc.DEFAULT_SOCKET_PATH)
    try:
        svc.run(socket_path=sock)
        return 0
    except KeyboardInterrupt:
        svc.stop()
        return 0
    finally:
        try:
            net.remove_captive_dns(net.CAPTIVE_DNS_PATH)
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main())
