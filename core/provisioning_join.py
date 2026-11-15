# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Join orchestration (Phase P1) — single-radio-safe, reversible, AP-fallback.

Runs inside the root service when the portal forwards a validated join. The one radio
can't be an AP and a client at once, so the flow is strictly:

    AP DOWN → nmcli connect → one of three outcomes → (success: stay / else: re-raise AP)

Outcomes (all PERSISTED for the portal to show once the AP is back):
  * wrong credentials (nmcli non-zero): delete ONLY the just-created profile (keep a
    pre-existing one), keep the SSID to pre-fill, re-raise the AP.
  * joined but no internet (exit 0, probe fails): bring the client DOWN but KEEP its
    profile (NM may auto-connect later), re-raise the AP.
  * success (exit 0, probe passes): keep the profile, AP stays down, Pi is online.

Invariants enforced here: never the AP and a client up together; never delete a
pre-existing profile; always end online OR with the AP back up. Never raises.
"""
from __future__ import annotations

import logging

from core import provisioning_state as pstate
from core.provisioning_backend import NetworkBackend

log = logging.getLogger("sentinel.provisioning.join")


def attempt_join(backend: NetworkBackend, settings: dict, ssid: str, password: str,
                 config=None) -> dict:
    """Execute the join state machine. Returns the persisted result dict
    (``{kind, ssid, message, ts}``). Fail-safe: on any error the AP is re-raised."""
    ifn = str(settings.get("ap_ifname", "wlan0"))
    timeout = int(settings.get("join_timeout", 30))
    # Did a profile for this SSID already exist? If so we must NEVER delete it.
    try:
        pre_existing = backend.profile_exists(ssid)
    except Exception:  # noqa: BLE001
        pre_existing = True                    # safest assumption: don't delete

    pstate.set_phase(config, "attempting", ssid)
    try:
        backend.ap_down()                      # single radio: AP must be down to attempt
        res = backend.join(ssid, password, ifn, timeout)

        if res.rc != 0:
            # WRONG CREDENTIALS / association failed / SSID gone / timeout
            if not pre_existing:
                backend.delete_profile(res.profile or ssid)   # only the just-created one
            result = pstate.set_last_result(
                config, pstate.WRONG_CRED, ssid,
                f"couldn't join {ssid} — {res.reason or 'authentication/association failed'}")
            _reraise_ap(backend, settings, config)
            return result

        # associated — is there REAL internet?
        if backend.probe():
            # SUCCESS — keep the profile (auto-connects next boot); AP stays DOWN.
            pstate.set_phase(config, "online", ssid)
            return pstate.set_last_result(
                config, pstate.OK, ssid, f"connected to {ssid} — online")

        # JOINED BUT NO INTERNET — drop the client (KEEP its profile), re-raise AP.
        backend.connection_down(ssid)
        result = pstate.set_last_result(
            config, pstate.NO_INTERNET, ssid,
            f"connected to {ssid} but no internet — try another network")
        _reraise_ap(backend, settings, config)
        return result

    except Exception as e:  # noqa: BLE001 — never crash the service on a join
        log.error("join state machine error for %r: %s", ssid, e)
        result = pstate.set_last_result(
            config, pstate.ERROR, ssid, f"join failed unexpectedly — {e}")
        _reraise_ap(backend, settings, config)
        return result


def _reraise_ap(backend: NetworkBackend, settings: dict, config) -> None:
    """Bring the AP back so the device is never left with neither internet nor AP."""
    try:
        if backend.ap_up(settings):
            pstate.set_phase(config, "ap_up", "re-raised after attempt")
        else:
            log.error("FAILSAFE: AP re-raise failed; monitor will retry")
    except Exception as e:  # noqa: BLE001
        log.error("FAILSAFE: AP re-raise raised: %s", e)
