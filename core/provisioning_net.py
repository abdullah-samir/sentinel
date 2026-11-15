# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Provisioning network layer (Phase P1).

Two parts:
  * PURE helpers — ``parse_wifi_scan``, ``build_ap_profile_args``,
    ``captive_dns_conf`` — unit-tested, no I/O.
  * ``NmcliBackend`` — the ONLY place that runs nmcli / writes NetworkManager config.
    It is exercised solely in the supervised live test, never in the suite and never
    during this build (it would drop the session). Every method is fail-safe: explicit
    nmcli arg lists (never shell=True), SSID/PSK passed as arguments, and no raising.

Discovery facts baked in as defaults: NM 1.52, onboard wlan0 is AP-capable and
2.4 GHz-only (band=bg), NM shared subnet default 10.42.0.0/24, no existing shared conn.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Optional

from core.provisioning_backend import JoinResult, NetworkBackend

log = logging.getLogger("sentinel.provisioning.net")

AP_CON_NAME = "sentinel-ap"     # our dedicated AP profile; we own it exclusively


# ── pure helpers ────────────────────────────────────────────────────────────────
def _split_terse(line: str) -> list:
    """Split an `nmcli -t` line on unescaped ':' and unescape each field."""
    fields, cur, i = [], [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    fields.append("".join(cur))
    return fields


def parse_wifi_scan(output: str) -> list:
    """Parse `nmcli -t -f SSID,SIGNAL,SECURITY,IN-USE dev wifi list` into
    ``[{ssid, signal, security, in_use}]``: drop empty/hidden SSIDs, de-dupe keeping
    the STRONGEST signal per SSID, sort strongest-first. Tolerant of short lines."""
    best: dict = {}
    for raw in (output or "").splitlines():
        if not raw.strip():
            continue
        f = _split_terse(raw)
        ssid = (f[0] if len(f) > 0 else "").strip()
        if not ssid:                                  # empty == hidden; skip in list
            continue
        try:
            signal = int(f[1]) if len(f) > 1 and f[1] != "" else 0
        except ValueError:
            signal = 0
        security = (f[2] if len(f) > 2 else "").strip()
        in_use = (f[3] == "*") if len(f) > 3 else False
        prev = best.get(ssid)
        if prev is None or signal > prev["signal"]:
            best[ssid] = {"ssid": ssid, "signal": signal,
                          "security": security or "--", "in_use": in_use}
        elif in_use:
            best[ssid]["in_use"] = True
    return sorted(best.values(), key=lambda n: n["signal"], reverse=True)


def build_ap_profile_args(settings: dict, con_name: str = AP_CON_NAME) -> dict:
    """The nmcli ARG LISTS to (re)create the dedicated AP profile. mode=ap, band=bg,
    ipv4.method=shared with the PINNED gateway, WPA2 PSK, hidden per settings,
    autoconnect=no. Returns ``{add, modify, up}`` arg lists. The PSK is an argument,
    never shell-interpolated. Disturbs no other connection."""
    ifn = str(settings.get("ap_ifname", "wlan0"))
    ssid = str(settings.get("ap_ssid", "Sentinel-Setup"))
    psk = str(settings.get("ap_password", ""))
    ap_ip = str(settings.get("ap_ip", "10.42.0.1"))
    prefix = int(settings.get("ap_prefix", 24))
    hidden = "yes" if settings.get("ap_hidden") else "no"
    add = ["connection", "add", "type", "wifi", "ifname", ifn,
           "con-name", con_name, "autoconnect", "no", "ssid", ssid]
    modify = ["connection", "modify", con_name,
              "802-11-wireless.mode", "ap",
              "802-11-wireless.band", "bg",
              "802-11-wireless.ssid", ssid,
              "802-11-wireless.hidden", hidden,
              "ipv4.method", "shared",
              "ipv4.addresses", f"{ap_ip}/{prefix}",
              "wifi-sec.key-mgmt", "wpa-psk",
              "wifi-sec.psk", psk,
              "connection.autoconnect", "no"]
    up = ["connection", "up", con_name]
    return {"con_name": con_name, "add": add, "modify": modify, "up": up}


def captive_dns_conf(ap_ip: str, friendly_hostname: str = "sentinel.local") -> str:
    """Contents of /etc/NetworkManager/dnsmasq-shared.d/sentinel-captive.conf: resolve
    ALL names from AP clients to the portal so the OS captive popup fires, and the
    friendly hostname to the portal too."""
    return (
        "# Sentinel captive portal — generated; removed when provisioning ends.\n"
        "# Every DNS query from an AP client resolves to the portal at the gateway.\n"
        f"address=/#/{ap_ip}\n"
        f"address=/{friendly_hostname}/{ap_ip}\n"
    )


CAPTIVE_DNS_PATH = "/etc/NetworkManager/dnsmasq-shared.d/sentinel-captive.conf"


def write_captive_dns(path, ap_ip: str, friendly_hostname: str = "sentinel.local") -> bool:
    """Write the captive dnsmasq snippet (idempotent). Returns True on success. The
    root service calls this with CAPTIVE_DNS_PATH when the AP rises; the suite calls
    it with a tmp path."""
    import os
    from pathlib import Path
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(captive_dns_conf(ap_ip, friendly_hostname), encoding="utf-8")
        os.replace(tmp, p)
        return True
    except OSError as e:
        log.warning("captive dns write failed (%s): %s", path, e)
        return False


def remove_captive_dns(path) -> bool:
    """Remove the captive dnsmasq snippet when provisioning ends. True if removed or
    already absent; never raises."""
    from pathlib import Path
    try:
        Path(path).unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError as e:
        log.warning("captive dns remove failed (%s): %s", path, e)
        return False


# ── real backend (LIVE ONLY — never run in the suite) ───────────────────────────
class NmcliBackend(NetworkBackend):
    """Runs nmcli for real. Constructed by the root provisioning service only."""

    def __init__(self, settings_fn, config=None):
        # settings_fn() -> current provisioning settings dict (fresh each use)
        self._settings_fn = settings_fn
        self._config = config

    def _nmcli(self, args: list, timeout: float = 20.0) -> subprocess.CompletedProcess:
        return subprocess.run(["nmcli"] + args, capture_output=True, text=True,
                             timeout=timeout, check=False)

    def nm_connectivity_full(self) -> bool:
        try:
            out = self._nmcli(["-t", "-f", "CONNECTIVITY", "general", "status"], timeout=8)
            return out.returncode == 0 and out.stdout.strip() == "full"
        except (OSError, subprocess.SubprocessError):
            return False

    def probe(self) -> bool:
        import urllib.request
        s = self._settings_fn()
        url = s.get("probe_url", "http://connectivitycheck.gstatic.com/generate_204")
        timeout = int(s.get("probe_timeout", 5))
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "sentinel-portal"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return 200 <= r.status < 400
        except Exception:  # noqa: BLE001
            return False

    def self_link_reason(self, ifname: str) -> str:
        # Normal path unchanged: whatever core.state.self_link_reason returns is passed
        # through (non-empty = refuse, "" = permit). Only the EXCEPTION path differs: a
        # crash here must FAIL CLOSED — if the one guard against self-lockout can't run,
        # refuse to raise the AP rather than assume the interface is safe.
        try:
            from core.state import self_link_reason
            return self_link_reason(ifname) or ""
        except Exception as e:  # noqa: BLE001
            log.error("self-link check errored for %s: %s — refusing (fail-closed)",
                      ifname, e)
            return f"self-link check errored for {ifname} — refusing (fail-closed)"

    def scan(self, ifname: str) -> list:
        try:
            self._nmcli(["dev", "wifi", "rescan", "ifname", ifname], timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            out = self._nmcli(["-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE",
                               "dev", "wifi", "list", "ifname", ifname], timeout=15)
            return parse_wifi_scan(out.stdout if out.returncode == 0 else "")
        except (OSError, subprocess.SubprocessError):
            return []

    def ap_up(self, settings: dict) -> bool:
        args = build_ap_profile_args(settings)
        try:
            if self.profile_exists(args["con_name"]):
                self._nmcli(["connection", "delete", args["con_name"]], timeout=10)
            if self._nmcli(args["add"], timeout=15).returncode != 0:
                return False
            if self._nmcli(args["modify"], timeout=15).returncode != 0:
                return False
            return self._nmcli(args["up"], timeout=25).returncode == 0
        except (OSError, subprocess.SubprocessError) as e:
            log.error("ap_up failed: %s", e)
            return False

    def ap_down(self) -> bool:
        try:
            self._nmcli(["connection", "down", AP_CON_NAME], timeout=15)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def profile_exists(self, name: str) -> bool:
        try:
            out = self._nmcli(["-t", "-f", "NAME", "connection", "show"], timeout=10)
            if out.returncode != 0:
                return False
            return name in [_split_terse(ln)[0] for ln in out.stdout.splitlines() if ln]
        except (OSError, subprocess.SubprocessError):
            return False

    def join(self, ssid: str, password: str, ifname: str, timeout: int) -> JoinResult:
        args = ["--wait", str(timeout), "dev", "wifi", "connect", ssid,
                "ifname", ifname]
        if password:
            args += ["password", password]
        try:
            out = self._nmcli(args, timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            return JoinResult(rc=124, reason="join timed out", profile=ssid)
        except (OSError, subprocess.SubprocessError) as e:
            return JoinResult(rc=1, reason=str(e), profile=ssid)
        if out.returncode == 0:
            return JoinResult(rc=0, profile=ssid)
        reason = (out.stderr or out.stdout or "association failed").strip().splitlines()
        return JoinResult(rc=out.returncode,
                          reason=reason[-1] if reason else "association failed",
                          profile=ssid)

    def connection_down(self, name: str) -> bool:
        try:
            self._nmcli(["connection", "down", name], timeout=15)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def delete_profile(self, name: str) -> bool:
        try:
            return self._nmcli(["connection", "delete", name], timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
