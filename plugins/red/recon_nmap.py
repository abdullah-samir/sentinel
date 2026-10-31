# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""red.recon_nmap — Nmap recon (Phase 1).

Real host discovery + port / service (+ OS, when privileged) scan of the run
target via python-nmap (explicit arg list, never shell=True).

Scan profile (fast vs full):
  * fast  — top ~100 ports, no ``-sV`` (service NAME only, from nmap's port
            table), no ``-O``. The default for /24-or-larger targets, where a
            full version scan is too slow on the Pi.
  * full  — top-1000 ports + ``-sV`` service/version (and ``-O`` when
            privileged). The default for a single host / small range.
Mode precedence: CLI flag (``--fast``/``--full``) overrides config
(``nmap_fast``), which overrides the target-size auto-default.

Privilege: ``-sS`` (SYN) + ``-O`` only when ``config.nmap_privileged`` AND root;
otherwise it logs and falls back to ``-sT`` (raw sockets needed for SYN/OS).

Host discovery: ``config.nmap_pn`` (``--pn`` / ``SENTINEL_NMAP_PN``) adds ``-Pn``,
which skips host discovery and treats every address as up. Useful for hosts that
drop ping, but **much slower on a large CIDR** (every host is fully scanned).
Composes with fast/full and privileged.

Timeout: ``config.nmap_timeout`` maps to nmap ``--host-timeout``; nmap finishes
cleanly and every host that completed in time is saved (partial results are
kept, not discarded, and a timed-out host never errors the run).

Emits one Asset per up host (``alive=True``, open_ports, os_guess, mac/vendor
when on-link) and one Finding per open service, weighting cleartext/legacy
exposures highest.
"""
from __future__ import annotations

import ipaddress
import os
from shutil import which
from typing import Tuple

from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity

FAST_TOP_PORTS = 100
FULL_TOP_PORTS = 1000
LARGE_TARGET_HOSTS = 256   # /24 (or larger) => fast by default


def _classify(port: int, name: str, blob: str) -> Tuple[Severity, str]:
    """Severity + reason for an open service, keyed by nmap service name then
    port. `blob` is the lowercased name+product+version+extrainfo, used to spot
    SMBv1. Works with name-only data (fast mode) or full version strings."""
    n = name.lower()
    if n == "telnet" or port == 23:
        return Severity.HIGH, "Telnet exposes credentials in cleartext"
    if n in ("ftp", "ftp-data") or port in (20, 21):
        return Severity.HIGH, "FTP exposes credentials in cleartext"
    if n in ("exec", "login", "shell", "rlogin", "rsh") or port in (512, 513, 514):
        return Severity.HIGH, "Legacy r-service (cleartext remote access)"
    if n in ("microsoft-ds", "netbios-ssn", "smb") or port in (139, 445):
        if any(t in blob for t in ("smbv1", "smb1", "nt lm 0.12", "smb 1.0")):
            return Severity.HIGH, "SMBv1 enabled (legacy, exploitable)"
        return Severity.MEDIUM, "SMB file sharing exposed"
    if n in ("ms-sql-s", "mysql", "postgresql", "mongodb", "redis", "oracle-tns") \
            or port in (1433, 3306, 5432, 27017, 6379, 1521):
        return Severity.MEDIUM, "Database/cache service exposed to the network"
    if n == "ms-wbt-server" or port == 3389:
        return Severity.MEDIUM, "Remote Desktop (RDP) exposed"
    if n == "vnc" or 5900 <= port <= 5905:
        return Severity.MEDIUM, "VNC remote desktop exposed"
    if n in ("http", "http-alt", "http-proxy") or port in (80, 8000, 8080):
        return Severity.LOW, "Plaintext HTTP (no TLS)"
    if n in ("https", "ssh", "domain", "smtps", "imaps", "pop3s") or port in (22, 443):
        return Severity.INFO, "Service present"
    return Severity.INFO, "Open service"


def _is_large_target(target: str) -> bool:
    """True when `target` covers /24-or-larger (>=256 addresses). A single host
    or a hostname is small."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return net.num_addresses >= LARGE_TARGET_HOSTS


# --------------------------------------------------------------------------- #
# enriched parsing + unified device-type inference (pure, unit-testable)
# --------------------------------------------------------------------------- #
_SCRIPT_MAX = 2000           # truncate a single NSE script's output beyond this

# nmap's own osclass "type" -> a friendly label (used when -O ran and matched).
_NMAP_TYPE_LABELS = {
    "general purpose": "Computer / general-purpose host",
    "router": "Router", "broadband router": "Router",
    "wap": "Wireless access point", "printer": "Printer",
    "storage-misc": "NAS / storage", "firewall": "Firewall", "switch": "Switch",
    "webcam": "IP camera", "media device": "Media device", "phone": "Phone",
    "game console": "Game console", "pda": "Mobile device",
    "specialized": "Specialized device", "power-device": "Power device",
    "bridge": "Bridge", "load balancer": "Load balancer",
}


def _truncate(s: str, limit: int = _SCRIPT_MAX) -> str:
    s = str(s)
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n… [truncated {len(s) - limit} chars]"


def _heur(label: str, confidence: str, why: str) -> dict:
    return {"device_type": label, "device_confidence": confidence,
            "device_reasoning": f"{why} (heuristic)"}


def infer_device_type(open_ports, services=None, vendor: str = "",
                      nmap_os_type: str = "", nmap_matched: bool = False) -> dict:
    """ONE coherent device-type guess with confidence + a short 'why'.

    Prefers nmap's own OS/device classification when ``-O`` ran AND matched
    (high confidence); otherwise falls back to port/service/MAC-vendor heuristics
    (clearly marked heuristic). Never returns two competing labels. Pure — no
    nmap object needed, so it unit-tests with and without OS data.
    """
    ports = {int(p) for p in (open_ports or [])}
    services = {int(k): str(v or "").lower() for k, v in (services or {}).items()}
    svc = " ".join(services.values())
    vlow = (vendor or "").lower()

    # 1) Trust nmap's fingerprint when it actually matched.
    if nmap_matched and nmap_os_type:
        key = nmap_os_type.strip().lower()
        label = _NMAP_TYPE_LABELS.get(key, nmap_os_type.strip().title())
        return {"device_type": label, "device_confidence": "high",
                "device_reasoning": f"nmap OS fingerprint classified this device as "
                                    f"'{nmap_os_type.strip()}'"}

    def has(*ps):
        return any(p in ports for p in ps)

    # 2) Heuristics — most specific first; the FIRST match wins (one guess).
    if has(9100, 515, 631) or "jetdirect" in svc or "printer" in svc or "ipp" in svc:
        return _heur("Printer", "medium", "print service port(s) open (9100/515/631)")
    if has(111, 2049) or "nfs" in svc:
        return _heur("NAS / file server", "medium", "NFS/portmapper port(s) open (111/2049)")
    if has(32400):
        return _heur("Media server", "medium", "Plex media-server port open (32400)")
    if has(1900) or "upnp" in svc or "ssdp" in svc:
        return _heur("Router / IoT gateway", "medium", "UPnP/SSDP present (1900)")
    if any(v in vlow for v in ("ubiquiti", "tp-link", "netgear", "mikrotik",
                               "asustek", "d-link", "zyxel", "aruba", "cisco")):
        return _heur("Router / access point", "medium", f"network-equipment MAC vendor ({vendor})")
    if has(53) and (has(80, 443, 23) or len(ports) <= 3):
        return _heur("Router / DNS gateway", "low", "DNS service open (53)")
    if has(3389) or has(445, 139):
        return _heur("Windows host", "medium", "SMB/RDP port(s) open (445/139/3389)")
    if "raspberry" in vlow:
        return _heur("Single-board computer (Raspberry Pi)", "medium", f"MAC vendor {vendor}")
    if has(22) and not has(80, 443, 8080, 8443):
        return _heur("Server / host (SSH)", "low", "SSH open, no web service")
    if has(80, 443, 8080, 8443):
        return _heur("Web server / appliance", "low", "HTTP(S) service open")
    if ports:
        return _heur("Networked host", "low",
                     f"{len(ports)} open port(s), no distinctive signature")
    return _heur("Host", "low", "no open ports observed")


def _port_detail(proto: str, port: int, info: dict) -> dict:
    name = info.get("name", "") or ""
    product = info.get("product", "") or ""
    version = info.get("version", "") or ""
    extrainfo = info.get("extrainfo", "") or ""
    banner = " ".join(x for x in (product, version, extrainfo) if x)
    return {"port": int(port), "proto": proto, "state": info.get("state", "") or "",
            "service": name, "product": product, "version": version,
            "extrainfo": extrainfo, "banner": banner}


def _parse_ssl_cert(output: str) -> dict:
    d = {}
    for line in str(output).splitlines():
        line = line.strip()
        for key in ("Subject:", "Issuer:", "Not valid before:", "Not valid after:"):
            if line.startswith(key):
                d[key.rstrip(":").lower().replace(" ", "_")] = line[len(key):].strip()
    return d


def _extract_tls_http(scripts: dict):
    """Pull an optional TLS cert summary + HTTP server/title from NSE output."""
    tls, http = {}, {}
    for sid, out in scripts.items():
        low = sid.lower()
        if "ssl-cert" in low and not tls:
            tls = _parse_ssl_cert(out)
        if "http-title" in low:
            first = next((ln for ln in str(out).splitlines() if ln.strip()), "")
            http["title"] = first.strip()[:200]
        if "http-server-header" in low:
            http["server"] = str(out).strip()[:200]
    return tls, http


@register
class ReconNmap(Module):
    manifest = Manifest(
        name="red.recon_nmap",
        category="red",
        title="Nmap recon",
        description="Host discovery, ports, service/OS fingerprint",
        requires_tools=["nmap"],
        provides=["assets", "open_services"],
        phase="1",
        display="Recon (nmap)",
    )

    def is_available(self, ctx) -> Tuple[bool, str]:
        if which("nmap") is None:
            return (False, "nmap not installed")
        try:
            import nmap  # noqa: F401  (python-nmap; lazy so discovery never fails)
        except Exception as e:  # noqa: BLE001
            return (False, f"python-nmap not importable: {e}")
        return (True, "")

    # --- scan planning ----------------------------------------------------
    def _effective_fast(self, ctx, target: str) -> bool:
        cfg = ctx.config
        if cfg.nmap_fast is not None:            # explicit config / CLI override
            return bool(cfg.nmap_fast)
        return _is_large_target(target)          # auto: fast for /24-or-larger

    def _privileged(self, ctx) -> bool:
        if not ctx.config.nmap_privileged:
            return False
        if os.geteuid() != 0:
            ctx.log.warning(
                "nmap_privileged set but not running as root; using unprivileged "
                "-sT (SYN/OS scans need raw sockets)"
            )
            return False
        return True

    def _build_args(self, ctx, target: str) -> Tuple[str, bool]:
        """Return (nmap argument string, fast?). Fast skips -sV and -O; full
        keeps the original -sV (+ -O when privileged)."""
        cfg = ctx.config
        fast = self._effective_fast(ctx, target)
        privileged = self._privileged(ctx)

        top = cfg.nmap_top_ports if cfg.nmap_top_ports and cfg.nmap_top_ports > 0 \
            else (FAST_TOP_PORTS if fast else FULL_TOP_PORTS)

        parts = ["-sS" if privileged else "-sT"]
        if cfg.nmap_pn:
            parts.append("-Pn")                  # skip host discovery; all hosts "up"
        if not fast:
            parts.append("-sV")                  # version detection: full only
            if privileged:
                parts.append("-O")               # OS detection: full + privileged
        parts.append(f"-T{cfg.nmap_timing or '4'}")
        parts.append(f"--top-ports {top}")
        if cfg.nmap_timeout and cfg.nmap_timeout > 0:
            parts.append(f"--host-timeout {cfg.nmap_timeout}s")
        return " ".join(parts), fast

    # --- run --------------------------------------------------------------
    def run(self, ctx) -> None:
        import nmap

        target = (ctx.target or "").strip()
        if not target:
            ctx.store.add_finding(
                module=self.manifest.name, type="module_status",
                severity=Severity.INFO, target="(no target)",
                title="Nmap recon skipped (no target)",
                detail="No network target was provided to scan.", tags=["recon"],
            )
            return

        arguments, fast = self._build_args(ctx, target)
        ctx.log.info("recon: scanning %s (%s mode) — nmap %s",
                     target, "fast" if fast else "full", arguments)
        if ctx.config.nmap_pn:
            ctx.log.info("recon: -Pn active — host discovery skipped; every address "
                         "is treated as up (slower on large CIDRs)")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=arguments)
        except Exception as e:  # noqa: BLE001 — a scan failure must not crash the run
            ctx.log.error("nmap scan failed: %s", e)
            ctx.store.add_finding(
                module=self.manifest.name, type="module_error",
                severity=Severity.LOW, target=target, title="Nmap scan failed",
                detail=str(e), evidence=f"nmap {arguments} {target}",
                tags=["recon", "error"],
            )
            return

        # -sS appears iff the scan is privileged; privileged on-link scans use
        # nmap's ARP discovery (finds ping-silent hosts) and report MAC/vendor.
        privileged = "-sS" in arguments.split()
        if privileged:
            ctx.log.info("recon: privileged scan — nmap uses ARP discovery for on-link "
                         "hosts (finds ping-silent devices) and reports MAC/vendor")
        else:
            ctx.log.info("recon: unprivileged scan — MAC/vendor unavailable "
                         "(ARP/OS detection need root)")

        hosts = scanner.all_hosts()
        pn = bool(ctx.config.nmap_pn)
        up_count = 0
        dropped = 0
        svc_count = 0
        discovered_hosts = []
        for host in hosts:
            data = scanner[host]
            if data.state() != "up":
                continue
            emitted = self._record_host(ctx, scanner, host, pn)
            if emitted is None:          # -Pn address with no response -> not alive
                dropped += 1
                continue
            up_count += 1
            svc_count += emitted
            discovered_hosts.append(host)

        # Feed results forward to later chained steps (e.g. Full Audit): the
        # discovered hosts + their open ports land in the store's scratch space so
        # a following module can consume them without the operator retyping a
        # target. Other workflows simply never read these keys.
        if discovered_hosts:
            open_ports = {a.ip: list(a.open_ports)
                          for a in ctx.store.assets()
                          if a.ip in set(discovered_hosts) and a.open_ports}
            ctx.store.set("recon.hosts", discovered_hosts)
            ctx.store.set("recon.open_ports", open_ports)

        if pn:
            ctx.log.info('recon: under -Pn, "alive" = responded with >=1 open/closed port '
                         "or a MAC (not merely pinged); %d alive, %d no-response "
                         "address(es) dropped", up_count, dropped)
        # Hosts that hit --host-timeout are simply absent/down here; the scan
        # still finished cleanly and everything that completed is saved.
        ctx.log.info("recon: complete — %d host(s) up (of %d scanned), %d open service(s)",
                     up_count, len(hosts), svc_count)

    def _record_host(self, ctx, scanner, host: str, pn: bool):
        """Emit one Asset + per-service Findings for a host, or return None to
        drop it.

        Under -Pn there is no host discovery, so nmap marks *every* scanned
        address "up". An address is only kept when it shows genuine liveness —
        a responsive (open/closed) port, a MAC (ARP reply), a hostname, or an OS
        match — so dead addresses that -Pn forced "up" are not counted as hosts.
        Default discovery already reports only live hosts, so nothing is dropped
        there. Returns the number of open-service findings emitted, or None when
        the host was dropped."""
        data = scanner[host]

        # MAC / vendor (populated by nmap's ARP on a privileged on-link scan)
        addresses = data.get("addresses", {}) or {}
        mac = addresses.get("mac", "")
        vendor_map = data.get("vendor", {}) or {}
        vendor = vendor_map.get(mac, "") if mac else ""
        try:
            hostname = data.hostname() or ""
        except Exception:  # noqa: BLE001
            hostname = ""

        # OS guess: best osmatch by accuracy (only when -O was used = full+priv).
        # Also capture the accuracy (nullable) and nmap's own device "type".
        os_guess = ""
        os_accuracy = None
        nmap_os_type = ""
        osmatch = data.get("osmatch", []) or []
        if osmatch:
            try:
                best = max(osmatch, key=lambda m: int(m.get("accuracy", 0)))
            except Exception:  # noqa: BLE001
                best = osmatch[0]
            os_guess = best.get("name", "")
            try:
                acc = best.get("accuracy")
                os_accuracy = int(acc) if acc not in (None, "") else None
            except (TypeError, ValueError):
                os_accuracy = None
            osclass = best.get("osclass") or []
            if osclass and isinstance(osclass[0], dict):
                nmap_os_type = osclass[0].get("type", "") or ""

        # One pass: collect open ports + pending findings, and note whether the
        # host answered any probe (an open OR closed port proves it is alive; a
        # "filtered"/unanswered port does not).
        open_ports = []
        pending = []
        port_details = []
        scripts: dict = {}
        services: dict = {}
        responsive_port = False
        for proto in data.all_protocols():
            if proto not in ("tcp", "udp", "sctp"):
                continue
            for raw_port, info in sorted(data[proto].items()):
                state = info.get("state", "")
                if state in ("open", "closed"):
                    responsive_port = True
                if state != "open":
                    continue
                port = int(raw_port)
                open_ports.append(port)
                name = info.get("name", "") or ""
                product = info.get("product", "") or ""
                version = info.get("version", "") or ""
                extrainfo = info.get("extrainfo", "") or ""
                port_details.append(_port_detail(proto, port, info))
                services[port] = name
                # per-port NSE output (present only when -sC/scripts ran)
                pscripts = info.get("script") or {}
                if isinstance(pscripts, dict):
                    for sid, out in pscripts.items():
                        scripts[f"{sid} ({port}/{proto})"] = _truncate(out)
                blob = " ".join(x for x in (name, product, version, extrainfo) if x).lower()
                sev, reason = _classify(port, name, blob)
                svc = " ".join(x for x in (product, version, extrainfo) if x)
                tags = ["network", "open_service"] + ([name] if name else [])
                pending.append(dict(
                    type="open_service", severity=sev, target=host,
                    title=f"{name or 'unknown'} ({port}/{proto}) open",
                    detail=reason, evidence=f"{port}/{proto} {name} {svc}".strip(),
                    tags=tags,
                ))

        # host-level NSE scripts (e.g. smb-os-discovery) when scripts ran
        for hs in (data.get("hostscript") or []):
            if isinstance(hs, dict) and hs.get("id"):
                scripts[hs["id"]] = _truncate(hs.get("output", ""))

        responded = responsive_port or bool(mac) or bool(hostname) or bool(os_guess)
        if pn and not responded:
            ctx.log.debug("recon: %s returned nothing under -Pn; dropping (not alive)", host)
            return None

        for pf in pending:
            ctx.store.add_finding(module=self.manifest.name, **pf)
        open_ports = sorted(set(open_ports))
        device = infer_device_type(open_ports, services, vendor,
                                   nmap_os_type=nmap_os_type, nmap_matched=bool(osmatch))
        tls, http = _extract_tls_http(scripts)
        ctx.store.add_asset(
            ip=host, alive=True, open_ports=open_ports,
            os_guess=os_guess, os_accuracy=os_accuracy, mac=mac, vendor=vendor,
            hostname=hostname, ports=port_details, scripts=scripts, tls=tls, http=http,
            device_type=device["device_type"],
            device_confidence=device["device_confidence"],
            device_reasoning=device["device_reasoning"],
        )
        ctx.log.info("recon: %s up, %d port(s), device=%s (%s)",
                     host, len(open_ports), device["device_type"], device["device_confidence"])
        return len(pending)
