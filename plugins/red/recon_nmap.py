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

        # OS guess: best osmatch by accuracy (only when -O was used = full+priv)
        os_guess = ""
        osmatch = data.get("osmatch", []) or []
        if osmatch:
            try:
                best = max(osmatch, key=lambda m: int(m.get("accuracy", 0)))
                os_guess = best.get("name", "")
            except Exception:  # noqa: BLE001
                os_guess = osmatch[0].get("name", "")

        # One pass: collect open ports + pending findings, and note whether the
        # host answered any probe (an open OR closed port proves it is alive; a
        # "filtered"/unanswered port does not).
        open_ports = []
        pending = []
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

        responded = responsive_port or bool(mac) or bool(hostname) or bool(os_guess)
        if pn and not responded:
            ctx.log.debug("recon: %s returned nothing under -Pn; dropping (not alive)", host)
            return None

        for pf in pending:
            ctx.store.add_finding(module=self.manifest.name, **pf)
        open_ports = sorted(set(open_ports))
        ctx.store.add_asset(
            ip=host, alive=True, open_ports=open_ports,
            os_guess=os_guess, mac=mac, vendor=vendor, hostname=hostname,
        )
        ctx.log.info("recon: %s up, %d port(s)", host, len(open_ports))
        return len(pending)
