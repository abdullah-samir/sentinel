# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""blue.capture_tshark — passive packet capture + offline analysis (Phase 1).

PASSIVE / read-only: this module only *listens*. tshark/dumpcap receive packets;
nothing is ever transmitted, and the analysis runs entirely against the saved
pcap. Two separable stages:

    capture(ctx)            -> writes a pcap under captures/, returns its path
    analyze(pcap_path, ctx) -> reads the pcap with tshark, emits findings
    run(ctx) = capture then analyze

Keeping them separate lets a pcap be re-analyzed (`sentinel analyze <pcap>`) and
lets future modules reuse `analyze`.

SECRET REDACTION: credentials are evidence of a weakness, but the secret itself
is never written to a finding or a log. Identifiers (usernames, hosts, SNMP
"community" label) are shown; the secret is masked to its first character plus
fixed bullets, e.g. ``user=admin pass=a•••••``. `_mask()` enforces this and is
applied to every password / community / token before it reaches the store.

Interface selection order: config.capture_iface, else the default-route
interface, else the first non-loopback up interface.

STREAM CORRELATION: protocols that spread a login over multiple packets (FTP and
POP3 send USER then PASS in separate packets; an HTTP POST's headers and form
body can split across segments) are correlated by ``tcp.stream`` — not ip.src,
which collides across concurrent sessions from one host and is empty for IPv6.
A USER seen without a following PASS is still reported as a cleartext login
attempt (password marked "not captured").
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from core.module import Module, Manifest
from core.registry import register
from core.schema import Severity

# --- analysis thresholds / tables ----------------------------------------
NX_BURST_THRESHOLD = 5            # NXDOMAIN responses to one host -> suspicious
TOP_TALKERS = 5
_SECRET_KEYS = {"password", "passwd", "pass", "pwd", "secret", "token",
                "pin", "apikey", "api_key", "auth"}
_BAD_TLDS = {"tk", "gq", "ml", "cf", "ga", "top", "xyz", "zip", "mov", "su"}


# --- small helpers (module-level so tests can inject) ---------------------
def _mask(secret: str) -> str:
    """Mask a secret: first char + fixed bullets, never the real length."""
    secret = str(secret)
    return (secret[:1] if secret else "") + "•••••"


def _capture_permitted(ctx) -> Tuple[bool, str]:
    """Whether this process may capture. Injectable: tests monkeypatch this so
    the result never depends on the test machine's real groups/privileges."""
    if os.geteuid() == 0:
        return (True, "")
    try:
        import grp
        groups = {grp.getgrgid(g).gr_name for g in os.getgroups()}
        if groups & {"wireshark", "pcap"}:
            return (True, "")
    except Exception:  # noqa: BLE001
        pass
    return (False, "no capture permission (add user to the 'wireshark' group or run as root)")


def _default_route_iface() -> Optional[str]:
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except Exception:  # noqa: BLE001
        return None
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    return None


def _first_up_nonloopback() -> Optional[str]:
    try:
        out = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except Exception:  # noqa: BLE001
        return None
    for line in out.splitlines():
        parts = line.split(": ")
        if len(parts) < 3:
            continue
        name = parts[1].split("@")[0]
        if name == "lo":
            continue
        flags = parts[2][parts[2].find("<") + 1:parts[2].find(">")]
        if "UP" in flags.split(","):
            return name
    return None


def _select_iface(config) -> Optional[str]:
    """config.capture_iface -> default-route iface -> first up non-loopback."""
    iface = getattr(config, "capture_iface", "") or ""
    if iface:
        return iface
    return _default_route_iface() or _first_up_nonloopback()


def _pcap_packet_count(pcap: Path) -> Optional[int]:
    if which("capinfos") is None:
        return None
    try:
        out = subprocess.run(["capinfos", "-c", "-M", str(pcap)],
                             capture_output=True, text=True, timeout=30, check=False).stdout
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"Number of packets\D*(\d+)", out)
    return int(m.group(1)) if m else None


_MAX_FILTER_HOSTS = 25            # keep the derived BPF bounded + valid


def _recon_host_filter(ctx) -> str:
    """Build a BPF 'host A or host B …' from hosts a prior recon step published to
    the store scratch (`recon.hosts`), so a Full-Audit capture focuses on the
    discovered hosts without the operator retyping them. Returns "" when no recon
    hosts were forwarded, there are too many to filter cleanly, or a value is not
    a valid IP (never let a stray value reach the BPF)."""
    hosts = ctx.store.get("recon.hosts") or []
    valid = []
    for h in hosts:
        try:
            ipaddress.ip_address(str(h))
        except ValueError:
            continue
        valid.append(str(h))
    if not valid or len(valid) > _MAX_FILTER_HOSTS:
        return ""
    return " or ".join(f"host {h}" for h in valid)


def _decode_basic(auth: str) -> Tuple[str, str]:
    try:
        token = auth.split(None, 1)[1]
        raw = base64.b64decode(token).decode("utf-8", "replace")
        user, _, pw = raw.partition(":")
        return user, pw
    except Exception:  # noqa: BLE001
        return "", ""


@register
class CaptureTshark(Module):
    manifest = Manifest(
        name="blue.capture_tshark",
        category="blue",
        title="Tshark capture",
        description="Passive packet capture to pcap + offline traffic analysis",
        requires_tools=["tshark"],
        provides=["capture", "pcap"],
        phase="1",
        display="Capture (tshark)",
    )

    # --- availability -----------------------------------------------------
    def is_available(self, ctx) -> Tuple[bool, str]:
        if which("tshark") is None:
            return (False, "tshark not installed")
        if _select_iface(ctx.config) is None:
            return (False, "no capture interface")
        ok, why = _capture_permitted(ctx)
        if not ok:
            return (False, why)
        return (True, "")

    def run(self, ctx) -> None:
        pcap = self.capture(ctx)
        if pcap is not None:
            self.analyze(pcap, ctx)

    # ======================================================================
    # Stage 1: capture (passive)
    # ======================================================================
    def capture(self, ctx) -> Optional[Path]:
        cfg = ctx.config
        iface = _select_iface(cfg)
        if not iface:
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target="(capture)", title="Capture skipped — no interface",
                detail="No capture interface could be selected.", tags=["capture"])
            return None

        cfg.captures_dir.mkdir(parents=True, exist_ok=True)
        pcap = cfg.captures_dir / f"{ctx.store.run.run_id}.pcap"
        secs = int(cfg.capture_seconds)
        maxpkts = int(cfg.capture_max_packets)
        maxkb = int(cfg.capture_max_filesize_kb)

        # An explicit filter wins; otherwise, in a chain, focus on the hosts a
        # prior recon step forwarded via the store scratch (no retyping).
        explicit = (cfg.capture_filter or "").strip()
        bpf = explicit or _recon_host_filter(ctx)
        filter_source = "config" if explicit else ("recon" if bpf else "")

        args = ["tshark", "-i", iface, "-w", str(pcap), "-q",
                "-a", f"duration:{secs}", "-c", str(maxpkts),
                "-a", f"filesize:{maxkb}"]
        if bpf:
            args += ["-f", bpf]

        ctx.store.set("capture.iface", iface)
        if filter_source:
            ctx.store.set("capture.filter_source", filter_source)
        ctx.log.info("capture: starting on %s (<=%ss, <=%d pkts, <=%dKB)%s",
                     iface, secs, maxpkts, maxkb,
                     f", filter={bpf!r} (from {filter_source})" if bpf else "")

        hard_timeout = secs + 10          # wall-clock kill so a run can never hang
        start = time.monotonic()
        rc: Optional[int] = None
        timed_out = False
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=hard_timeout, check=False)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True              # subprocess.run has already killed tshark
        except Exception as e:  # noqa: BLE001
            ctx.log.error("capture: tshark failed to start: %s", e)
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=f"capture:{iface}", title="Capture failed to start",
                detail=str(e), tags=["capture", "error"])
            return None

        elapsed = time.monotonic() - start
        size_kb = (pcap.stat().st_size // 1024) if pcap.exists() else 0
        pkts = _pcap_packet_count(pcap) if pcap.exists() else 0

        if timed_out:
            stop = "hard-timeout (killed)"
        elif rc not in (0, None):
            stop = f"tshark-exit-{rc}"
        elif pkts is not None and pkts >= maxpkts:
            stop = "max-packets"
        elif size_kb >= maxkb:
            stop = "max-filesize"
        elif elapsed >= secs - 1:
            stop = "duration"
        else:
            stop = "completed"
        ctx.store.set("capture.stop_reason", stop)
        ctx.store.set("capture.pcap", str(pcap))

        ctx.log.info("capture: done — iface=%s packets=%s bytes=%d duration=%.1fs stop=%s",
                     iface, pkts if pkts is not None else "?",
                     pcap.stat().st_size if pcap.exists() else 0, elapsed, stop)

        if timed_out or (rc not in (0, None)):
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_issue", severity=Severity.INFO,
                target=f"capture:{iface}", title="Capture ended abnormally (partial saved)",
                detail=f"stop reason: {stop}; analyzing whatever was written.",
                tags=["capture"])

        if not pcap.exists():
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=f"capture:{iface}", title="No pcap produced",
                detail="tshark wrote no capture file.", tags=["capture"])
            return None
        return pcap

    # ======================================================================
    # Stage 2: analyze (defensive, offline)
    # ======================================================================
    def analyze(self, pcap_path, ctx) -> None:
        pcap = Path(pcap_path)
        if not pcap.exists() or not pcap.is_file():
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=str(pcap), title="Analysis skipped — pcap not found",
                detail=f"No file at {pcap}.", tags=["capture", "error"])
            return
        try:
            with open(pcap, "rb") as fh:
                fh.read(1)
        except Exception as e:  # noqa: BLE001
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=str(pcap), title="Analysis skipped — pcap not readable",
                detail=str(e), tags=["capture", "error"])
            return
        if which("tshark") is None:
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=str(pcap), title="Analysis skipped — tshark unavailable",
                detail="tshark is required to read the pcap.", tags=["capture", "error"])
            return

        iface = ctx.store.get("capture.iface") or "n/a"
        stop = ctx.store.get("capture.stop_reason") or "n/a"

        summ = self._summarize(ctx, pcap)
        if summ is None:
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_error", severity=Severity.INFO,
                target=str(pcap), title="Analysis failed — tshark could not read pcap",
                detail="tshark returned an error reading the capture.", tags=["capture", "error"])
            return
        if summ["packets"] == 0:
            ctx.store.add_finding(
                module=self.manifest.name, type="capture_summary", severity=Severity.INFO,
                target=f"capture:{iface}", title="No packets captured",
                detail=f"The capture on {iface} contained no packets (stop: {stop}).",
                tags=["capture"])
            return

        self._emit_summary(ctx, summ, iface, stop)

        # Telnet is a cleartext terminal protocol — presence alone is exposure.
        telnet = sum(c for p, c in summ["proto"].items() if p.upper() == "TELNET")
        if telnet:
            ctx.store.add_finding(
                module=self.manifest.name, type="cleartext_cred", severity=Severity.HIGH,
                target="(capture)", title="Cleartext credentials — Telnet session",
                detail="Telnet carries the whole session, including the login, in cleartext.",
                evidence=f"{telnet} Telnet packet(s) observed", tags=["capture", "cleartext", "telnet"])

        # Each check is independently guarded: a missing tshark field only skips
        # that one check (never crashes the analysis).
        self._check_http_basic(ctx, pcap)
        self._check_http_post(ctx, pcap)
        self._check_ftp(ctx, pcap)
        self._check_mail(ctx, pcap)
        self._check_snmp(ctx, pcap)
        self._check_dns(ctx, pcap)
        self._check_arp(ctx, pcap)

    # --- tshark streaming helper -----------------------------------------
    def _stream(self, ctx, pcap: Path, fields: List[str], on_row,
                display_filter: Optional[str] = None, timeout: int = 180,
                two_pass: bool = False) -> bool:
        """Run `tshark -r pcap -T fields ...` and call on_row(list) per packet.
        Streams stdout (the pcap is never loaded whole into memory). Returns
        False — without raising — if tshark errors (e.g. an unknown field), so
        the caller cleanly skips that check.

        `two_pass` adds `-2`: tshark builds full conversation state before
        dissecting, which is required to reliably label stateful app-layer
        protocols (FTP/POP3/HTTP) whose single-pass dissection can miss packets
        in a real capture (reordering, retransmits, mid-stream start)."""
        args = ["tshark", "-r", str(pcap), "-n"]
        if two_pass:
            args.append("-2")
        args += ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"]
        if display_filter:
            args += ["-Y", display_filter]
        for f in fields:
            args += ["-e", f]
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except Exception as e:  # noqa: BLE001
            ctx.log.warning("capture: tshark spawn failed: %s", e)
            return False
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                on_row(line.rstrip("\n").split("\t"))
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            ctx.log.warning("capture: tshark read timed out")
            return False
        except Exception as e:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            ctx.log.warning("capture: tshark read failed: %s", e)
            return False
        if proc.returncode != 0:
            err = (proc.stderr.read() if proc.stderr else "").strip()
            ctx.log.debug("capture: field pass skipped (%s): %s", fields, err[:160])
            return False
        return True

    # --- summary ----------------------------------------------------------
    def _summarize(self, ctx, pcap: Path) -> Optional[Dict]:
        proto: Counter = Counter()
        talkers: Counter = Counter()
        totals = {"packets": 0, "bytes": 0}

        def row(r):
            totals["packets"] += 1
            try:
                totals["bytes"] += int(r[0]) if r and r[0] else 0
            except ValueError:
                pass
            p = r[1] if len(r) > 1 else ""
            if p:
                proto[p] += 1
            src = (r[2] if len(r) > 2 else "") or (r[4] if len(r) > 4 else "")
            dst = (r[3] if len(r) > 3 else "") or (r[5] if len(r) > 5 else "")
            if src or dst:
                try:
                    talkers[(src, dst)] += int(r[0]) if r and r[0] else 0
                except ValueError:
                    pass

        ok = self._stream(ctx, pcap,
                          ["frame.len", "_ws.col.Protocol", "ip.src", "ip.dst",
                           "eth.src", "eth.dst"], row, two_pass=True)
        if not ok:
            return None
        return {"packets": totals["packets"], "bytes": totals["bytes"],
                "proto": proto, "talkers": talkers}

    def _emit_summary(self, ctx, summ: Dict, iface: str, stop: str) -> None:
        proto_txt = ", ".join(f"{p}:{c}" for p, c in summ["proto"].most_common(8)) or "none"
        talk_lines = [f"{(s or '?')}→{(d or '?')}: {b} B"
                      for (s, d), b in summ["talkers"].most_common(TOP_TALKERS)]
        detail = (f"iface={iface}; stop={stop}; packets={summ['packets']}; "
                  f"bytes={summ['bytes']}; protocols: {proto_txt}")
        if talk_lines:
            detail += "; top talkers: " + " | ".join(talk_lines)
        ctx.store.add_finding(
            module=self.manifest.name, type="capture_summary", severity=Severity.INFO,
            target=f"capture:{iface}",
            title=f"Capture summary — {summ['packets']} packets on {iface}",
            detail=detail, evidence=f"protocols={proto_txt}", tags=["capture", "summary"])

    # --- cleartext credential checks (HIGH) -------------------------------
    def _check_http_basic(self, ctx, pcap: Path) -> None:
        found = []

        def row(r):
            auth = r[0] if r else ""
            if auth and auth.lower().startswith("basic"):
                host = r[1] if len(r) > 1 else ""
                uri = r[2] if len(r) > 2 else ""
                user, pw = _decode_basic(auth)
                found.append((host, uri, user, pw))

        if not self._stream(ctx, pcap, ["http.authorization", "http.host",
                                        "http.request.uri"], row, two_pass=True):
            return
        for host, uri, user, pw in found:
            where = f"http://{host}{uri}" if host else (uri or "(unknown)")
            ctx.store.add_finding(
                module=self.manifest.name, type="cleartext_cred", severity=Severity.HIGH,
                target=host or "(capture)", title="Cleartext credentials — HTTP Basic auth",
                detail="HTTP Basic sends credentials base64-encoded (not encrypted) over "
                       "plaintext HTTP.",
                evidence=f"HTTP Basic {where} user={user or '?'} pass={_mask(pw)}",
                tags=["capture", "cleartext", "http"])

    def _check_http_post(self, ctx, pcap: Path) -> None:
        # The POST request line/headers and the urlencoded body can land in
        # different packets; correlate the method and form fields by tcp.stream
        # rather than assuming they share one row.
        streams: Dict[str, Dict] = {}

        def row(r):
            method = (r[0] if r else "").upper()
            uri = r[1] if len(r) > 1 else ""
            host = r[2] if len(r) > 2 else ""
            keys = r[3] if len(r) > 3 else ""
            vals = r[4] if len(r) > 4 else ""
            sid = r[5] if len(r) > 5 else ""
            st = streams.setdefault(sid, {"post": False, "pairs": [], "host": "", "uri": ""})
            if method == "POST":
                st["post"] = True
                st["host"] = host or st["host"]
                st["uri"] = uri or st["uri"]
            if keys:
                for k, v in zip(keys.split(","), vals.split(",")):
                    if k:
                        st["pairs"].append((k, v))

        if not self._stream(ctx, pcap, ["http.request.method", "http.request.uri",
                                        "http.host", "urlencoded-form.key",
                                        "urlencoded-form.value", "tcp.stream"], row,
                            two_pass=True):
            return
        for st in streams.values():
            if not st["post"]:
                continue
            if not any(k.lower() in _SECRET_KEYS for k, _ in st["pairs"]):
                continue
            shown = " ".join(f"{k}={_mask(v) if k.lower() in _SECRET_KEYS else v}"
                             for k, v in st["pairs"])
            where = f"http://{st['host']}{st['uri']}" if st["host"] else (st["uri"] or "(unknown)")
            ctx.store.add_finding(
                module=self.manifest.name, type="cleartext_cred", severity=Severity.HIGH,
                target=st["host"] or "(capture)", title="Cleartext credentials — HTTP POST form",
                detail="A login form was submitted over plaintext HTTP.",
                evidence=f"HTTP POST {where} {shown}"[:300],
                tags=["capture", "cleartext", "http"])

    def _check_ftp(self, ctx, pcap: Path) -> None:
        # FTP sends USER and PASS in SEPARATE packets of the same control
        # connection, so correlate on tcp.stream (not ip.src — which collides
        # across concurrent sessions from one host and is empty for IPv6).
        streams: Dict[str, Dict] = {}

        def row(r):
            cmd = (r[0] if r else "").upper()
            arg = r[1] if len(r) > 1 else ""
            sid = r[2] if len(r) > 2 else ""
            src = r[3] if len(r) > 3 else ""
            if cmd not in ("USER", "PASS"):
                return
            st = streams.setdefault(sid, {"user": None, "pw": None, "src": ""})
            if src and not st["src"]:
                st["src"] = src
            if cmd == "USER":
                st["user"] = arg
            else:
                st["pw"] = arg

        if not self._stream(ctx, pcap, ["ftp.request.command", "ftp.request.arg",
                                        "tcp.stream", "ip.src"], row, two_pass=True):
            return
        for st in streams.values():
            if st["user"] is None and st["pw"] is None:
                continue
            user = st["user"] if st["user"] is not None else "?"
            # USER-without-PASS is still a reportable cleartext login attempt.
            if st["pw"] is not None:
                ev = f"FTP login user={user} pass={_mask(st['pw'])}"
            else:
                ev = f"FTP login attempt user={user} pass=(not captured)"
            if st["src"]:
                ev += f" from {st['src']}"
            ctx.store.add_finding(
                module=self.manifest.name, type="cleartext_cred", severity=Severity.HIGH,
                target=st["src"] or "(capture)", title="Cleartext credentials — FTP login",
                detail="FTP transmits USER/PASS in cleartext.", evidence=ev,
                tags=["capture", "cleartext", "ftp"])

    # --- mail credential checks (MEDIUM) ----------------------------------
    def _check_mail(self, ctx, pcap: Path) -> None:
        # POP3 USER/PASS span two packets (like FTP) -> correlate on tcp.stream.
        # IMAP LOGIN carries user+pass in one request line (single packet).
        pop: Dict[str, Dict] = {}
        imap_events = []

        def row(r):
            pcmd = (r[0] if r else "").upper()
            pparam = r[1] if len(r) > 1 else ""
            ireq = r[2] if len(r) > 2 else ""
            sid = r[3] if len(r) > 3 else ""
            src = r[4] if len(r) > 4 else ""
            if pcmd in ("USER", "PASS"):
                st = pop.setdefault(sid, {"user": None, "pw": None, "src": ""})
                if src and not st["src"]:
                    st["src"] = src
                if pcmd == "USER":
                    st["user"] = pparam
                else:
                    st["pw"] = pparam
            if ireq and "login" in ireq.lower():
                toks = ireq.split()            # "<tag> LOGIN <user> <pass>"
                if len(toks) >= 4 and toks[1].lower() == "login":
                    imap_events.append((src, toks[2], toks[3]))

        if not self._stream(ctx, pcap, ["pop.request.command", "pop.request.parameter",
                                        "imap.request", "tcp.stream", "ip.src"], row,
                            two_pass=True):
            return
        for st in pop.values():
            if st["user"] is None and st["pw"] is None:
                continue
            user = st["user"] if st["user"] is not None else "?"
            pwtxt = _mask(st["pw"]) if st["pw"] is not None else "(not captured)"
            ctx.store.add_finding(
                module=self.manifest.name, type="mail_cred", severity=Severity.MEDIUM,
                target=st["src"] or "(capture)", title="Cleartext credentials — POP3 login",
                detail="POP3 USER/PASS without TLS exposes mailbox credentials.",
                evidence=f"POP3 user={user} pass={pwtxt}"
                         + (f" from {st['src']}" if st["src"] else ""),
                tags=["capture", "cleartext", "pop3"])
        for src, user, pw in imap_events:
            ctx.store.add_finding(
                module=self.manifest.name, type="mail_cred", severity=Severity.MEDIUM,
                target=src or "(capture)", title="Cleartext credentials — IMAP login",
                detail="IMAP LOGIN without TLS exposes mailbox credentials.",
                evidence=f"IMAP user={user} pass={_mask(pw)}", tags=["capture", "cleartext", "imap"])

    def _check_snmp(self, ctx, pcap: Path) -> None:
        comms = set()

        def row(r):
            c = r[0] if r else ""
            if c:
                comms.add((c, r[1] if len(r) > 1 else ""))

        if not self._stream(ctx, pcap, ["snmp.community", "ip.src"], row):
            return
        for comm, src in comms:
            ctx.store.add_finding(
                module=self.manifest.name, type="snmp_community", severity=Severity.MEDIUM,
                target=src or "(capture)", title="SNMP community string exposed",
                detail="SNMP v1/v2c community strings travel in cleartext and act as passwords.",
                evidence=f"SNMP community={_mask(comm)}" + (f" from {src}" if src else ""),
                tags=["capture", "cleartext", "snmp"])

    # --- suspicious DNS (MEDIUM) ------------------------------------------
    def _check_dns(self, ctx, pcap: Path) -> None:
        nx: Counter = Counter()
        bad_tld = []

        def row(r):
            rcode = r[0] if r else ""
            qname = r[1] if len(r) > 1 else ""
            src = r[2] if len(r) > 2 else ""
            dst = r[3] if len(r) > 3 else ""
            if rcode == "3":                       # NXDOMAIN (in the response) -> client is dst
                client = dst or src
                if client:
                    nx[client] += 1
            if qname:
                tld = qname.rstrip(".").rsplit(".", 1)[-1].lower()
                if tld in _BAD_TLDS:
                    bad_tld.append((qname, src))

        if not self._stream(ctx, pcap, ["dns.flags.rcode", "dns.qry.name",
                                        "ip.src", "ip.dst"], row):
            return
        for client, count in nx.items():
            if count >= NX_BURST_THRESHOLD:
                ctx.store.add_finding(
                    module=self.manifest.name, type="suspicious_dns", severity=Severity.MEDIUM,
                    target=client, title=f"Suspicious DNS — {count} NXDOMAIN responses to {client}",
                    detail="A burst of NXDOMAIN answers to one host can indicate DNS tunneling, "
                           "DGA malware, or misconfiguration. Investigate.",
                    evidence=f"{count} NXDOMAIN responses to {client} within the capture window",
                    tags=["capture", "dns"])
        if bad_tld:
            sample = ", ".join(sorted({q for q, _ in bad_tld})[:5])
            ctx.store.add_finding(
                module=self.manifest.name, type="suspicious_dns", severity=Severity.MEDIUM,
                target="(capture)", title=f"Suspicious DNS — {len(bad_tld)} queries to high-risk TLDs",
                detail="Queries to TLDs frequently abused for malware C2/phishing. Investigate.",
                evidence=f"examples: {sample}", tags=["capture", "dns"])

    # --- ARP anomaly (MEDIUM, phrased as possible) ------------------------
    def _check_arp(self, ctx, pcap: Path) -> None:
        ip2mac: Dict[str, set] = defaultdict(set)

        def row(r):
            ip = r[0] if r else ""
            mac = r[1] if len(r) > 1 else ""
            if ip and mac:
                ip2mac[ip].add(mac.lower())

        if not self._stream(ctx, pcap, ["arp.src.proto_ipv4", "arp.src.hw_mac"], row):
            return
        for ip, macs in ip2mac.items():
            if len(macs) >= 2:
                ctx.store.add_finding(
                    module=self.manifest.name, type="arp_anomaly", severity=Severity.MEDIUM,
                    target=ip, title=f"Possible ARP spoofing — {ip} claimed by {len(macs)} MACs",
                    detail="Within the capture window one IP was announced by multiple MAC "
                           "addresses. This can indicate ARP spoofing / MITM, or a legitimate "
                           "failover (VRRP/HSRP). Investigate — not confirmed.",
                    evidence=f"{ip} claimed by MACs: {', '.join(sorted(macs))}",
                    tags=["capture", "arp", "possible"])
