"""Tests for blue.capture_tshark.

Deterministic and offline: pcaps are generated programmatically with scapy
(synthetic, obviously-fake data) as REALISTIC TCP streams — handshake, server
responses, and credentials spread across multiple packets, as real traffic does.
analyze() runs real tshark against them; the capture subprocess is mocked (never
a live capture); is_available's permission check is injected.
"""
from __future__ import annotations

import base64
import shutil
from pathlib import Path

import pytest
from scapy.all import ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap

from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.log import get_logger
from core.schema import RunResult, utcnow_iso
from core.store import Store
from plugins.blue import capture_tshark as cap
from plugins.blue.capture_tshark import CaptureTshark

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


def make_ctx(tmp_path, **cfg_over):
    cfg = Config(root=tmp_path)
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    run = RunResult(run_id="cap-test", workflow="capture_only", target="(capture)",
                    started_at=utcnow_iso())
    store = Store(run, tmp_path / "r.json")
    return RunContext(target="(capture)", workflow="capture_only", config=cfg, store=store,
                      log=get_logger("sentinel.test"), hw=build_hardware(cfg), events=EventBus())


def _blob(ctx):
    return " ".join(f"{f.evidence} {f.detail}" for f in ctx.store.findings())


# --- realistic TCP stream builder (handshake + segments) ------------------
def _tcp_stream(cli, sport, srv, dport, segs):
    """segs: list of ("c"|"s", payload_str). Builds a plausible TCP stream with
    a 3-way handshake so credentials genuinely span separate packets."""
    pkts = []
    c, s = 1000, 5000
    pkts.append(Ether() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)); c += 1
    pkts.append(Ether() / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c)); s += 1
    pkts.append(Ether() / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s))
    for who, payload in segs:
        b = payload.encode()
        if who == "c":
            pkts.append(Ether() / IP(src=cli, dst=srv) /
                        TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / Raw(load=b))
            c += len(b)
        else:
            pkts.append(Ether() / IP(src=srv, dst=cli) /
                        TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / Raw(load=b))
            s += len(b)
    return pkts


def _ftp_login(cli="10.0.0.6", sport=40003, user="admin", pw="s3cr3tftp"):
    return _tcp_stream(cli, sport, "10.0.0.21", 21, [
        ("s", "220 FTP ready\r\n"), ("c", f"USER {user}\r\n"),
        ("s", "331 need password\r\n"), ("c", f"PASS {pw}\r\n"), ("s", "230 ok\r\n")])


def _ftp_user_only(cli="10.0.0.16", sport=40004, user="orphan"):
    return _tcp_stream(cli, sport, "10.0.0.21", 21, [
        ("s", "220 FTP ready\r\n"), ("c", f"USER {user}\r\n"), ("s", "331 need password\r\n")])


def _http_basic(cli="10.0.0.5", sport=40010, user="admin", pw="secret123"):
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = f"GET /secret HTTP/1.1\r\nHost: web.lab\r\nAuthorization: Basic {tok}\r\n\r\n"
    return _tcp_stream(cli, sport, "10.0.0.80", 80, [("c", req), ("s", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])


def _http_post_split(cli="10.0.0.5", sport=40011, pw="hunter2"):
    body = f"user=admin&password={pw}"
    headers = ("POST /login HTTP/1.1\r\nHost: web.lab\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n\r\n")
    # headers and body in SEPARATE client packets (same stream)
    return _tcp_stream(cli, sport, "10.0.0.80", 80,
                       [("c", headers), ("c", body), ("s", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])


def _pop3(cli="10.0.0.7", sport=40020, user="alice", pw="popsecret"):
    return _tcp_stream(cli, sport, "10.0.0.110", 110, [
        ("s", "+OK POP3\r\n"), ("c", f"USER {user}\r\n"), ("s", "+OK\r\n"),
        ("c", f"PASS {pw}\r\n"), ("s", "+OK\r\n")])


def _imap(cli="10.0.0.8", sport=40030, user="bob", pw="imapsecret"):
    return _tcp_stream(cli, sport, "10.0.0.143", 143, [
        ("s", "* OK IMAP\r\n"), ("c", f"a1 LOGIN {user} {pw}\r\n"), ("s", "a1 OK\r\n")])


def _write(p, pkts):
    wrpcap(str(p), pkts)


def _dns_pcap(p):
    pkts = []
    for i in range(10):
        name = f"x{i}chunk.tunnel.example.com"
        pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=50000 + i, dport=53) /
                    DNS(id=i, rd=1, qd=DNSQR(qname=name)))
        pkts.append(Ether() / IP(src="10.0.0.53", dst="10.0.0.5") / UDP(sport=53, dport=50000 + i) /
                    DNS(id=i, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name)))
    _write(p, pkts)


def _arp_pcap(p):
    _write(p, [Ether(src="aa:aa:aa:aa:aa:aa") / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.9"),
               Ether(src="bb:bb:bb:bb:bb:bb") / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.9")])


def _empty_pcap(p):
    wrpcap(str(p), [], linktype=1)


# =========================================================================
# Regression: the reported FTP bug — USER in packet 1, PASS in packet 2
# =========================================================================
def test_ftp_cred_across_packets_regression(tmp_path):
    pcap = tmp_path / "ftp.pcap"
    _write(pcap, _ftp_login(user="admin", pw="s3cr3tftp"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    ftp = [f for f in ctx.store.findings()
           if f.type == "cleartext_cred" and "FTP" in f.title]
    assert ftp, "FTP cleartext credential finding was not emitted"
    assert ftp[0].severity == "high"
    assert "user=admin" in ftp[0].evidence
    assert "s3cr3tftp" not in _blob(ctx)          # raw password never written
    assert "•" in ftp[0].evidence                 # masked


def test_ftp_user_without_pass_still_reported(tmp_path):
    pcap = tmp_path / "ftp_user.pcap"
    _write(pcap, _ftp_user_only(user="orphan"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    ftp = [f for f in ctx.store.findings()
           if f.type == "cleartext_cred" and "FTP" in f.title]
    assert ftp and ftp[0].severity == "high"
    assert "user=orphan" in ftp[0].evidence
    assert "not captured" in ftp[0].evidence.lower()


# =========================================================================
# Each protocol spread across packets: detected AND redacted
# =========================================================================
def test_http_basic_detected_and_redacted(tmp_path):
    pcap = tmp_path / "hb.pcap"
    _write(pcap, _http_basic(pw="secret123"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    hb = [f for f in ctx.store.findings() if "HTTP Basic" in f.title]
    assert hb and hb[0].severity == "high"
    assert "user=admin" in hb[0].evidence
    assert "secret123" not in _blob(ctx)
    assert base64.b64encode(b"admin:secret123").decode() not in _blob(ctx)


def test_http_post_form_across_packets(tmp_path):
    pcap = tmp_path / "hp.pcap"
    _write(pcap, _http_post_split(pw="hunter2"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    hp = [f for f in ctx.store.findings() if "HTTP POST form" in f.title]
    assert hp and hp[0].severity == "high"
    assert "user=admin" in hp[0].evidence
    assert "hunter2" not in _blob(ctx)
    assert "password=" in hp[0].evidence and "•" in hp[0].evidence


def test_pop3_cred_across_packets(tmp_path):
    pcap = tmp_path / "pop.pcap"
    _write(pcap, _pop3(user="alice", pw="popsecret"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    pop = [f for f in ctx.store.findings() if "POP3" in f.title]
    assert pop and pop[0].severity == "medium"
    assert "user=alice" in pop[0].evidence
    assert "popsecret" not in _blob(ctx)


def test_imap_login_detected_and_redacted(tmp_path):
    pcap = tmp_path / "imap.pcap"
    _write(pcap, _imap(user="bob", pw="imapsecret"))
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    im = [f for f in ctx.store.findings() if "IMAP" in f.title]
    assert im and im[0].severity == "medium"
    assert "user=bob" in im[0].evidence
    assert "imapsecret" not in _blob(ctx)


def test_all_creds_combined_detected_and_masked(tmp_path):
    pcap = tmp_path / "creds.pcap"
    _write(pcap, _ftp_login() + _http_basic() + _http_post_split() + _pop3() + _imap())
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    titles = " ".join(f.title for f in ctx.store.findings())
    for needle in ("FTP login", "HTTP Basic", "HTTP POST form", "POP3", "IMAP"):
        assert needle in titles, f"missing detection: {needle}"
    # no raw secret anywhere in any finding
    blob = _blob(ctx)
    for secret in ("s3cr3tftp", "secret123", "hunter2", "popsecret", "imapsecret"):
        assert secret not in blob, f"raw secret leaked: {secret}"


# =========================================================================
# Non-credential analysis (unchanged behavior)
# =========================================================================
def test_dns_heuristic_fires(tmp_path):
    pcap = tmp_path / "dns.pcap"
    _dns_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    dns = [f for f in ctx.store.findings() if f.type == "suspicious_dns"]
    assert dns and any("NXDOMAIN" in f.title and "10.0.0.5" in f.title for f in dns)
    assert all(f.severity == "medium" for f in dns)


def test_arp_anomaly_flagged_possible(tmp_path):
    pcap = tmp_path / "arp.pcap"
    _arp_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    arp = [f for f in ctx.store.findings() if f.type == "arp_anomaly"]
    assert arp and arp[0].severity == "medium" and "10.0.0.1" in arp[0].title
    text = (arp[0].title + " " + arp[0].detail).lower()
    assert "possible" in text and "investigate" in text


def test_summary_finding(tmp_path):
    pcap = tmp_path / "ftp.pcap"
    _write(pcap, _ftp_login())
    ctx = make_ctx(tmp_path)
    ctx.store.set("capture.iface", "eth0")
    ctx.store.set("capture.stop_reason", "duration")
    CaptureTshark().analyze(pcap, ctx)
    summ = [f for f in ctx.store.findings() if f.type == "capture_summary"]
    assert len(summ) == 1 and summ[0].severity == "info"
    assert "eth0" in summ[0].detail and "packets=" in summ[0].detail


def test_zero_packet_clean_noop(tmp_path):
    pcap = tmp_path / "empty.pcap"
    _empty_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)
    fs = ctx.store.findings()
    assert len(fs) == 1 and fs[0].type == "capture_summary" and "No packets" in fs[0].title
    assert not [f for f in fs if f.type in ("cleartext_cred", "suspicious_dns", "arp_anomaly")]


def test_missing_tshark_field_skips_not_crash(tmp_path):
    pcap = tmp_path / "ftp.pcap"
    _write(pcap, _ftp_login())
    ctx = make_ctx(tmp_path)
    assert CaptureTshark()._stream(ctx, pcap, ["totally.bogus.field"], lambda r: None) is False


def test_analyze_bad_path_clean_error(tmp_path):
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(tmp_path / "does-not-exist.pcap", ctx)
    errs = [f for f in ctx.store.findings() if f.type == "capture_error"]
    assert errs and "not found" in errs[0].title.lower()


# =========================================================================
# is_available (injected permission) + capture (mocked subprocess)
# =========================================================================
def test_is_available_permission_branches(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "which", lambda n: "/usr/bin/tshark")
    ctx = make_ctx(tmp_path, capture_iface="eth0")
    monkeypatch.setattr(cap, "_capture_permitted", lambda c: (True, ""))
    ok, why = CaptureTshark().is_available(ctx)
    assert ok and why == ""
    monkeypatch.setattr(cap, "_capture_permitted", lambda c: (False, "nope"))
    ok, why = CaptureTshark().is_available(ctx)
    assert not ok and why == "nope"


def test_is_available_no_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "which", lambda n: "/usr/bin/tshark")
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: None)
    ok, why = CaptureTshark().is_available(make_ctx(tmp_path))
    assert not ok and "interface" in why


def test_capture_builds_args_and_records_stop(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 5)
    captured = {}

    def fake_run(args, **kw):
        captured["args"] = args
        Path(args[args.index("-w") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1")
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(cap.subprocess, "run", fake_run)
    ctx = make_ctx(tmp_path, capture_seconds=5, capture_max_packets=100,
                   capture_max_filesize_kb=1024, capture_filter="not port 22")
    pcap = CaptureTshark().capture(ctx)
    assert pcap is not None and pcap.exists()
    a = captured["args"]
    assert a[0] == "tshark" and a[a.index("-i") + 1] == "eth0" and "-w" in a
    assert "duration:5" in a and a[a.index("-c") + 1] == "100" and "filesize:1024" in a
    assert a[a.index("-f") + 1] == "not port 22"
    assert ctx.store.get("capture.pcap") == str(pcap)
    assert ctx.store.get("capture.iface") == "eth0"
    assert ctx.store.get("capture.stop_reason")


def _fake_run_writing(captured):
    def fake_run(args, **kw):
        captured["args"] = args
        Path(args[args.index("-w") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1")

        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()
    return fake_run


def test_capture_focuses_on_recon_hosts_when_no_filter(tmp_path, monkeypatch):
    """Full-Audit data-forward: recon's discovered hosts (store scratch) become
    the capture's BPF filter when the operator set none."""
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 1)
    captured = {}
    monkeypatch.setattr(cap.subprocess, "run", _fake_run_writing(captured))
    ctx = make_ctx(tmp_path, capture_seconds=2)        # no explicit capture_filter
    ctx.store.set("recon.hosts", ["10.0.0.8", "10.0.0.9"])
    CaptureTshark().capture(ctx)
    a = captured["args"]
    assert a[a.index("-f") + 1] == "host 10.0.0.8 or host 10.0.0.9"
    assert ctx.store.get("capture.filter_source") == "recon"


def test_capture_explicit_filter_beats_recon(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 1)
    captured = {}
    monkeypatch.setattr(cap.subprocess, "run", _fake_run_writing(captured))
    ctx = make_ctx(tmp_path, capture_seconds=2, capture_filter="not port 22")
    ctx.store.set("recon.hosts", ["10.0.0.8"])
    CaptureTshark().capture(ctx)
    a = captured["args"]
    assert a[a.index("-f") + 1] == "not port 22"        # explicit wins
    assert ctx.store.get("capture.filter_source") == "config"


def test_capture_no_filter_without_recon(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 1)
    captured = {}
    monkeypatch.setattr(cap.subprocess, "run", _fake_run_writing(captured))
    ctx = make_ctx(tmp_path, capture_seconds=2)         # no filter, no recon scratch
    CaptureTshark().capture(ctx)
    assert "-f" not in captured["args"]


def test_capture_ignores_bad_recon_values(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 1)
    captured = {}
    monkeypatch.setattr(cap.subprocess, "run", _fake_run_writing(captured))
    ctx = make_ctx(tmp_path, capture_seconds=2)
    ctx.store.set("recon.hosts", ["not-an-ip", "10.0.0.5"])   # non-IP dropped
    CaptureTshark().capture(ctx)
    assert captured["args"][captured["args"].index("-f") + 1] == "host 10.0.0.5"


def test_capture_timeout_saves_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 3)

    def fake_run(args, **kw):
        Path(args[args.index("-w") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1")
        raise cap.subprocess.TimeoutExpired(cmd="tshark", timeout=kw.get("timeout", 1))

    monkeypatch.setattr(cap.subprocess, "run", fake_run)
    ctx = make_ctx(tmp_path, capture_seconds=1)
    pcap = CaptureTshark().capture(ctx)
    assert pcap is not None and pcap.exists()
    assert ctx.store.get("capture.stop_reason").startswith("hard-timeout")
    assert [f for f in ctx.store.findings() if f.type == "capture_issue"]
