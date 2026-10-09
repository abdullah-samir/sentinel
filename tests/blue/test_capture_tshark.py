"""Tests for blue.capture_tshark.

Deterministic and offline: pcaps are generated programmatically with scapy
(synthetic, obviously-fake data), analyze() runs real tshark against them, and
the capture subprocess is mocked (never a live capture). is_available's
permission check is injected so results don't depend on the test machine.
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


# --- synthetic pcap builders (fake data, safe to commit) ------------------
def _creds_pcap(p: Path):
    b64 = base64.b64encode(b"admin:secret123").decode()
    http_basic = (Ether() / IP(src="10.0.0.5", dst="10.0.0.80") /
                  TCP(sport=40001, dport=80, flags="PA", seq=1) /
                  Raw(load=(f"GET /secret HTTP/1.1\r\nHost: web.lab\r\n"
                            f"Authorization: Basic {b64}\r\n\r\n").encode()))
    body = b"user=admin&password=hunter2"
    http_post = (Ether() / IP(src="10.0.0.5", dst="10.0.0.80") /
                 TCP(sport=40002, dport=80, flags="PA", seq=1) /
                 Raw(load=(b"POST /login HTTP/1.1\r\nHost: web.lab\r\n"
                           b"Content-Type: application/x-www-form-urlencoded\r\n"
                           b"Content-Length: %d\r\n\r\n%s" % (len(body), body))))
    ftp_u = (Ether() / IP(src="10.0.0.6", dst="10.0.0.21") /
             TCP(sport=40003, dport=21, flags="PA", seq=1) / Raw(load=b"USER admin\r\n"))
    ftp_p = (Ether() / IP(src="10.0.0.6", dst="10.0.0.21") /
             TCP(sport=40003, dport=21, flags="PA", seq=12) / Raw(load=b"PASS s3cr3tftp\r\n"))
    wrpcap(str(p), [http_basic, http_post, ftp_u, ftp_p])


def _dns_pcap(p: Path):
    pkts = []
    for i in range(10):                        # NXDOMAIN burst from one client
        name = f"x{i}chunk.tunnel.example.com"
        q = (IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=50000 + i, dport=53) /
             DNS(id=i, rd=1, qd=DNSQR(qname=name)))
        r = (IP(src="10.0.0.53", dst="10.0.0.5") / UDP(sport=53, dport=50000 + i) /
             DNS(id=i, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name)))
        pkts += [Ether() / q, Ether() / r]
    wrpcap(str(p), pkts)


def _arp_pcap(p: Path):
    a = (Ether(src="aa:aa:aa:aa:aa:aa") /
         ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.9"))
    b = (Ether(src="bb:bb:bb:bb:bb:bb") /
         ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.9"))
    wrpcap(str(p), [a, b])


def _empty_pcap(p: Path):
    wrpcap(str(p), [], linktype=1)


def _blob(ctx):
    return " ".join(f"{f.evidence} {f.detail}" for f in ctx.store.findings())


# --- analyze: cleartext creds detected AND redacted -----------------------
def test_cleartext_creds_detected_and_redacted(tmp_path):
    pcap = tmp_path / "creds.pcap"
    _creds_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    titles = [f.title for f in ctx.store.findings()]
    assert any("HTTP Basic" in t for t in titles)
    assert any("HTTP POST form" in t for t in titles)
    assert any("FTP login" in t for t in titles)

    creds = [f for f in ctx.store.findings() if f.type == "cleartext_cred"]
    assert creds and all(f.severity == "high" for f in creds)

    blob = _blob(ctx)
    for secret in ("secret123", "hunter2", "s3cr3tftp", "YWRtaW46c2VjcmV0MTIz"):
        assert secret not in blob, f"raw secret leaked: {secret}"
    assert "user=admin" in blob      # identifiers shown
    assert "•" in blob               # secret masked


# --- analyze: DNS heuristic ----------------------------------------------
def test_dns_heuristic_fires(tmp_path):
    pcap = tmp_path / "dns.pcap"
    _dns_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    dns = [f for f in ctx.store.findings() if f.type == "suspicious_dns"]
    assert dns
    assert any("NXDOMAIN" in f.title and "10.0.0.5" in f.title for f in dns)
    assert all(f.severity == "medium" for f in dns)


# --- analyze: ARP anomaly phrased as possible -----------------------------
def test_arp_anomaly_flagged_possible(tmp_path):
    pcap = tmp_path / "arp.pcap"
    _arp_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    arp = [f for f in ctx.store.findings() if f.type == "arp_anomaly"]
    assert arp and arp[0].severity == "medium"
    assert "10.0.0.1" in arp[0].title
    text = (arp[0].title + " " + arp[0].detail).lower()
    assert "possible" in text and "investigate" in text   # not asserted as fact


# --- analyze: summary -----------------------------------------------------
def test_summary_finding(tmp_path):
    pcap = tmp_path / "creds.pcap"
    _creds_pcap(pcap)
    ctx = make_ctx(tmp_path)
    ctx.store.set("capture.iface", "eth0")
    ctx.store.set("capture.stop_reason", "duration")
    CaptureTshark().analyze(pcap, ctx)

    summ = [f for f in ctx.store.findings() if f.type == "capture_summary"]
    assert len(summ) == 1
    assert summ[0].severity == "info"
    assert "eth0" in summ[0].detail and "packets=" in summ[0].detail


# --- analyze: zero-packet clean no-op -------------------------------------
def test_zero_packet_clean_noop(tmp_path):
    pcap = tmp_path / "empty.pcap"
    _empty_pcap(pcap)
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(pcap, ctx)

    fs = ctx.store.findings()
    assert len(fs) == 1 and fs[0].type == "capture_summary"
    assert "No packets" in fs[0].title
    assert not [f for f in fs if f.type in ("cleartext_cred", "suspicious_dns", "arp_anomaly")]


# --- analyze: defensive against a missing tshark field --------------------
def test_missing_tshark_field_skips_not_crash(tmp_path):
    pcap = tmp_path / "creds.pcap"
    _creds_pcap(pcap)
    ctx = make_ctx(tmp_path)
    ok = CaptureTshark()._stream(ctx, pcap, ["totally.bogus.field"], lambda r: None)
    assert ok is False                # unknown field -> clean False, no exception


# --- analyze: bad path ----------------------------------------------------
def test_analyze_bad_path_clean_error(tmp_path):
    ctx = make_ctx(tmp_path)
    CaptureTshark().analyze(tmp_path / "does-not-exist.pcap", ctx)
    errs = [f for f in ctx.store.findings() if f.type == "capture_error"]
    assert errs and "not found" in errs[0].title.lower()


# --- is_available: both permission branches (injected) --------------------
def test_is_available_permission_branches(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "which", lambda n: "/usr/bin/tshark")
    ctx = make_ctx(tmp_path, capture_iface="eth0")     # force iface -> no machine dep

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


# --- capture: mocked subprocess (no live capture) -------------------------
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
    assert a[0] == "tshark"
    assert a[a.index("-i") + 1] == "eth0"
    assert "-w" in a
    assert "duration:5" in a
    assert a[a.index("-c") + 1] == "100"
    assert "filesize:1024" in a
    assert a[a.index("-f") + 1] == "not port 22"
    assert ctx.store.get("capture.pcap") == str(pcap)
    assert ctx.store.get("capture.iface") == "eth0"
    assert ctx.store.get("capture.stop_reason")


def test_capture_timeout_saves_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "_select_iface", lambda cfg: "eth0")
    monkeypatch.setattr(cap, "_pcap_packet_count", lambda p: 3)

    def fake_run(args, **kw):
        Path(args[args.index("-w") + 1]).write_bytes(b"\xd4\xc3\xb2\xa1")   # partial pcap
        raise cap.subprocess.TimeoutExpired(cmd="tshark", timeout=kw.get("timeout", 1))

    monkeypatch.setattr(cap.subprocess, "run", fake_run)
    ctx = make_ctx(tmp_path, capture_seconds=1)
    pcap = CaptureTshark().capture(ctx)

    assert pcap is not None and pcap.exists()                 # partial saved, not lost
    assert ctx.store.get("capture.stop_reason").startswith("hard-timeout")
    assert [f for f in ctx.store.findings() if f.type == "capture_issue"]
