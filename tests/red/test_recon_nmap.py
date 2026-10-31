"""Tests for red.recon_nmap — python-nmap is mocked so no real scan runs."""
from __future__ import annotations

import os

import nmap
import pytest

from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.log import get_logger
from core.schema import RunResult, utcnow_iso
from core.store import Store
from plugins.red import recon_nmap as recon_mod
from plugins.red.recon_nmap import ReconNmap


# --- fakes mimicking the python-nmap surface the module touches -----------
class FakeHost(dict):
    def __init__(self, state="up", protocols=None, osmatch=None, addresses=None,
                 vendor=None, hostname=""):
        super().__init__()
        self._state = state
        self._hostname = hostname
        if protocols:
            self.update(protocols)
        if osmatch is not None:
            self["osmatch"] = osmatch
        if addresses is not None:
            self["addresses"] = addresses
        if vendor is not None:
            self["vendor"] = vendor

    def state(self):
        return self._state

    def hostname(self):
        return self._hostname

    def all_protocols(self):
        return [p for p in ("ip", "tcp", "udp", "sctp") if p in self]


class FakeScanner:
    def __init__(self, hosts):
        self._hosts = hosts
        self.calls = []

    def scan(self, hosts=None, arguments=None, **kw):
        self.calls.append({"hosts": hosts, "arguments": arguments})
        return {}

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, h):
        return self._hosts[h]


def make_ctx(tmp_path, target="10.0.0.0/24", **cfg_over):
    cfg = Config(root=tmp_path)
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    run = RunResult(run_id="t", workflow="quick_recon", target=target,
                    started_at=utcnow_iso())
    store = Store(run, tmp_path / "t.json")
    return RunContext(target=target, workflow="quick_recon", config=cfg, store=store,
                      log=get_logger("sentinel.test"), hw=build_hardware(cfg),
                      events=EventBus())


# --- availability ---------------------------------------------------------
def test_is_available_true(monkeypatch):
    monkeypatch.setattr(recon_mod, "which", lambda name: "/usr/bin/nmap")
    ok, reason = ReconNmap().is_available(None)
    assert ok and reason == ""


def test_is_available_without_nmap(monkeypatch):
    monkeypatch.setattr(recon_mod, "which", lambda name: None)
    ok, reason = ReconNmap().is_available(None)
    assert not ok and "nmap" in reason


# --- arg construction: fast vs full ---------------------------------------
def test_full_arg_construction(tmp_path):
    args, fast = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=False), "10.0.0.5")
    assert fast is False
    assert "-sT" in args and "-sV" in args
    assert "--top-ports 1000" in args
    assert "-O" not in args
    assert "-T4" in args


def test_fast_arg_construction(tmp_path):
    args, fast = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=True), "10.0.0.0/24")
    assert fast is True
    assert "-sT" in args
    assert "-sV" not in args           # version detection skipped in fast mode
    assert "-O" not in args
    assert "--top-ports 100" in args


def test_auto_fast_for_large_target(tmp_path):
    args, fast = ReconNmap()._build_args(make_ctx(tmp_path), "10.0.0.0/24")
    assert fast is True and "-sV" not in args and "--top-ports 100" in args


def test_auto_full_for_single_host(tmp_path):
    args, fast = ReconNmap()._build_args(make_ctx(tmp_path), "10.0.0.5")
    assert fast is False and "-sV" in args and "--top-ports 1000" in args


def test_config_overrides_auto(tmp_path):
    # explicit full on a large target beats the fast auto-default, and vice versa
    _, fast_full = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=False), "10.0.0.0/24")
    _, fast_fast = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=True), "10.0.0.5")
    assert fast_full is False and fast_fast is True


def test_top_ports_override(tmp_path):
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=True, nmap_top_ports=50), "10.0.0.0/24")
    assert "--top-ports 50" in args


# --- arg construction: timeout --------------------------------------------
def test_timeout_arg_present_by_default(tmp_path):
    args, _ = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=True), "10.0.0.0/24")
    assert "--host-timeout 300s" in args


def test_timeout_override(tmp_path):
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=True, nmap_timeout=120), "10.0.0.0/24")
    assert "--host-timeout 120s" in args


def test_timeout_disabled(tmp_path):
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=True, nmap_timeout=0), "10.0.0.0/24")
    assert "--host-timeout" not in args


# --- arg construction: privilege gating -----------------------------------
def test_full_with_privileged_has_sv_and_o(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=False, nmap_privileged=True), "10.0.0.5")
    assert "-sS" in args and "-sV" in args and "-O" in args
    assert "--top-ports 1000" in args


def test_fast_with_privileged_is_syn_no_version_no_os(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args, fast = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=True, nmap_privileged=True), "10.0.0.0/24")
    assert fast is True
    assert "-sS" in args                # SYN scan honored
    assert "-sV" not in args            # no version in fast mode
    assert "-O" not in args             # OS detection skipped in fast mode
    assert "--top-ports 100" in args


def test_privileged_falls_back_when_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=False, nmap_privileged=True), "10.0.0.5")
    assert "-sT" in args and "-sS" not in args
    assert "-sV" in args                # still full mode
    assert "-O" not in args


# --- full-mode scan: assets + findings + version evidence -----------------
def test_scan_emits_assets_and_findings(tmp_path, monkeypatch):
    tcp = {
        23: {"state": "open", "name": "telnet", "product": "", "version": "", "extrainfo": ""},
        80: {"state": "open", "name": "http", "product": "lighttpd", "version": "1.4", "extrainfo": ""},
        22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.2", "extrainfo": ""},
        9999: {"state": "closed", "name": "", "product": "", "version": "", "extrainfo": ""},
    }
    up = FakeHost(
        state="up", protocols={"tcp": tcp},
        osmatch=[{"name": "Linux 3.x", "accuracy": "90"},
                 {"name": "Linux 5.x", "accuracy": "96"}],
        addresses={"ipv4": "10.0.0.8", "mac": "AA:BB:CC:DD:EE:FF"},
        vendor={"AA:BB:CC:DD:EE:FF": "Raspberry Pi"},
        hostname="pi.local",
    )
    down = FakeHost(state="down", protocols={})
    fake = FakeScanner({"10.0.0.8": up, "10.0.0.9": down})
    monkeypatch.setattr(nmap, "PortScanner", lambda: fake)

    ctx = make_ctx(tmp_path, nmap_fast=False)   # force full for -sV behavior
    ReconNmap().run(ctx)

    # full-mode args, correct target
    call = fake.calls[0]
    assert "-sT" in call["arguments"] and "-sV" in call["arguments"]
    assert "--top-ports 1000" in call["arguments"]
    assert call["hosts"] == "10.0.0.0/24"

    # one asset for the up host only
    assets = ctx.store.assets()
    assert len(assets) == 1
    a = assets[0]
    assert a.ip == "10.0.0.8"
    assert a.alive is True
    assert a.open_ports == [22, 23, 80]          # closed port excluded, sorted
    assert a.os_guess == "Linux 5.x"             # highest accuracy wins
    assert a.mac == "AA:BB:CC:DD:EE:FF"
    assert a.vendor == "Raspberry Pi"
    assert a.hostname == "pi.local"

    # one finding per open service, with sensible severities
    svc = [f for f in ctx.store.findings() if f.type == "open_service"]
    assert len(svc) == 3
    sev = {f.title: f.severity for f in svc}
    assert sev["telnet (23/tcp) open"] == "high"
    assert sev["http (80/tcp) open"] == "low"
    assert sev["ssh (22/tcp) open"] == "info"

    ctx.store.run.compute_stats()
    stats = ctx.store.run.stats
    assert stats["hosts_up"] == 1
    assert stats["findings_by_severity"]["high"] == 1


def test_recon_forwards_hosts_and_ports_to_scratch(tmp_path, monkeypatch):
    """Discovered hosts + their open ports are published to the store scratch so a
    later chained step (Full Audit) can consume them without retyping."""
    tcp = {22: {"state": "open", "name": "ssh"}, 80: {"state": "open", "name": "http"},
           443: {"state": "closed", "name": "https"}}
    up = FakeHost(state="up", protocols={"tcp": tcp}, addresses={"ipv4": "10.0.0.8"})
    down = FakeHost(state="down", protocols={})
    fake = FakeScanner({"10.0.0.8": up, "10.0.0.9": down})
    monkeypatch.setattr(nmap, "PortScanner", lambda: fake)
    ctx = make_ctx(tmp_path, nmap_fast=True)
    ReconNmap().run(ctx)
    assert ctx.store.get("recon.hosts") == ["10.0.0.8"]          # only the up host
    assert ctx.store.get("recon.open_ports") == {"10.0.0.8": [22, 80]}  # open only


def test_recon_scratch_empty_when_no_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "PortScanner", lambda: FakeScanner({}))
    ctx = make_ctx(tmp_path)
    ReconNmap().run(ctx)
    assert ctx.store.get("recon.hosts") is None                 # nothing forwarded


def test_smbv1_is_high(tmp_path, monkeypatch):
    tcp = {445: {"state": "open", "name": "microsoft-ds", "product": "Samba",
                 "version": "", "extrainfo": "SMBv1"}}
    up = FakeHost(state="up", protocols={"tcp": tcp})
    fake = FakeScanner({"10.0.0.5": up})
    monkeypatch.setattr(nmap, "PortScanner", lambda: fake)
    ctx = make_ctx(tmp_path)
    ReconNmap().run(ctx)
    smb = [f for f in ctx.store.findings() if "445/tcp" in f.title]
    assert smb and smb[0].severity == "high"


# --- fast-mode scan: findings still emit without version detection --------
def test_findings_emit_without_version_in_fast_mode(tmp_path, monkeypatch):
    tcp = {
        23: {"state": "open", "name": "telnet", "product": "", "version": "", "extrainfo": ""},
        80: {"state": "open", "name": "http", "product": "", "version": "", "extrainfo": ""},
    }
    up = FakeHost(state="up", protocols={"tcp": tcp})
    fake = FakeScanner({"10.0.0.8": up})
    monkeypatch.setattr(nmap, "PortScanner", lambda: fake)

    ctx = make_ctx(tmp_path, nmap_fast=True)
    ReconNmap().run(ctx)

    assert "-sV" not in fake.calls[0]["arguments"]
    assert "--top-ports 100" in fake.calls[0]["arguments"]

    svc = {f.title: f for f in ctx.store.findings() if f.type == "open_service"}
    assert svc["telnet (23/tcp) open"].severity == "high"
    assert svc["http (80/tcp) open"].severity == "low"
    # evidence uses the port-table service name, with no version string
    assert svc["telnet (23/tcp) open"].evidence == "23/tcp telnet"
    assert ctx.store.assets()[0].open_ports == [23, 80]


# --- edge cases -----------------------------------------------------------
def test_no_target_is_graceful(tmp_path, monkeypatch):
    fake = FakeScanner({})
    monkeypatch.setattr(nmap, "PortScanner", lambda: fake)
    ctx = make_ctx(tmp_path, target="")
    ReconNmap().run(ctx)
    assert fake.calls == []                        # never scanned
    assert any("no target" in f.title.lower() for f in ctx.store.findings())


def test_scan_exception_is_recorded(tmp_path, monkeypatch):
    class Boom:
        def scan(self, **kw):
            raise RuntimeError("nmap boom")
    monkeypatch.setattr(nmap, "PortScanner", lambda: Boom())
    ctx = make_ctx(tmp_path)
    ReconNmap().run(ctx)
    errs = [f for f in ctx.store.findings() if f.type == "module_error"]
    assert errs and "boom" in errs[0].detail


# --- -Pn (skip host discovery) -------------------------------------------
def test_pn_absent_by_default(tmp_path):
    args, _ = ReconNmap()._build_args(make_ctx(tmp_path, nmap_fast=True), "10.0.0.0/24")
    assert "-Pn" not in args


def test_pn_adds_flag(tmp_path):
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=True, nmap_pn=True), "10.0.0.0/24")
    assert "-Pn" in args


def test_pn_composes_with_privileged_full(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args, _ = ReconNmap()._build_args(
        make_ctx(tmp_path, nmap_fast=False, nmap_privileged=True, nmap_pn=True), "10.0.0.5")
    assert "-Pn" in args and "-sS" in args and "-sV" in args and "-O" in args


# --- -Pn host accounting: alive must mean "responded", not "was scanned" ---
def _open_host(port=22, name="ssh"):
    return FakeHost(state="up", protocols={"tcp": {
        port: {"state": "open", "name": name, "product": "", "version": "", "extrainfo": ""}}})


def _dead_host(port=80):
    # -Pn forces state "up", but the address answered nothing (all filtered, no MAC)
    return FakeHost(state="up", protocols={"tcp": {
        port: {"state": "filtered", "name": "http", "product": "", "version": "", "extrainfo": ""}}})


def test_pn_drops_no_response_addresses(tmp_path, monkeypatch):
    hosts = {ip: _open_host() for ip in ("10.0.0.5", "10.0.0.6", "10.0.0.7")}
    for i in range(10, 30):                      # ~20 dead addresses forced "up" by -Pn
        hosts[f"10.0.0.{i}"] = _dead_host()
    hosts["10.0.0.40"] = FakeHost(state="up", protocols={"tcp": {}})   # nothing at all
    monkeypatch.setattr(nmap, "PortScanner", lambda: FakeScanner(hosts))

    ctx = make_ctx(tmp_path, nmap_pn=True, nmap_fast=True)
    ReconNmap().run(ctx)

    assets = ctx.store.assets()
    assert len(assets) == 3                      # not 24 — only responders kept
    assert {a.ip for a in assets} == {"10.0.0.5", "10.0.0.6", "10.0.0.7"}
    assert all(a.alive for a in assets)
    ctx.store.run.compute_stats()
    assert ctx.store.run.stats["hosts_up"] == 3


def test_pn_keeps_ping_silent_host_with_mac(tmp_path, monkeypatch):
    # ARP-replied (has MAC) but all ports filtered -> still alive under -Pn
    live = FakeHost(state="up",
                    protocols={"tcp": {80: {"state": "filtered", "name": "http",
                                            "product": "", "version": "", "extrainfo": ""}}},
                    addresses={"ipv4": "10.0.0.9", "mac": "DE:AD:BE:EF:00:09"},
                    vendor={"DE:AD:BE:EF:00:09": "Acme"})
    hosts = {"10.0.0.9": live, "10.0.0.50": FakeHost(state="up", protocols={"tcp": {}})}
    monkeypatch.setattr(nmap, "PortScanner", lambda: FakeScanner(hosts))

    ctx = make_ctx(tmp_path, nmap_pn=True, nmap_fast=True)
    ReconNmap().run(ctx)

    assets = ctx.store.assets()
    assert [a.ip for a in assets] == ["10.0.0.9"]     # MAC proves life; dead one dropped
    assert assets[0].mac == "DE:AD:BE:EF:00:09" and assets[0].vendor == "Acme"
    assert assets[0].open_ports == []


def test_mac_vendor_parsed_when_present(tmp_path, monkeypatch):
    host = FakeHost(state="up", protocols={"tcp": {
        22: {"state": "open", "name": "ssh", "product": "", "version": "", "extrainfo": ""}}},
        addresses={"ipv4": "10.0.0.8", "mac": "AA:BB:CC:00:00:08"},
        vendor={"AA:BB:CC:00:00:08": "Raspberry Pi"})
    monkeypatch.setattr(nmap, "PortScanner", lambda: FakeScanner({"10.0.0.8": host}))

    ctx = make_ctx(tmp_path, nmap_fast=True)          # default discovery
    ReconNmap().run(ctx)
    a = ctx.store.assets()[0]
    assert a.mac == "AA:BB:CC:00:00:08" and a.vendor == "Raspberry Pi"


def test_default_discovery_keeps_up_host_without_open_ports(tmp_path, monkeypatch):
    # No -Pn: nmap only reports up hosts, so a firewalled up host (all filtered,
    # no MAC) is authoritative and must NOT be dropped.
    monkeypatch.setattr(nmap, "PortScanner", lambda: FakeScanner({"10.0.0.2": _dead_host()}))
    ctx = make_ctx(tmp_path, nmap_fast=True)          # nmap_pn defaults False
    ReconNmap().run(ctx)
    assets = ctx.store.assets()
    assert [a.ip for a in assets] == ["10.0.0.2"]     # kept under default discovery
    assert assets[0].alive is True and assets[0].open_ports == []
