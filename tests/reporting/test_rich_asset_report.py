# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Phase 2 Commit 2: the report renders enriched per-asset detail (ports with
service/version/banner, OS guess + accuracy, device-type + confidence +
reasoning, hostname/MAC/vendor, TLS/HTTP, collapsible NSE scripts)."""
from __future__ import annotations

import json
from pathlib import Path

from core.config import Config
from reporting import report_engine

RICH_RUN = {
    "schema_version": 1, "run_id": "20260101T000000_quick_recon_rich01",
    "workflow": "quick_recon", "target": "10.0.0.0/24",
    "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
    "findings": [{"finding_id": "f-0001", "module": "red.recon_nmap",
                  "type": "open_service", "severity": "info", "target": "10.0.0.8",
                  "title": "ssh (22/tcp) open", "detail": "", "evidence": "22/tcp",
                  "timestamp": "2026-01-01T00:00:30Z", "tags": ["network"]}],
    "assets": [{
        "ip": "10.0.0.8", "alive": True, "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "Raspberry Pi", "hostname": "pi.local", "open_ports": [22, 443],
        "os_guess": "Linux 5.x", "os_accuracy": 96,
        "device_type": "Single-board computer (Raspberry Pi)",
        "device_confidence": "medium",
        "device_reasoning": "MAC vendor Raspberry Pi (heuristic)",
        "ports": [
            {"port": 22, "proto": "tcp", "state": "open", "service": "ssh",
             "product": "OpenSSH", "version": "9.2", "extrainfo": "", "banner": "OpenSSH 9.2"},
            {"port": 443, "proto": "tcp", "state": "open", "service": "https",
             "product": "nginx", "version": "1.24", "extrainfo": "", "banner": "nginx 1.24"}],
        "scripts": {"ssl-cert (443/tcp)": "Subject: CN=pi.local\nIssuer: CN=CA",
                    "http-title (443/tcp)": "Pi Dashboard"},
        "tls": {"subject": "CN=pi.local"},
        "http": {"server": "nginx", "title": "Pi Dashboard"},
    }],
    "stats": {"hosts_up": 1, "assets_total": 1, "findings_total": 1,
              "findings_by_severity": {"info": 1, "low": 0, "medium": 0,
                                       "high": 0, "critical": 0}},
}


def _render(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    (cfg.results_dir / f"{RICH_RUN['run_id']}.json").write_text(
        json.dumps(RICH_RUN), encoding="utf-8")
    out, _ = report_engine.generate_report(RICH_RUN["run_id"], cfg)
    return Path(out["html"]).read_text(encoding="utf-8")


def test_report_shows_device_type_with_confidence_and_reasoning(tmp_path):
    html = _render(tmp_path)
    assert "Single-board computer (Raspberry Pi)" in html      # device type (header + detail)
    assert "medium confidence" in html
    assert "MAC vendor Raspberry Pi (heuristic)" in html       # the "why"


def test_report_shows_os_accuracy_and_identity(tmp_path):
    html = _render(tmp_path)
    assert "Linux 5.x" in html and "96% accuracy" in html
    assert "pi.local" in html and "AA:BB:CC:DD:EE:FF" in html


def test_report_shows_ports_with_service_version_banner(tmp_path):
    html = _render(tmp_path)
    assert "Host details" in html                              # expandable detail
    assert "OpenSSH 9.2" in html and "nginx 1.24" in html      # banners
    assert "22/tcp" in html and "443/tcp" in html


def test_report_shows_collapsible_nse_and_tls_http(tmp_path):
    html = _render(tmp_path)
    assert "NSE scripts (2)" in html
    assert "ssl-cert (443/tcp)" in html and "CN=pi.local" in html   # collapsible script
    assert "<details" in html                                       # per-script collapse
    assert "Pi Dashboard" in html                                   # HTTP title


def test_report_collapsed_header_is_clean(tmp_path):
    html = _render(tmp_path)
    # collapsed row carries IP, alive, port count, device-type, grade
    assert "10.0.0.8" in html and "alive" in html and "2 ports" in html
