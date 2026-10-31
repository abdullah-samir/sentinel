# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Backward compatibility: result JSONs written BEFORE the enriched Asset fields
existed must still load and render. Readers must default-handle the missing
fields (ports, device_type, os_accuracy, scripts, tls, http) without error."""
from __future__ import annotations

import json
from pathlib import Path

from core.config import Config
from dashboard import assets as assets_mod
from reporting import report_engine

# An asset exactly as older Sentinel wrote it — no ports/device_type/os_accuracy/
# scripts/tls/http keys at all.
OLD_RUN = {
    "schema_version": 1,
    "run_id": "20260101T000000_quick_recon_old123",
    "workflow": "quick_recon", "target": "10.0.0.0/24",
    "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
    "findings": [{"finding_id": "f-0001", "module": "red.recon_nmap",
                  "type": "open_service", "severity": "high", "target": "10.0.0.8",
                  "title": "telnet (23/tcp) open", "detail": "cleartext",
                  "evidence": "23/tcp", "timestamp": "2026-01-01T00:00:30Z",
                  "tags": ["network"]}],
    "assets": [{"ip": "10.0.0.8", "alive": True, "mac": "", "vendor": "",
                "hostname": "", "open_ports": [23, 80], "os_guess": "Linux"}],
    "stats": {"hosts_up": 1, "assets_total": 1, "findings_total": 1,
              "findings_by_severity": {"info": 0, "low": 0, "medium": 0,
                                       "high": 1, "critical": 0}},
}


def _seed(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    (cfg.results_dir / f"{OLD_RUN['run_id']}.json").write_text(
        json.dumps(OLD_RUN), encoding="utf-8")
    return cfg


def test_old_run_renders_report_without_error(tmp_path):
    cfg = _seed(tmp_path)
    out, context = report_engine.generate_report(OLD_RUN["run_id"], cfg)
    html = Path(out["html"]).read_text(encoding="utf-8")
    assert "10.0.0.8" in html                       # rendered, missing fields tolerated


def test_old_run_aggregates_without_error(tmp_path):
    cfg = _seed(tmp_path)
    data = assets_mod.compute(cfg)
    host = next(h for h in data if h["ip"] == "10.0.0.8")
    assert host["open_ports"] == [23, 80]


def test_old_run_loads_raw(tmp_path):
    cfg = _seed(tmp_path)
    run = report_engine.load_run(OLD_RUN["run_id"], cfg)
    a = run["assets"][0]
    # the new fields are simply absent; readers use .get(...) defaults
    assert a.get("device_type", "") == "" and a.get("ports", []) == []
    assert a.get("os_accuracy") is None
