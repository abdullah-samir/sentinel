"""Tests for the reporting module (Pass 1): rendering, grading, grouping,
escaping, and graceful PDF fallback. No real WeasyPrint is exercised."""
from __future__ import annotations

import json
import os
import sys

import pytest

from core.config import Config
from reporting import report_engine as eng
from reporting import risk


# A rich run with every severity incl. high + critical, and an XSS attempt in
# device-controlled fields (title + evidence).
RICH = {
    "schema_version": 1,
    "run_id": "20260101T000000_full_audit_abc123",
    "workflow": "full_audit",
    "target": "10.0.0.0/24",
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:02:30Z",
    "findings": [
        {"finding_id": "f-1", "module": "red.recon_nmap", "type": "open_service",
         "severity": "critical", "target": "10.0.0.5",
         "title": "<script>alert(1)</script> telnet (23/tcp) open",
         "detail": "cleartext", "evidence": "23/tcp telnet <script>alert('x')</script>",
         "timestamp": "2026-01-01T00:01:00Z", "tags": ["network", "telnet"]},
        {"finding_id": "f-2", "module": "red.recon_nmap", "type": "open_service",
         "severity": "high", "target": "10.0.0.5", "title": "ftp (21/tcp) open",
         "detail": "cleartext", "evidence": "21/tcp ftp",
         "timestamp": "2026-01-01T00:01:01Z", "tags": ["network", "ftp"]},
        {"finding_id": "f-3", "module": "red.recon_nmap", "type": "open_service",
         "severity": "low", "target": "10.0.0.6", "title": "http (80/tcp) open",
         "detail": "no TLS", "evidence": "80/tcp http",
         "timestamp": "2026-01-01T00:01:02Z", "tags": ["network", "http"]},
        {"finding_id": "f-4", "module": "red.recon_nmap", "type": "open_service",
         "severity": "info", "target": "10.0.0.6", "title": "ssh (22/tcp) open",
         "detail": "", "evidence": "22/tcp ssh",
         "timestamp": "2026-01-01T00:01:03Z", "tags": ["network", "ssh"]},
    ],
    "assets": [
        {"ip": "10.0.0.5", "alive": True, "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme",
         "hostname": "h5", "open_ports": [21, 23], "os_guess": "Linux"},
        {"ip": "10.0.0.6", "alive": True, "mac": "", "vendor": "", "hostname": "",
         "open_ports": [22, 80], "os_guess": ""},
    ],
    "stats": {"hosts_up": 2, "assets_total": 2, "findings_total": 4,
              "findings_by_severity": {"info": 1, "low": 1, "medium": 0,
                                       "high": 1, "critical": 1}},
}

EMPTY = {
    "schema_version": 1, "run_id": "20260101T010000_quick_recon_empty0",
    "workflow": "quick_recon", "target": "10.0.0.0/24",
    "started_at": "2026-01-01T01:00:00Z", "finished_at": "2026-01-01T01:00:01Z",
    "findings": [], "assets": [],
    "stats": {"hosts_up": 0, "assets_total": 0, "findings_total": 0,
              "findings_by_severity": {"info": 0, "low": 0, "medium": 0,
                                       "high": 0, "critical": 0}},
}


# --- risk scoring ---------------------------------------------------------
def test_risk_weights_and_grades():
    assert risk.score(RICH["findings"]) == 16 + 8 + 1 + 0        # = 25
    assert risk.grade_for_score(0) == "A"
    assert risk.grade_for_score(3) == "B"
    assert risk.grade_for_score(4) == "C"
    assert risk.grade_for_score(8) == "D"
    assert risk.grade_for_score(16) == "F"
    assert risk.grade_for_score(25) == "F"


# --- rich render: grade, grouping, ordering, remediation, escaping --------
def test_rich_context_grading_and_grouping():
    ctx = eng.build_context(RICH)
    assert ctx["overall"]["grade"] == "F"            # score 25
    assert ctx["overall"]["score"] == 25

    # grouped by host, worst-first
    targets = [h["target"] for h in ctx["hosts"]]
    assert targets == ["10.0.0.5", "10.0.0.6"]
    h5 = ctx["hosts"][0]
    assert h5["grade"] == "F" and h5["score"] == 24
    assert [f["severity"] for f in h5["findings"]] == ["critical", "high"]  # sorted
    assert ctx["hosts"][1]["grade"] == "B"           # low+info -> 1

    # all findings sorted critical -> info
    assert [f["severity"] for f in ctx["all_findings"]] == \
        ["critical", "high", "low", "info"]

    # inventory carries per-host grade
    inv = {a["ip"]: a for a in ctx["inventory"]}
    assert inv["10.0.0.5"]["grade"] == "F"
    assert inv["10.0.0.6"]["grade"] == "B"


def test_rich_html_render_and_escaping():
    html = eng.render_html(eng.build_context(RICH))

    # grade rendered in hero, hosts grouped into sections
    assert 'data-grade="F"' in html
    assert 'data-host="10.0.0.5"' in html and 'data-host="10.0.0.6"' in html

    # remediation text present
    assert "Disable Telnet" in html
    assert "SFTP" in html                             # ftp remediation

    # formula in footer
    assert "Risk score =" in html

    # attacker payloads from title/evidence never appear raw in the document...
    assert "<script>alert(1)</script>" not in html
    assert "<script>alert('x')</script>" not in html
    # ...and the visible (HTML body) copies are entity-escaped
    assert "&lt;script&gt;" in html


def test_rich_markdown_render():
    md = eng.render_markdown(eng.build_context(RICH))
    assert md.startswith("# Sentinel report")
    assert "Overall grade: F" in md
    assert "Disable Telnet" in md
    assert "| Severity | Host | Title | Module | Evidence |" in md


# --- empty states ---------------------------------------------------------
def test_empty_run_renders_cleanly():
    ctx = eng.build_context(EMPTY)
    assert ctx["overall"]["grade"] == "A"
    assert ctx["empty"]["no_findings"] and ctx["empty"]["no_hosts_up"]

    html = eng.render_html(ctx)
    assert 'data-grade="A"' in html
    assert "No findings were recorded" in html
    assert "No hosts to report" in html
    assert "No hosts were found up" in html


def test_all_skipped_banner():
    run = dict(EMPTY)
    run["findings"] = [
        {"finding_id": "f-1", "module": "ml.detector_template", "type": "skipped",
         "severity": "info", "target": "10.0.0.0/24", "title": "ml skipped",
         "detail": "skipped: no model", "evidence": "", "timestamp": "x", "tags": []},
    ]
    run["stats"] = {**EMPTY["stats"], "findings_total": 1,
                    "findings_by_severity": {**EMPTY["stats"]["findings_by_severity"],
                                             "info": 1}}
    ctx = eng.build_context(run)
    assert ctx["empty"]["all_skipped"] is True
    html = eng.render_html(ctx)
    assert "All modules were skipped" in html


# --- file generation + graceful PDF fallback ------------------------------
def test_generate_report_writes_files_and_skips_pdf(tmp_path, monkeypatch):
    # Force WeasyPrint import to fail so --pdf is a clean no-op (never fatal).
    monkeypatch.setitem(sys.modules, "weasyprint", None)

    cfg = Config(root=tmp_path)
    results = cfg.results_dir
    results.mkdir(parents=True)
    (results / f"{RICH['run_id']}.json").write_text(json.dumps(RICH), encoding="utf-8")

    out, ctx = eng.generate_report(RICH["run_id"], cfg, want_pdf=True, want_md=True)
    assert out["html"].exists()
    assert out["md"].exists()
    assert "pdf" not in out                           # gracefully skipped, no raise
    assert ctx["overall"]["grade"] == "F"
    assert 'data-grade="F"' in out["html"].read_text(encoding="utf-8")


def test_latest_resolves_newest_run(tmp_path):
    cfg = Config(root=tmp_path)
    results = cfg.results_dir
    results.mkdir(parents=True)
    (results / "a.json").write_text(json.dumps({**EMPTY, "run_id": "a"}), encoding="utf-8")
    (results / "b.json").write_text(json.dumps({**EMPTY, "run_id": "b"}), encoding="utf-8")
    os.utime(results / "a.json", (1000, 1000))
    os.utime(results / "b.json", (2000, 2000))
    assert eng.load_run("latest", cfg)["run_id"] == "b"


def test_missing_run_raises(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        eng.load_run("nope", cfg)
