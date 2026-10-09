"""Tests for reporting Pass 2: safe JS data embedding, run diffing, and the
newest-first history index. No real network or browser is involved."""
from __future__ import annotations

import json
import re

from core.config import Config
from reporting import history
from reporting import report_engine as eng


def mkrun(run_id, started, findings, workflow="full_audit", target="10.0.0.0/24"):
    bys = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        bys[f["severity"]] = bys.get(f["severity"], 0) + 1
    return {
        "schema_version": 1, "run_id": run_id, "workflow": workflow, "target": target,
        "started_at": started, "finished_at": started,
        "findings": findings, "assets": [],
        "stats": {"hosts_up": 0, "assets_total": 0, "findings_total": len(findings),
                  "findings_by_severity": bys},
    }


def svc(sev, target, port, module="red.recon_nmap", evidence=None):
    return {
        "finding_id": f"f-{target}-{port}", "module": module, "type": "open_service",
        "severity": sev, "target": target, "title": f"svc ({port}/tcp) open", "detail": "",
        "evidence": evidence if evidence is not None else f"{port}/tcp svc", "tags": [],
    }


# --- safe JS embedding ----------------------------------------------------
def test_script_evidence_safely_embedded():
    run = mkrun("r-xss", "2026-01-01T00:00:00Z", [{
        "finding_id": "f-1", "module": "m", "type": "open_service", "severity": "high",
        "target": "10.0.0.1", "title": "t", "detail": "d",
        "evidence": "before </script><script>alert(1)</script> after", "tags": [],
    }])
    html = eng.render_html(eng.build_context(run))

    m = re.search(r'<script[^>]*id="sentinel-data"[^>]*>(.*?)</script>', html, re.S)
    assert m, "data blob script tag not found"
    blob = m.group(1)
    assert "</script>" not in blob                 # cannot break out of the <script>
    data = json.loads(blob)                         # still valid JSON
    assert any("</script>" in f["evidence"] for f in data["findings"])  # round-trips


# --- diff math ------------------------------------------------------------
def test_finding_key_ignores_version_evidence():
    a = svc("medium", "10.0.0.7", 445, evidence="445/tcp microsoft-ds Samba 4.1")
    b = svc("medium", "10.0.0.7", 445, evidence="445/tcp microsoft-ds Samba 4.9")
    assert history.finding_key(a) == history.finding_key(b)


def test_diff_new_resolved_and_grade_delta():
    prev = mkrun("prev", "2026-01-01T00:00:00Z", [
        svc("critical", "10.0.0.5", 23),                                # telnet
        svc("medium", "10.0.0.7", 445, evidence="445/tcp microsoft-ds Samba 4.1"),
    ])
    cur = mkrun("cur", "2026-01-02T00:00:00Z", [
        svc("medium", "10.0.0.7", 445, evidence="445/tcp microsoft-ds Samba 4.9"),  # unchanged
        svc("low", "10.0.0.6", 80),                                     # new
        # telnet (10.0.0.5:23) is gone -> resolved
    ])
    d = history.diff_runs(cur, prev)
    assert d["new"] == 1          # only the http low finding
    assert d["resolved"] == 1     # only the telnet critical finding
    # the smb finding changed version/evidence only -> NOT counted as new or resolved
    assert d["new"] + d["resolved"] == 2
    # grade delta: prev 16+4=20 -> F ; cur 4+1=5 -> C
    assert d["grade_from"] == "F"
    assert d["grade_to"] == "C"
    assert d["grade_changed"] is True


def test_diff_baseline_when_no_previous():
    d = history.diff_runs(mkrun("solo", "2026-01-01T00:00:00Z", [svc("low", "10.0.0.6", 80)]), None)
    assert d["has_previous"] is False
    assert d["new"] == 0 and d["resolved"] == 0
    assert d["grade_from"] is None and d["grade_to"] == "B"


# --- history index --------------------------------------------------------
def test_index_lists_runs_newest_first(tmp_path):
    cfg = Config(root=tmp_path)
    res = cfg.results_dir
    res.mkdir(parents=True)
    plan = [
        ("run_a", "2026-01-01T00:00:00Z", [svc("low", "10.0.0.6", 80)]),
        ("run_b", "2026-01-02T00:00:00Z", [svc("low", "10.0.0.6", 80), svc("high", "10.0.0.5", 23)]),
        ("run_c", "2026-01-03T00:00:00Z", [svc("high", "10.0.0.5", 23)]),
    ]
    for rid, started, finds in plan:
        (res / f"{rid}.json").write_text(json.dumps(mkrun(rid, started, finds)), encoding="utf-8")

    index_path, rows = eng.generate_index(cfg)
    assert [r["run_id"] for r in rows] == ["run_c", "run_b", "run_a"]    # newest first

    html = index_path.read_text(encoding="utf-8")
    assert html.index("run_c.html") < html.index("run_a.html")          # newest rendered first

    # newest (run_c) diffs against run_b: http (10.0.0.6:80) resolved, nothing new
    c_diff = rows[0]["diff"]
    assert c_diff["has_previous"] is True
    assert c_diff["resolved"] == 1 and c_diff["new"] == 0
    # oldest (run_a) is the baseline
    assert rows[-1]["diff"]["has_previous"] is False


def test_previous_run_matches_same_workflow_and_target(tmp_path):
    cfg = Config(root=tmp_path)
    res = cfg.results_dir
    res.mkdir(parents=True)
    runs = [
        mkrun("w1-a", "2026-01-01T00:00:00Z", [], workflow="quick_recon", target="10.0.0.0/24"),
        mkrun("w2-a", "2026-01-02T00:00:00Z", [], workflow="full_audit", target="10.0.0.0/24"),
        mkrun("w1-b", "2026-01-03T00:00:00Z", [], workflow="quick_recon", target="10.0.0.0/24"),
        mkrun("w1-other", "2026-01-02T12:00:00Z", [], workflow="quick_recon", target="10.9.9.0/24"),
    ]
    for r in runs:
        (res / f"{r['run_id']}.json").write_text(json.dumps(r), encoding="utf-8")

    cur = next(r for r in runs if r["run_id"] == "w1-b")
    prev = history.previous_run(cur, cfg)
    assert prev is not None and prev["run_id"] == "w1-a"   # same wf+target, not w2-a/other
