"""Pass 1 tests: scan launcher, run management, assets view, stat cards."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

import core.orchestrator as orch
from core.config import Config
from dashboard import assets as assets_mod
from dashboard import launcher, manage
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "capture_only: { steps: [blue.capture_tshark] }\n"
        "full_audit: { steps: [red.recon_nmap, blue.capture_tshark] }\n",
        encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def _csrf(c):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/login").text).group(1)


def login(c):
    csrf = _csrf(c)
    assert c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                  follow_redirects=False).status_code == 303
    return csrf


def seed_run(cfg, run_id, started="2026-01-01T00:00:00Z", assets=None, findings=None,
             reports=True):
    assets = assets or []
    findings = findings or []
    sev = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    run = {"schema_version": 1, "run_id": run_id, "workflow": "quick_recon",
           "target": "10.0.0.0/24", "started_at": started, "finished_at": started,
           "findings": findings, "assets": assets,
           "stats": {"hosts_up": len(assets), "assets_total": len(assets),
                     "findings_total": len(findings), "findings_by_severity": sev}}
    (cfg.results_dir / f"{run_id}.json").write_text(json.dumps(run), encoding="utf-8")
    if reports:
        for suf in (".html", ".md", ".launch.json", ".meta.json"):
            (cfg.reports_dir / f"{run_id}{suf}").write_text("x", encoding="utf-8")


# --- A) launcher ----------------------------------------------------------
def test_launcher_shows_workflow_appropriate_options(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    recon = c.get("/scan?workflow=quick_recon").text
    assert 'name="mode"' in recon and 'name="nmap_pn"' in recon and 'name="nmap_timing"' in recon
    assert 'name="capture_seconds"' not in recon
    cap = c.get("/scan?workflow=capture_only").text
    assert 'name="capture_seconds"' in cap and 'name="capture_filter"' in cap
    assert 'name="mode"' not in cap
    both = c.get("/scan?workflow=full_audit").text
    assert 'name="mode"' in both and 'name="capture_seconds"' in both


def test_launcher_passes_options_through(tmp_path, monkeypatch):
    _, _, app = make_env(tmp_path)
    captured = {}

    def fake_run(wf, target, config=None, authorized=False, events=None, run_id=None,
                 should_stop=None):
        captured["config"] = config

    monkeypatch.setattr(orch, "run_workflow", fake_run)
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/run/quick_recon", data={
        "target": "10.0.0.0/24", "csrf": csrf, "mode": "fast", "nmap_pn": "1",
        "nmap_timeout": "120", "nmap_top_ports": "50", "nmap_timing": "2",
        "nmap_privileged": "1"}, follow_redirects=False)
    assert r.status_code == 303
    cfg = captured["config"]
    assert cfg.nmap_fast is True and cfg.nmap_pn is True
    assert cfg.nmap_timeout == 120 and cfg.nmap_top_ports == 50
    assert cfg.nmap_timing == "2" and cfg.nmap_privileged is True


def test_launcher_rejects_invalid_options(tmp_path, monkeypatch):
    _, _, app = make_env(tmp_path)
    monkeypatch.setattr(orch, "run_workflow", lambda *a, **k: None)
    c = TestClient(app)
    csrf = login(c)
    assert c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf,
                  "nmap_timeout": "abc"}, follow_redirects=False).status_code == 400
    assert c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf,
                  "nmap_timing": "9"}, follow_redirects=False).status_code == 400
    assert c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf,
                  "nmap_timeout": "99999"}, follow_redirects=False).status_code == 400


# --- C) run management ----------------------------------------------------
def test_delete_removes_files_and_guards(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-del-1")
    c = TestClient(app)
    csrf = login(c)
    # unauth (fresh client) -> redirect to login
    assert TestClient(app).post("/run/run-del-1/delete", follow_redirects=False).status_code == 303
    # missing CSRF -> 403, nothing deleted
    assert c.post("/run/run-del-1/delete", follow_redirects=False).status_code == 403
    assert (cfg.results_dir / "run-del-1.json").exists()
    # valid -> files removed
    r = c.post("/run/run-del-1/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert not (cfg.results_dir / "run-del-1.json").exists()
    assert not (cfg.reports_dir / "run-del-1.html").exists()
    assert not (cfg.reports_dir / "run-del-1.launch.json").exists()


def test_delete_blocked_in_readonly(tmp_path):
    cfg, _, app = make_env(tmp_path, readonly=True)
    seed_run(cfg, "run-ro-1")
    c = TestClient(app)
    csrf = login(c)
    assert c.post("/run/run-ro-1/delete", data={"csrf": csrf},
                  follow_redirects=False).status_code == 403
    assert (cfg.results_dir / "run-ro-1.json").exists()      # untouched


def test_bulk_delete_partial_success(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-b1")
    seed_run(cfg, "run-b2")
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/runs/delete", data={"csrf": csrf, "run_ids": "run-b1,run-b2,run-missing"},
               follow_redirects=False)
    assert r.status_code == 303 and "deleted=2" in r.headers["location"] and "failed=1" in r.headers["location"]
    assert not (cfg.results_dir / "run-b1.json").exists()
    assert not (cfg.results_dir / "run-b2.json").exists()


def test_delete_rejects_path_traversal(tmp_path):
    cfg, _, app = make_env(tmp_path)
    # unit: traversal / absolute run_ids refused
    for bad in ("..", "../etc/passwd", "/etc/passwd", "a/../b"):
        assert not manage.valid_run_id(bad)
        with pytest.raises(ValueError):
            manage.delete_run(cfg, bad)
    assert manage.safe_path(cfg.results_dir, "../x.json") is None
    # endpoint: a traversing-but-routable run_id -> 400, not a traversal
    c = TestClient(app)
    csrf = login(c)
    assert c.post("/run/.../delete", data={"csrf": csrf},
                  follow_redirects=False).status_code == 400


def test_rerun_reconstructs_options(tmp_path, monkeypatch):
    _, _, app = make_env(tmp_path)
    monkeypatch.setattr(orch, "run_workflow", lambda *a, **k: None)
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/run/quick_recon", data={"target": "10.1.2.0/24", "csrf": csrf,
               "mode": "full", "nmap_timeout": "77"}, follow_redirects=False)
    run_id = r.headers["location"].rsplit("/run/", 1)[1].rsplit("/live", 1)[0]
    page = c.get(f"/scan?rerun={run_id}").text
    assert 'value="10.1.2.0/24"' in page                       # target prefilled
    assert 'value="full" selected' in page or 'value="full"  selected' in page
    assert 'value="77"' in page                                # timeout prefilled


# --- D) assets view -------------------------------------------------------
def test_assets_aggregate_and_dedupe(tmp_path):
    cfg, _, _ = make_env(tmp_path)
    mac = "aa:bb:cc:dd:ee:01"
    seed_run(cfg, "a1", "2026-01-01T00:00:00Z",
             assets=[{"ip": "10.0.0.5", "mac": mac, "vendor": "Acme", "open_ports": [22]}],
             findings=[{"target": "10.0.0.5", "severity": "high"}])
    seed_run(cfg, "a2", "2026-01-02T00:00:00Z",
             assets=[{"ip": "10.0.0.9", "mac": mac, "vendor": "Acme", "open_ports": [80]}],
             findings=[{"target": "10.0.0.9", "severity": "low"}])
    seed_run(cfg, "a3", "2026-01-03T00:00:00Z",
             assets=[{"ip": "10.0.0.20", "mac": "", "open_ports": [443]}])
    seed_run(cfg, "a4", "2026-01-04T00:00:00Z",
             assets=[{"ip": "10.0.0.20", "mac": "", "open_ports": [8080]}],
             findings=[{"target": "10.0.0.20", "severity": "medium"}])

    hosts = assets_mod.compute(cfg)
    assert len(hosts) == 2                                     # MAC-dedupe + IP-dedupe
    by_mac = next(h for h in hosts if h["mac"] == mac)
    assert sorted(by_mac["ips"]) == ["10.0.0.5", "10.0.0.9"] and by_mac["times_seen"] == 2
    assert by_mac["worst"] == "high"
    by_ip = next(h for h in hosts if h["key"] == "10.0.0.20")
    assert by_ip["times_seen"] == 2 and by_ip["open_ports"] == [443, 8080]
    assert by_ip["worst"] == "medium"


def test_assets_cache_invalidates_on_create_and_delete(tmp_path):
    cfg, _, _ = make_env(tmp_path)
    seed_run(cfg, "c1", assets=[{"ip": "10.0.0.5", "mac": "", "open_ports": [22]}])
    cache: dict = {}
    assert len(assets_mod.aggregate(cfg, cache)) == 1
    seed_run(cfg, "c2", assets=[{"ip": "10.0.0.6", "mac": "", "open_ports": [80]}])
    assert len(assets_mod.aggregate(cfg, cache)) == 2         # auto-invalidated on create
    (cfg.results_dir / "c2.json").unlink()
    assert len(assets_mod.aggregate(cfg, cache)) == 1         # auto-invalidated on delete


def test_assets_page_renders(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "p1", assets=[{"ip": "10.0.0.5", "mac": "aa:bb", "open_ports": [22]}])
    c = TestClient(app)
    login(c)
    body = c.get("/assets").text
    assert "10.0.0.5" in body and "/assets/aa:bb" in body


# --- B) stat cards --------------------------------------------------------
def test_overview_stat_cards(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "s1", "2026-01-01T00:00:00Z",
             assets=[{"ip": "10.0.0.5", "mac": "m1", "open_ports": [23]}],
             findings=[{"target": "10.0.0.5", "severity": "critical"}])
    seed_run(cfg, "s2", "2026-01-02T00:00:00Z",
             assets=[{"ip": "10.0.0.6", "mac": "m2", "open_ports": [80]}],
             findings=[{"target": "10.0.0.6", "severity": "low"}])
    c = TestClient(app)
    login(c)
    body = c.get("/").text
    assert '<div class="n">2</div><div class="l">Runs</div>' in body
    assert '<div class="n">2</div><div class="l">Hosts seen</div>' in body
    # worst grade is F (critical present); latest run (s2) has only a low -> B
    assert "Latest / worst grade" in body and ">F<" in body
