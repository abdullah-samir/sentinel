"""Dashboard tests (FastAPI TestClient, deterministic — no real scans/network)."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

import core.orchestrator as orch
from core.config import Config
from dashboard import cli as dcli
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False, with_pass=True):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "capture_only: { steps: [blue.capture_tshark] }\n"
        "full_audit: { steps: [red.recon_nmap, blue.capture_tshark] }\n",
        encoding="utf-8")
    dc = DashConfig(user="admin",
                    password_hash=hash_password(PW) if with_pass else "",
                    secret=SECRET, readonly=readonly,
                    path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def seed_run(cfg, run_id, workflow="quick_recon", target="10.0.0.0/24",
             findings=None, sev=None):
    findings = findings or []
    sevc = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    if sev:
        sevc.update(sev)
    run = {"schema_version": 1, "run_id": run_id, "workflow": workflow, "target": target,
           "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
           "findings": findings, "assets": [],
           "stats": {"hosts_up": 1, "assets_total": 1, "findings_total": len(findings),
                     "findings_by_severity": sevc}}
    (cfg.results_dir / f"{run_id}.json").write_text(json.dumps(run), encoding="utf-8")
    return run


def _csrf(client):
    r = client.get("/login")
    m = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text)
    assert m, "csrf token not found on login page"
    return m.group(1)


def login(client):
    csrf = _csrf(client)
    r = client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
    return csrf, r.cookies.get("sentinel_session")


# --- auth gating ----------------------------------------------------------
def test_protected_pages_redirect_to_login(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    for path in ("/", "/modules"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/api/runs").status_code == 401


def test_health_no_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and "version" in body
    assert "modules" in body and "runs" in body and "free_disk_bytes" in body


# --- login / password / rate limit ---------------------------------------
def test_wrong_password_then_rate_limited(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = _csrf(c)
    r = c.post("/login", data={"username": "admin", "password": "wrong", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 200 and "Invalid username or password" in r.text
    for _ in range(6):
        r = c.post("/login", data={"username": "admin", "password": "wrong", "csrf": csrf},
                   follow_redirects=False)
    assert "Too many failed attempts" in r.text


def test_password_is_scrypt_hash_not_plaintext(tmp_path):
    _, dc, _ = make_env(tmp_path)
    assert dc.password_hash.startswith("scrypt$")
    assert PW not in dc.password_hash


def test_setpass_writes_hash_only(tmp_path):
    cfg = Config(root=tmp_path)
    rc = dcli.setpass(core_config=cfg, _prompt=lambda prompt: "s3cretpass")
    assert rc == 0
    text = (tmp_path / "data" / "dashboard.json").read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["password_hash"].startswith("scrypt$")
    assert "s3cretpass" not in text


def test_session_persists_across_restart(tmp_path):
    cfg, dc, app1 = make_env(tmp_path)
    c1 = TestClient(app1)
    _, session = login(c1)
    assert session
    # "restart": a fresh app from the SAME (persisted) secret
    app2 = create_app(cfg, dc)
    c2 = TestClient(app2)
    c2.cookies.set("sentinel_session", session)
    r = c2.get("/", follow_redirects=False)
    assert r.status_code == 200


def test_dashboard_no_password_exits_cleanly(tmp_path, monkeypatch, capsys):
    called = {"run": False}
    monkeypatch.setattr(dcli.uvicorn, "run",
                        lambda *a, **k: called.__setitem__("run", True))
    monkeypatch.delenv("SENTINEL_DASH_SECRET", raising=False)
    cfg = Config(root=tmp_path)                         # no dashboard.json -> no hash
    rc = dcli.dashboard(core_config=cfg)
    assert rc == 1 and called["run"] is False
    assert "No admin password set" in capsys.readouterr().err


# --- pages after login ----------------------------------------------------
def test_overview_lists_runs(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-a", findings=[{"severity": "high"}], sev={"high": 1})
    seed_run(cfg, "run-b")
    c = TestClient(app)
    login(c)
    r = c.get("/")
    assert r.status_code == 200
    assert "run-a" in r.text and "run-b" in r.text


def test_run_view_is_iframe_not_inlined(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-x", findings=[{"severity": "low", "type": "open_service",
                                      "module": "red.recon_nmap", "target": "10.0.0.5",
                                      "title": "http (80/tcp) open", "evidence": "80/tcp http"}],
             sev={"low": 1})
    c = TestClient(app)
    login(c)
    wrapper = c.get("/run/run-x")
    assert wrapper.status_code == 200
    assert 'src="/run/run-x/report"' in wrapper.text and "<iframe" in wrapper.text
    assert "Risk score =" not in wrapper.text          # report NOT inlined into wrapper
    report = c.get("/run/run-x/report")
    assert report.status_code == 200
    assert "Risk score =" in report.text               # standalone report served here


def test_api_runs_json(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-j")
    c = TestClient(app)
    login(c)
    data = c.get("/api/runs").json()
    assert "runs" in data and any(r["run_id"] == "run-j" for r in data["runs"])


def test_modules_page_lists_modules(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    r = c.get("/modules")
    assert r.status_code == 200
    assert "red.recon_nmap" in r.text and "blue.capture_tshark" in r.text


def test_malformed_result_file_does_not_crash_overview(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "good-run")
    (cfg.results_dir / "broken.json").write_text("{not valid json", encoding="utf-8")
    c = TestClient(app)
    login(c)
    r = c.get("/")
    assert r.status_code == 200 and "good-run" in r.text


# --- triggering scans -----------------------------------------------------
def test_trigger_calls_orchestrator_and_needs_csrf(tmp_path, monkeypatch):
    cfg, _, app = make_env(tmp_path)
    calls = []
    monkeypatch.setattr(orch, "run_workflow",
                        lambda *a, **k: calls.append((a[0], a[1], k.get("authorized"))))
    c = TestClient(app)
    csrf, _ = login(c)

    # missing CSRF -> rejected, orchestrator not called
    r = c.post("/run/quick_recon", data={"target": "10.0.0.0/24"}, follow_redirects=False)
    assert r.status_code == 403 and not calls

    # valid CSRF -> accepted, orchestrator called (background task runs in TestClient)
    r = c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 303
    assert calls and calls[0][0] == "quick_recon"
    assert calls[0][2] is False          # dashboard never bypasses the offensive gate


def test_second_concurrent_trigger_rejected(tmp_path, monkeypatch):
    cfg, _, app = make_env(tmp_path)
    monkeypatch.setattr(orch, "run_workflow", lambda *a, **k: None)
    c = TestClient(app)
    csrf, _ = login(c)
    app.state.run_state.try_start("quick_recon", "10.0.0.0/24")   # simulate a run in progress
    r = c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 409 and "in progress" in r.text.lower()


def test_readonly_blocks_trigger_endpoint(tmp_path, monkeypatch):
    cfg, _, app = make_env(tmp_path, readonly=True)
    called = {"n": 0}
    monkeypatch.setattr(orch, "run_workflow", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    c = TestClient(app)
    csrf, _ = login(c)
    r = c.post("/run/quick_recon", data={"target": "10.0.0.0/24", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 403 and called["n"] == 0


def test_invalid_target_rejected(tmp_path, monkeypatch):
    cfg, _, app = make_env(tmp_path)
    monkeypatch.setattr(orch, "run_workflow", lambda *a, **k: None)
    c = TestClient(app)
    csrf, _ = login(c)
    r = c.post("/run/quick_recon", data={"target": "999.999.999.999", "csrf": csrf},
               follow_redirects=False)
    assert r.status_code == 400
