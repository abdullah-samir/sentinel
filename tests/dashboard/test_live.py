"""Dashboard Pass B tests — addressable live run view, SSE, ETA, overview sort."""
from __future__ import annotations

import asyncio
import json
import re
import time

from fastapi.testclient import TestClient

from core.config import Config
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig
from dashboard.live import LiveRun

PW = "hunter2-correct-horse"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=False, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login(client):
    r = client.get("/login")
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.text).group(1)
    r = client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                    follow_redirects=False)
    assert r.status_code == 303


def seed_run(cfg, run_id, workflow="quick_recon", target="10.0.0.0/24",
             started="2026-01-01T00:00:00Z", hosts=1, findings=None):
    findings = findings or []
    sevc = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        sevc[f["severity"]] = sevc.get(f["severity"], 0) + 1
    run = {"schema_version": 1, "run_id": run_id, "workflow": workflow, "target": target,
           "started_at": started, "finished_at": started, "findings": findings, "assets": [],
           "stats": {"hosts_up": hosts, "assets_total": hosts, "findings_total": len(findings),
                     "findings_by_severity": sevc}}
    (cfg.results_dir / f"{run_id}.json").write_text(json.dumps(run), encoding="utf-8")


def _seed_active_live(app, run_id="run-active-1"):
    live = app.state.run_state.try_start("quick_recon", "10.0.0.0/24", run_id)
    live.on_event("run.start", {"run_id": run_id, "steps_total": 2})
    live.on_event("step.start", {"name": "red.recon_nmap", "index": 1, "total": 2})
    return live               # still active, not done


def _seed_done_live(app, run_id="run-live-1"):
    live = app.state.run_state.try_start("quick_recon", "10.0.0.0/24", run_id)
    live.on_event("run.start", {"run_id": run_id, "steps_total": 1})
    live.on_event("step.start", {"name": "red.recon_nmap", "index": 1, "total": 1})
    live.on_event("step.done", {"name": "red.recon_nmap", "index": 1, "total": 1,
                                "findings_by_severity": {"high": 1, "info": 2}, "assets": 3})
    live.on_event("run.done", {"run_id": run_id,
                               "findings_by_severity": {"high": 1, "info": 2}, "assets": 3})
    app.state.run_state.finish()
    return live


def _row_order(text):
    seen = []
    for m in re.findall(r'href="/run/(run-[a-z]+)"', text):
        if m not in seen:
            seen.append(m)           # first occurrence per run = its row position
    return seen


# --- ETA (honest) ---------------------------------------------------------
def test_eta_estimating_then_positive():
    live = LiveRun("r", "quick_recon", "10.0.0.0/24")
    assert live.eta()["state"] == "estimating"
    live.started_at = time.time() - 10
    live.steps_total, live.steps_done = 2, 1
    e = live.eta()
    assert e["state"] == "ok" and e["remaining"] > 0


def test_eta_prefers_host_fraction():
    live = LiveRun("r", "quick_recon", "10.0.0.0/24")
    live.started_at = time.time() - 10
    live.steps_total, live.steps_done = 1, 0
    live.hosts_total, live.hosts_done = 10, 5
    assert abs(live.eta()["fraction"] - 0.5) < 1e-6


# --- live state updates ---------------------------------------------------
def test_live_state_updates_on_events():
    live = LiveRun("r", "quick_recon", "10.0.0.0/24")
    live.on_event("run.start", {"run_id": "r", "steps_total": 2})
    assert live.steps_total == 2
    live.on_event("step.done", {"name": "x", "index": 1, "total": 2,
                                "findings_by_severity": {"high": 1}, "assets": 3})
    assert live.steps_done == 1 and live.findings["high"] == 1 and live.hosts_done == 3
    live.on_event("run.done", {"findings_by_severity": {"high": 2}, "assets": 3})
    assert live.done is True and live.findings["high"] == 2


def test_live_notifies_listener():
    live = LiveRun("r", "quick_recon", "t")
    loop = asyncio.new_event_loop()
    q: asyncio.Queue = asyncio.Queue()
    live.add_listener(loop, q)
    live.on_event("step.done", {"name": "x", "index": 1, "total": 1})
    loop.call_soon(loop.stop)
    loop.run_forever()
    assert not q.empty()
    evt, data = q.get_nowait()
    assert evt == "step.done" and "_seq" in data
    loop.close()


# --- SSE endpoint ---------------------------------------------------------
def test_events_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    assert TestClient(app).get("/events/anything").status_code == 401


def test_events_streams_and_terminates_on_done(tmp_path):
    _, _, app = make_env(tmp_path)
    _seed_done_live(app, "run-live-1")
    c = TestClient(app)
    login(c)
    body = c.get("/events/run-live-1").text
    assert "event: snapshot" in body and "event: done" in body
    assert "run-live-1" in body and "step.done" in body and '"high": 1' in body


def test_events_scoped_no_leak(tmp_path):
    _, _, app = make_env(tmp_path)
    _seed_done_live(app, "run-A")
    c = TestClient(app)
    login(c)
    body = c.get("/events/run-B").text
    assert "run-B" in body and '"active": false' in body and "run-A" not in body


# --- addressable / resumable live page ------------------------------------
def test_live_page_active_run(tmp_path):
    _, _, app = make_env(tmp_path)
    _seed_active_live(app, "run-active-1")
    c = TestClient(app)
    login(c)
    r = c.get("/run/run-active-1/live")
    assert r.status_code == 200
    assert "run-active-1" in r.text and "EventSource" in r.text and "estimating" in r.text


def test_live_page_redirects_to_report_when_finished(tmp_path):
    cfg, _, app = make_env(tmp_path)
    seed_run(cfg, "run-done-x")           # result exists, no active run
    c = TestClient(app)
    login(c)
    r = c.get("/run/run-done-x/live", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/run/run-done-x"


def test_live_page_unknown_404(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    assert c.get("/run/nope-xyz/live", follow_redirects=False).status_code == 404


def test_live_page_requires_auth(tmp_path):
    _, _, app = make_env(tmp_path)
    r = TestClient(app).get("/run/x/live", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_overview_shows_running_badge(tmp_path):
    _, _, app = make_env(tmp_path)
    _seed_active_live(app, "run-active-1")
    c = TestClient(app)
    login(c)
    body = c.get("/").text
    assert "running" in body and "/run/run-active-1/live" in body


# --- overview sorting (server-side ?sort=) --------------------------------
def _seed_three(cfg):
    seed_run(cfg, "run-alpha", workflow="alpha", target="10.0.0.1",
             started="2026-01-01T00:00:00Z", hosts=5, findings=[])
    seed_run(cfg, "run-beta", workflow="beta", target="10.0.0.2",
             started="2026-01-02T00:00:00Z", hosts=1, findings=[{"severity": "critical"}])
    seed_run(cfg, "run-gamma", workflow="gamma", target="10.0.0.3",
             started="2026-01-03T00:00:00Z", hosts=3,
             findings=[{"severity": "low"}, {"severity": "low"}])


def test_overview_sort_default_is_date_desc(tmp_path):
    cfg, _, app = make_env(tmp_path)
    _seed_three(cfg)
    c = TestClient(app)
    login(c)
    assert _row_order(c.get("/").text) == ["run-gamma", "run-beta", "run-alpha"]


def test_overview_sort_by_hosts_and_findings_and_grade(tmp_path):
    cfg, _, app = make_env(tmp_path)
    _seed_three(cfg)
    c = TestClient(app)
    login(c)
    assert _row_order(c.get("/?sort=hosts&dir=desc").text) == ["run-alpha", "run-gamma", "run-beta"]
    assert _row_order(c.get("/?sort=findings&dir=desc").text) == ["run-gamma", "run-beta", "run-alpha"]
    # grade asc: A (0 findings) < B (score 2) < F (critical)
    assert _row_order(c.get("/?sort=grade&dir=asc").text) == ["run-alpha", "run-gamma", "run-beta"]
    assert _row_order(c.get("/?sort=workflow&dir=asc").text) == ["run-alpha", "run-beta", "run-gamma"]


def test_overview_empty_state_not_broken_by_sort(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    r = c.get("/?sort=hosts&dir=desc")
    assert r.status_code == 200 and "No runs yet" in r.text
