"""Global live indicator, stop-active-scan, and the stop/finish interface
release. No real scans run — the orchestrator is stubbed where needed."""
from __future__ import annotations

import re
import threading

from fastapi.testclient import TestClient

from core import orchestrator as orch
from core.config import Config
from core.state import get_interface_registry
from dashboard import app as app_mod
from dashboard.app import create_app
from dashboard.auth import hash_password
from dashboard.config import DashConfig
from dashboard.state import RunState

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text("wifi_scan: { steps: [red.wifi_scan] }\n",
                                       encoding="utf-8")
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def login_csrf(client):
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/login").text).group(1)
    client.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                follow_redirects=False)
    return csrf


# --- global live indicator (shared base layout, every page) ----------------
def test_global_indicator_shows_active_run_on_any_page(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.run_state.try_start("full_audit", "10.0.0.0/24", "run-ind-1")
    c = TestClient(app)
    login_csrf(c)
    for path in ("/", "/settings", "/modules"):          # pages that don't pass active
        body = c.get(path).text
        assert "Scan running" in body, path
        assert "full_audit" in body and "10.0.0.0/24" in body
        assert "/run/run-ind-1/live" in body             # link to the live view
        assert "/scan/stop" in body                      # stop control present


def test_global_indicator_absent_when_idle(tmp_path):
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    login_csrf(c)
    assert "Scan running" not in c.get("/").text          # unobtrusive when idle


def test_global_indicator_reflects_shared_runstate(tmp_path):
    # The indicator reads run_state.current() — the SAME source the scheduler
    # feeds via _begin_run, so scheduler-launched runs show too.
    _, _, app = make_env(tmp_path)
    rs = app.state.run_state
    rs.try_start("wifi_scan", "", "sched-run-9")          # as a scheduler launch would
    c = TestClient(app)
    login_csrf(c)
    assert "sched-run-9" in c.get("/").text


# --- stop active scan ------------------------------------------------------
def test_stop_route_requests_stop(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.run_state.try_start("wifi_scan", "", "run-stop-1")
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/scan/stop", data={"csrf": csrf, "next": "/"}, follow_redirects=False)
    assert r.status_code == 303 and "stopped=1" in r.headers["location"]
    assert app.state.run_state.stop_requested() is True


def test_stop_blocked_in_readonly(tmp_path):
    _, _, app = make_env(tmp_path, readonly=True)
    app.state.run_state.try_start("wifi_scan", "", "run-ro")
    c = TestClient(app)
    csrf = login_csrf(c)
    r = c.post("/scan/stop", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 403
    assert app.state.run_state.stop_requested() is False


def test_stop_requires_csrf(tmp_path):
    _, _, app = make_env(tmp_path)
    app.state.run_state.try_start("wifi_scan", "", "run-csrf")
    c = TestClient(app)
    login_csrf(c)
    assert c.post("/scan/stop", data={}, follow_redirects=False).status_code == 403


# --- orchestrator cooperative stop -----------------------------------------
def test_orchestrator_honors_should_stop(tmp_path):
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text(
        "full_audit:\n  steps: [red.recon_nmap, blue.capture_tshark]\n", encoding="utf-8")
    store = orch.run_workflow("full_audit", "10.0.0.0/24", config=Config(root=tmp_path),
                              should_stop=lambda: True)          # stop immediately
    stopped = [f for f in store.findings() if f.type == "module_status"
               and "stopped by operator" in f.title.lower()]
    assert stopped                                               # recorded, not silent
    # no module ran (stopped before step 1): no recon/capture findings
    assert not [f for f in store.findings() if f.module == "red.recon_nmap"]


# --- stop/finish releases the run's interface (safety net in _bg_run) -------
def test_bg_run_releases_interface_on_finish(tmp_path, monkeypatch):
    cfg = Config(root=tmp_path)
    reg = get_interface_registry(cfg)

    def fake_rw(wf, target, config=None, authorized=False, events=None, run_id=None,
                should_stop=None):
        reg.claim("wlan1", run_id, "monitor", label="Wi-Fi scan")   # leaves it held

    monkeypatch.setattr(orch, "run_workflow", fake_rw)
    rs = RunState(lock=threading.RLock())
    rs.try_start("wifi_scan", "", "run-rel")
    app_mod._bg_run("wifi_scan", "", cfg, rs, run_id="run-rel")
    assert reg.busy_reason("wlan1", "x") == ""              # released on finish
    assert rs.is_active() is False
