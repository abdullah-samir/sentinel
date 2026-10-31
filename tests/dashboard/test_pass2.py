"""Pass 2 tests: recurring-scan scheduler + runtime settings.

Covers every Pass-2 guarantee:
  * create/list/delete persists and reloads
  * a due schedule triggers the (mocked) orchestrator AND registers in live-state
  * firing while a run is active enqueues (never drops) with the cap enforced
  * the scheduler and the web trigger share ONE lock -> only one run can start
  * startup clears a stale run flag and does NOT fire missed occurrences
  * a corrupt schedules file loads as empty without crashing
  * offensive workflows are refused (create + route)
  * readonly pauses scheduled runs
  * "daily at HH:MM" computes the next run in the Pi's LOCAL timezone
  * password change requires the current password, re-hashes, session survives
  * runtime config persists across a simulated restart; env pins win
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from core import orchestrator as orch
from core import registry
from core.config import Config
from dashboard import settings as settings_mod
from dashboard.app import create_app
from dashboard.auth import hash_password, verify_password
from dashboard.config import DashConfig
from dashboard.schedule import Scheduler, next_daily, valid_hhmm
from dashboard.state import RunState

PW = "correct-horse-battery-staple"
SECRET = "fixed-test-secret-0123456789abcdef"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _write_workflows(tmp_path):
    wf = tmp_path / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "workflows.yaml").write_text(
        "quick_recon: { steps: [red.recon_nmap] }\n"
        "capture_only: { steps: [blue.capture_tshark] }\n"
        "full_audit: { steps: [red.recon_nmap, blue.capture_tshark] }\n",
        encoding="utf-8")


def make_env(tmp_path, readonly=False):
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    _write_workflows(tmp_path)
    dc = DashConfig(user="admin", password_hash=hash_password(PW), secret=SECRET,
                    readonly=readonly, path=tmp_path / "data" / "dashboard.json")
    return cfg, dc, create_app(cfg, dc)


def make_scheduler(tmp_path, clock, readonly=False, launch=None):
    """A standalone Scheduler wired to a real RunState over a shared lock, with an
    injectable clock. The default launch_fn mimics the app's: it claims the single
    run slot (so is_active flips) and records the call."""
    cfg = Config(root=tmp_path)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    _write_workflows(tmp_path)
    lock = threading.RLock()
    rs = RunState(lock=lock)
    dash = SimpleNamespace(readonly=readonly)
    calls = []

    def default_launch(wf, target, opts):
        live = rs.try_start(wf, target, f"run-{len(calls)}")
        if live is None:
            return None
        calls.append((wf, target, opts))
        return live.run_id

    sched = Scheduler(cfg, rs, dash, lock, launch or default_launch, clock=clock)
    return cfg, rs, dash, calls, sched


def _csrf(c):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', c.get("/login").text).group(1)


def login(c):
    csrf = _csrf(c)
    assert c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf},
                  follow_redirects=False).status_code == 303
    return csrf


# --------------------------------------------------------------------------- #
# A) CRUD + persistence
# --------------------------------------------------------------------------- #
def test_create_list_delete_persists_and_reloads(tmp_path):
    clock = lambda: 1000.0
    cfg, rs, dash, calls, sched = make_scheduler(tmp_path, clock)
    s = sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=6)
    assert s["kind"] == "interval" and s["every_hours"] == 6
    assert s["next_run"] == 1000.0 + 6 * 3600
    listed = sched.list()
    assert len(listed) == 1 and listed[0]["next_run_iso"]      # iso rendered

    # a fresh Scheduler on the same root reloads from disk
    sched2 = Scheduler(cfg, rs, dash, sched.lock, sched.launch_fn, clock=clock)
    assert len(sched2.list()) == 1
    assert sched2.list()[0]["id"] == s["id"]

    # delete persists
    assert sched2.delete(s["id"]) is True
    sched3 = Scheduler(cfg, rs, dash, sched.lock, sched.launch_fn, clock=clock)
    assert sched3.list() == []


def test_corrupt_schedules_file_loads_empty(tmp_path):
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "schedules.json").write_text("{ this is not json ][", encoding="utf-8")
    _, _, _, _, sched = make_scheduler(tmp_path, lambda: 1000.0)
    assert sched.list() == []          # tolerant load, no crash


def test_create_rejects_bad_input(tmp_path):
    _, _, _, _, sched = make_scheduler(tmp_path, lambda: 1000.0)
    with pytest.raises(ValueError):
        sched.create("no_such_workflow", "10.0.0.0/24", {}, "interval", every_hours=6)
    with pytest.raises(ValueError):
        sched.create("quick_recon", "not a valid target!!", {}, "interval", every_hours=6)
    with pytest.raises(ValueError):
        sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=0)
    with pytest.raises(ValueError):
        sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=999)
    with pytest.raises(ValueError):
        sched.create("quick_recon", "10.0.0.0/24", {}, "daily", at="25:00")


# --------------------------------------------------------------------------- #
# B) firing: due -> trigger + live-state; busy -> queue; cap; readonly
# --------------------------------------------------------------------------- #
def test_due_schedule_triggers_orchestrator_and_registers_livestate(tmp_path, monkeypatch):
    cfg, dc, app = make_env(tmp_path)
    scheduler = app.state.scheduler
    rs = app.state.run_state

    started = threading.Event()
    release = threading.Event()
    seen = {}

    def blocking_run(wf, target, config=None, authorized=False, events=None, run_id=None,
                     should_stop=None):
        seen["wf"] = wf
        seen["target"] = target
        started.set()
        release.wait(5)                # hold the run so is_active stays True

    monkeypatch.setattr(orch, "run_workflow", blocking_run)

    s = scheduler.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=6)
    s["next_run"] = 0                  # make it due now
    scheduler.tick()

    # launch registered in live-state synchronously (before the bg thread blocks)
    assert rs.is_active() is True
    live = rs.live()
    assert live is not None and live.workflow == "quick_recon"
    assert s["last_run_id"] == live.run_id        # schedule records its run
    # next_run advanced into the future (no immediate re-fire)
    assert s["next_run"] > time.time()

    # the orchestrator actually got called in the bg thread
    assert started.wait(5)
    assert seen["wf"] == "quick_recon" and seen["target"] == "10.0.0.0/24"

    release.set()
    for _ in range(50):
        if not rs.is_active():
            break
        time.sleep(0.05)
    assert rs.is_active() is False     # slot freed after the run finished


def test_fire_while_busy_enqueues_then_drains(tmp_path):
    cfg, rs, dash, calls, sched = make_scheduler(tmp_path, lambda: 10_000.0)
    s = sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=1)
    s["next_run"] = 0                  # due

    rs.try_start("web", "10.9.9.9", "web-run")   # a web run is already active
    sched.tick()
    assert calls == []                 # not launched while busy
    assert len(sched.queue) == 1       # queued, not dropped

    rs.finish()                        # web run ends
    sched.tick()                       # next tick drains the queue
    assert len(calls) == 1 and calls[0][0] == "quick_recon"
    assert sched.queue == []


def test_queue_cap_drops_with_log_beyond_ten(tmp_path):
    _, _, _, _, sched = make_scheduler(tmp_path, lambda: 1000.0)
    with sched.lock:
        for i in range(15):
            sched._enqueue({"id": f"s{i}", "workflow": "quick_recon",
                            "target": "10.0.0.0/24", "options": {}})
    assert len(sched.queue) == 10      # capped at QUEUE_CAP, extra dropped


def test_readonly_pauses_scheduled_runs(tmp_path):
    _, rs, dash, calls, sched = make_scheduler(tmp_path, lambda: 1000.0, readonly=True)
    s = sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=1)
    s["next_run"] = 0
    sched.tick()
    assert calls == [] and sched.queue == []       # paused entirely
    # lifting readonly lets it fire
    dash.readonly = False
    sched.tick()
    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# C) the single-run guarantee (shared lock)
# --------------------------------------------------------------------------- #
def test_scheduler_and_runstate_share_one_lock(tmp_path):
    _, _, app = make_env(tmp_path)
    assert app.state.scheduler.lock is app.state.run_state.lock


def test_concurrent_starts_yield_exactly_one_run(tmp_path):
    rs = RunState(lock=threading.RLock())
    barrier = threading.Barrier(20)
    wins = []

    def contender(i):
        barrier.wait()                 # maximise the race
        live = rs.try_start("wf", "t", f"r{i}")
        if live is not None:
            wins.append(i)

    threads = [threading.Thread(target=contender, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1              # the lock admits exactly one


# --------------------------------------------------------------------------- #
# D) startup: clear stale flag, skip missed occurrences
# --------------------------------------------------------------------------- #
def test_prime_clears_stale_and_skips_missed(tmp_path):
    now = {"t": 1000.0}
    cfg, rs, dash, calls, sched = make_scheduler(tmp_path, lambda: now["t"])
    s = sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=1)
    assert s["next_run"] == 1000.0 + 3600          # 4600

    # time jumps forward past the due time (process was offline), slot left stale
    now["t"] = 9000.0
    rs.try_start("stale", "x", "stale-run")        # simulate a stale "in progress" flag
    assert rs.is_active() is True

    sched.prime()
    assert rs.is_active() is False                 # stale flag cleared
    assert calls == []                             # missed occurrence NOT fired
    assert sched.queue == []
    assert s["next_run"] > 9000.0                  # advanced to a FUTURE time
    assert s["next_run"] == 9000.0 + 3600


# --------------------------------------------------------------------------- #
# E) offensive refusal
# --------------------------------------------------------------------------- #
def test_offensive_workflow_refused(tmp_path, monkeypatch):
    registry.discover()
    mod = registry.get("red.recon_nmap")
    assert mod is not None
    monkeypatch.setattr(mod.manifest, "offensive", True)      # restored by monkeypatch

    _, _, _, _, sched = make_scheduler(tmp_path, lambda: 1000.0)
    assert sched.is_offensive("quick_recon") is True
    with pytest.raises(ValueError):
        sched.create("quick_recon", "10.0.0.0/24", {}, "interval", every_hours=6)

    # and the route refuses it too
    _, _, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/schedule", data={"csrf": csrf, "workflow": "quick_recon",
               "target": "10.0.0.0/24", "kind": "interval", "every_hours": "6"},
               follow_redirects=False)
    assert r.status_code == 400 and "offensive" in r.text.lower()


# --------------------------------------------------------------------------- #
# F) daily HH:MM in local tz
# --------------------------------------------------------------------------- #
def test_valid_hhmm():
    assert valid_hhmm("00:00") and valid_hhmm("23:59") and valid_hhmm("3:05")
    assert not valid_hhmm("24:00") and not valid_hhmm("12:60")
    assert not valid_hhmm("noon") and not valid_hhmm("")


def test_next_daily_is_local_tz():
    base = datetime(2026, 1, 1, 10, 0, 0)           # 10:00 local
    ts = base.timestamp()
    # 03:00 already passed today -> tomorrow 03:00 local
    assert next_daily("03:00", ts) == datetime(2026, 1, 2, 3, 0, 0).timestamp()
    # 15:00 still ahead today -> today 15:00 local
    assert next_daily("15:00", ts) == datetime(2026, 1, 1, 15, 0, 0).timestamp()
    # result is always strictly in the future and matches the requested local time
    nxt = datetime.fromtimestamp(next_daily("10:00", ts))
    assert nxt == base + timedelta(days=1) and nxt.hour == 10 and nxt.minute == 0


# --------------------------------------------------------------------------- #
# G) schedule route round-trip
# --------------------------------------------------------------------------- #
def test_schedule_route_creates_persists_and_deletes(tmp_path):
    cfg, dc, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/schedule", data={"csrf": csrf, "workflow": "quick_recon",
               "target": "10.0.0.0/24", "kind": "daily", "at": "03:00"},
               follow_redirects=False)
    assert r.status_code == 303 and "created" in r.headers["location"]
    # persisted to the gitignored store
    stored = json.loads((tmp_path / "data" / "schedules.json").read_text())
    assert len(stored) == 1 and stored[0]["kind"] == "daily" and stored[0]["at"] == "03:00"
    sched_id = stored[0]["id"]
    # shows on the page
    assert "daily at 03:00" in c.get("/schedule").text
    # delete via route
    r = c.post(f"/schedule/{sched_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert json.loads((tmp_path / "data" / "schedules.json").read_text()) == []


def test_schedule_create_blocked_in_readonly(tmp_path):
    cfg, dc, app = make_env(tmp_path, readonly=True)
    c = TestClient(app)
    csrf = login(c)
    r = c.post("/schedule", data={"csrf": csrf, "workflow": "quick_recon",
               "target": "10.0.0.0/24", "kind": "interval", "every_hours": "6"},
               follow_redirects=False)
    assert r.status_code == 403
    assert not (tmp_path / "data" / "schedules.json").exists()


def test_schedule_requires_auth_and_csrf(tmp_path):
    cfg, dc, app = make_env(tmp_path)
    # unauth
    assert TestClient(app).get("/schedule", follow_redirects=False).status_code == 303
    c = TestClient(app)
    login(c)
    # missing csrf
    assert c.post("/schedule", data={"workflow": "quick_recon", "target": "10.0.0.0/24",
                  "kind": "interval", "every_hours": "6"},
                  follow_redirects=False).status_code == 403


# --------------------------------------------------------------------------- #
# H) settings: password change
# --------------------------------------------------------------------------- #
def test_password_change_requires_current_and_session_survives(tmp_path):
    cfg, dc, app = make_env(tmp_path)
    c = TestClient(app)
    csrf = login(c)
    old_hash = dc.password_hash

    # wrong current password -> rejected, hash unchanged
    r = c.post("/settings/password", data={"csrf": csrf, "current": "wrong",
               "new": "a-brand-new-password", "confirm": "a-brand-new-password"},
               follow_redirects=False)
    assert r.status_code == 303 and "badcurrent" in r.headers["location"]
    assert dc.password_hash == old_hash

    # too short
    r = c.post("/settings/password", data={"csrf": csrf, "current": PW,
               "new": "short", "confirm": "short"}, follow_redirects=False)
    assert "tooshort" in r.headers["location"] and dc.password_hash == old_hash

    # mismatch
    r = c.post("/settings/password", data={"csrf": csrf, "current": PW,
               "new": "a-brand-new-password", "confirm": "different-password"},
               follow_redirects=False)
    assert "mismatch" in r.headers["location"] and dc.password_hash == old_hash

    # valid change -> re-hashed, persisted, session still valid
    r = c.post("/settings/password", data={"csrf": csrf, "current": PW,
               "new": "a-brand-new-password", "confirm": "a-brand-new-password"},
               follow_redirects=False)
    assert r.status_code == 303 and "pwchanged" in r.headers["location"]
    assert dc.password_hash != old_hash
    assert verify_password("a-brand-new-password", dc.password_hash)
    # persisted atomically to disk
    saved = json.loads((tmp_path / "data" / "dashboard.json").read_text())
    assert saved["password_hash"] == dc.password_hash
    # the existing session cookie still works (secret unchanged)
    assert c.get("/settings", follow_redirects=False).status_code == 200


# --------------------------------------------------------------------------- #
# I) settings: runtime config persistence + precedence
# --------------------------------------------------------------------------- #
def test_runtime_config_persists_across_restart(tmp_path):
    cfg = Config(root=tmp_path)
    dc = SimpleNamespace(readonly=False)
    settings_mod.update(cfg, dc, {"readonly": True, "nmap_timing": "2",
                                  "nmap_top_ports": "25", "nmap_timeout": "60"})
    assert dc.readonly is True
    assert cfg.nmap_timing == "2" and cfg.nmap_top_ports == 25 and cfg.nmap_timeout == 60

    # simulate a restart: fresh config objects, re-apply from the stored file
    cfg2 = Config(root=tmp_path)
    dc2 = SimpleNamespace(readonly=False)
    assert cfg2.nmap_timing == "4"            # defaults before apply
    settings_mod.apply_to(cfg2, dc2)
    assert dc2.readonly is True
    assert cfg2.nmap_timing == "2" and cfg2.nmap_top_ports == 25 and cfg2.nmap_timeout == 60


def test_runtime_config_rejects_invalid(tmp_path):
    cfg = Config(root=tmp_path)
    dc = SimpleNamespace(readonly=False)
    with pytest.raises(ValueError):
        settings_mod.update(cfg, dc, {"nmap_timing": "9"})
    with pytest.raises(ValueError):
        settings_mod.update(cfg, dc, {"nmap_top_ports": "99999"})
    with pytest.raises(ValueError):
        settings_mod.update(cfg, dc, {"nmap_timeout": "abc"})


def test_env_pin_wins_over_stored(tmp_path, monkeypatch):
    cfg = Config(root=tmp_path)
    dc = SimpleNamespace(readonly=False)
    settings_mod.update(cfg, dc, {"nmap_timing": "2"})        # stored = 2
    # env pins timing to 5 -> apply_to must NOT clobber it back to the stored value
    monkeypatch.setenv("SENTINEL_NMAP_TIMING", "5")
    assert settings_mod.env_pinned("nmap_timing") is True
    cfg2 = Config(root=tmp_path)
    cfg2.nmap_timing = "5"                                    # as Config.from_env would set
    settings_mod.apply_to(cfg2, SimpleNamespace(readonly=False))
    assert cfg2.nmap_timing == "5"                           # env pin preserved


def test_settings_page_renders(tmp_path):
    cfg, dc, app = make_env(tmp_path)
    c = TestClient(app)
    login(c)
    body = c.get("/settings").text
    assert "Runtime config" in body and "Change admin password" in body
    assert "Precedence" in body            # documented precedence shown
