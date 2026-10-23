"""FastAPI dashboard app (Pass A).

Reuses the engine rather than reimplementing it: core.registry +
core.orchestrator for modules/scans, reporting.report_engine for reports,
reporting.history/risk for the run list. Server-rendered Jinja2 (autoescape on),
offline (no CDN), dark Sentinel theme. All routes except /login and /health
require a valid signed session.
"""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs

import asyncio
import threading
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse,
)
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import escape

from core import orchestrator, registry
from core.config import Config
from core.context import RunContext
from core.events import EventBus
from core.hardware import build_hardware
from core.schema import RunResult, make_run_id, utcnow_iso
from core.store import Store
from core.workflows import load_workflows
from dashboard.auth import (
    RateLimiter, csrf_ok, hash_password, make_session, new_csrf_token, read_session,
    verify_password,
)
from dashboard.config import DashConfig, load_dash_config, save_dash_config
from dashboard.live import attach_log_capture, detach_log_capture, sse
from dashboard.schedule import Scheduler
from dashboard.state import RunState
from dashboard import assets as assets_mod
from dashboard import launcher, manage, settings as settings_mod
from reporting import history, risk, report_engine

_EVENT_TOPICS = ("run.start", "step.start", "step.done", "step.skip",
                 "step.refuse", "run.done")

log = logging.getLogger("sentinel.dashboard")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#E5484D", "high": "#F5953E", "medium": "#E0B341",
             "low": "#2DD4BF", "info": "#8B98AB"}
GRADE_COLOR = {"A": "#2DD4BF", "B": "#A3D977", "C": "#E0B341", "D": "#F5953E", "F": "#E5484D"}
GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

# Overview sort keys -> (row field accessor). Server-side so it works without JS
# and is deterministic for tests; column headers are plain links.
_SORT_KEYS = {
    "date": lambda r: r["started_at"],
    "workflow": lambda r: r["workflow"].lower(),
    "target": lambda r: r["target"].lower(),
    "hosts": lambda r: r["hosts_up"],
    "findings": lambda r: r["findings_total"],
    "grade": lambda r: GRADE_RANK.get(r["grade"], 99),
}


def _sorted_rows(rows: list, sort: str, direction: str) -> list:
    fn = _SORT_KEYS.get(sort)
    if fn is None:
        return rows                      # unknown key -> default (newest-first) order
    return sorted(rows, key=fn, reverse=(direction != "asc"))
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_TEMPLATES = Path(__file__).parent / "templates"

SESSION_COOKIE = "sentinel_session"
CSRF_COOKIE = "sentinel_csrf"


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("sentinel")
    except Exception:  # noqa: BLE001
        return "0.1.0"


async def _parse_form(request: Request) -> dict:
    body = await request.body()
    parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def create_app(core_config: Optional[Config] = None,
               dash_config: Optional[DashConfig] = None) -> FastAPI:
    core_config = core_config or Config.from_env()
    dash_config = dash_config or load_dash_config(core_config)
    settings_mod.apply_to(core_config, dash_config)   # stored runtime settings (env pins win)
    shared_lock = threading.RLock()                   # guards run-state AND schedules
    run_state = RunState(lock=shared_lock)
    limiter = RateLimiter()
    assets_cache: dict = {}            # signature-cached asset aggregation
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                      autoescape=select_autoescape(["html", "xml"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.globals.update(sev_order=SEV_ORDER, sev_color=SEV_COLOR, grade_color=GRADE_COLOR,
                       version=_version())

    @asynccontextmanager
    async def _lifespan(app):                 # fires under uvicorn / `with TestClient`
        sched = getattr(app.state, "scheduler", None)
        if sched is not None:
            sched.start()                     # not under bare TestClient(app)
        try:
            yield
        finally:
            if sched is not None:
                sched.stop()

    app = FastAPI(title="Sentinel Dashboard", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=_lifespan)
    app.state.run_state = run_state
    app.state.limiter = limiter
    app.state.dash_config = dash_config

    # --- helpers ----------------------------------------------------------
    def current_user(request: Request) -> Optional[str]:
        tok = request.cookies.get(SESSION_COOKIE)
        return read_session(tok, dash_config.secret) if tok else None

    def render(name: str, request: Request, **ctx) -> HTMLResponse:
        tok = request.cookies.get(CSRF_COOKIE) or new_csrf_token()
        html = env.get_template(name).render(csrf_token=tok, readonly=dash_config.readonly,
                                             user=current_user(request), **ctx)
        resp = HTMLResponse(html)
        if request.cookies.get(CSRF_COOKIE) != tok:
            resp.set_cookie(CSRF_COOKIE, tok, httponly=True, samesite="strict", max_age=43200)
        return resp

    def login_redirect() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    def probe_ctx() -> RunContext:
        run = RunResult(run_id="probe", workflow="(probe)", target="", started_at=utcnow_iso())
        store = Store(run, core_config.results_dir / "_dash_probe.json")
        return RunContext(target="", workflow="(probe)", config=core_config, store=store,
                          log=logging.getLogger("sentinel.dashboard.probe"),
                          hw=build_hardware(core_config), events=EventBus())

    def run_rows() -> list:
        rows = []
        for run in history.load_all_runs(core_config):   # newest first, skips malformed
            stats = run.get("stats") or {}
            by_sev = stats.get("findings_by_severity") or {}
            findings = run.get("findings") or []
            grade = risk.grade_for_score(risk.score(findings))
            run_id = run.get("run_id", "")
            meta = manage.load_meta(core_config, run_id)
            rows.append({
                "run_id": run_id, "workflow": run.get("workflow", ""),
                "target": run.get("target", ""), "started_at": run.get("started_at", ""),
                "hosts_up": int(stats.get("hosts_up", 0)),
                "findings_total": int(stats.get("findings_total", len(findings))),
                "by_severity": {s: int(by_sev.get(s, 0)) for s in SEV_ORDER},
                "grade": grade, "grade_color": GRADE_COLOR.get(grade, "#8B98AB"),
                "name": meta.get("name", ""), "tags": meta.get("tags", ""),
            })
        return rows

    def module_rows() -> list:
        registry.discover()
        ctx = probe_ctx()
        out = []
        mods = registry.all_modules()
        for name in sorted(mods):
            m = mods[name].manifest
            try:
                ok, reason = mods[name]().is_available(ctx)
            except Exception as e:  # noqa: BLE001
                ok, reason = False, f"error: {e}"
            out.append({"phase": m.phase or "?", "name": name, "category": m.category,
                        "display": m.display or m.title, "offensive": m.offensive,
                        "available": ok, "reason": "" if ok else reason})
        out.sort(key=lambda r: (r["phase"], r["name"]))
        return out

    def _begin_run(workflow: str, target: str, options: dict):
        """Atomic check-and-set: claim the single run slot + register the LiveRun
        + wire the shared EventBus. Returns (run_id, run_config, events) or None
        if a run is already active. Shared by web triggers AND the scheduler, so
        both register in the same live-state and the lock guarantees one run."""
        run_config = launcher.config_from_options(core_config, options)
        run_id = make_run_id(workflow, target)
        live = run_state.try_start(workflow, target, run_id)   # atomic under shared lock
        if live is None:
            return None
        launcher.save_launch(core_config, run_id, workflow, target, options)
        assets_mod.invalidate(assets_cache)
        events = EventBus()
        for topic in _EVENT_TOPICS:
            events.subscribe(topic, live.on_event)
        return run_id, run_config, events

    def _scheduler_launch(workflow: str, target: str, options: dict):
        """Scheduler's launch fn: start a run in a background thread (visible in
        live-state/SSE). Returns run_id, or None if busy."""
        began = _begin_run(workflow, target, options)
        if began is None:
            return None
        run_id, run_config, events = began
        threading.Thread(target=_bg_run, name=f"scan-{run_id}",
                         args=(workflow, target, run_config, run_state, events, run_id),
                         daemon=True).start()
        return run_id

    scheduler = Scheduler(core_config, run_state, dash_config, shared_lock, _scheduler_launch)
    app.state.scheduler = scheduler

    # --- health (no auth) -------------------------------------------------
    @app.get("/health")
    def health():
        try:
            registry.discover()
            modules = len(registry.all_modules())
        except Exception:  # noqa: BLE001
            modules = 0
        results = core_config.results_dir
        runs = len(list(results.glob("*.json"))) if results.exists() else 0
        try:
            free = shutil.disk_usage(results if results.exists() else core_config.root).free
        except Exception:  # noqa: BLE001
            free = -1
        return JSONResponse({"status": "ok", "version": _version(),
                             "modules": modules, "runs": runs, "free_disk_bytes": free})

    # --- auth -------------------------------------------------------------
    @app.get("/login")
    def login_form(request: Request):
        if current_user(request):
            return RedirectResponse("/", status_code=303)
        return render("login.html", request, error=request.query_params.get("error"))

    @app.post("/login")
    async def login(request: Request):
        ip = request.client.host if request.client else "?"
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return render("login.html", request, error="Invalid request (CSRF). Try again.")
        if limiter.blocked(ip):
            mins = limiter.locked_for(ip) // 60 + 1
            return render("login.html", request,
                          error=f"Too many failed attempts — this IP is locked for ~{mins} min.")
        user = form.get("username", "")
        password = form.get("password", "")
        if (user == dash_config.user and dash_config.password_hash
                and verify_password(password, dash_config.password_hash)):
            limiter.reset(ip)
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(SESSION_COOKIE, make_session(user, dash_config.secret),
                            httponly=True, samesite="strict", max_age=43200)
            return resp
        limiter.record_failure(ip)
        return render("login.html", request, error="Invalid username or password.")

    @app.post("/logout")
    async def logout(request: Request):
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    def _sort_params(request: Request):
        sort = request.query_params.get("sort", "date")
        direction = request.query_params.get("dir", "desc")
        if sort not in _SORT_KEYS:
            sort, direction = "date", "desc"
        return sort, direction

    def _stat_cards(base_rows: list) -> dict:
        sev_tot = {s: sum(r["by_severity"][s] for r in base_rows) for s in SEV_ORDER}
        latest = base_rows[0]["grade"] if base_rows else "—"
        worst = (max((r["grade"] for r in base_rows), key=lambda g: GRADE_RANK.get(g, 0))
                 if base_rows else "—")
        return {"runs": len(base_rows),
                "hosts": len(assets_mod.aggregate(core_config, assets_cache)),
                "by_severity": sev_tot, "latest_grade": latest, "worst_grade": worst}

    # --- overview ---------------------------------------------------------
    @app.get("/")
    def overview(request: Request):
        if not current_user(request):
            return login_redirect()
        base_rows = run_rows()                       # newest-first
        sort, direction = _sort_params(request)
        rows = _sorted_rows(base_rows, sort, direction)
        return render("overview.html", request, rows=rows, show_stats=True,
                      stat_cards=_stat_cards(base_rows), nav_active="overview",
                      sort=sort, direction=direction, active=run_state.current(),
                      started=request.query_params.get("started"),
                      msg_deleted=request.query_params.get("deleted"),
                      msg_failed=request.query_params.get("failed"))

    @app.get("/runs")
    def runs_page(request: Request):
        if not current_user(request):
            return login_redirect()
        sort, direction = _sort_params(request)
        rows = _sorted_rows(run_rows(), sort, direction)
        return render("overview.html", request, rows=rows, show_stats=False,
                      stat_cards=None, nav_active="runs", sort=sort, direction=direction,
                      active=run_state.current(),
                      msg_deleted=request.query_params.get("deleted"),
                      msg_failed=request.query_params.get("failed"))

    @app.get("/modules")
    def modules(request: Request):
        if not current_user(request):
            return login_redirect()
        wfs = load_workflows(core_config)
        wf_view = {name: (wf.get("steps", []) if isinstance(wf, dict) else [])
                   for name, wf in wfs.items()}
        return render("modules.html", request, modules=module_rows(), workflows=wf_view,
                      nav_active="modules")

    # --- report view (served standalone in an iframe) ---------------------
    @app.get("/run/{run_id}")
    def run_view(run_id: str, request: Request):
        if not current_user(request):
            return login_redirect()
        if not _RUN_ID_RE.match(run_id):
            return HTMLResponse("Invalid run id", status_code=404)
        try:
            run = report_engine.load_run(run_id, core_config)
        except FileNotFoundError:
            return HTMLResponse(f"Run not found: {escape(run_id)}", status_code=404)
        return render("run.html", request, run_id=run_id, meta={
            "workflow": run.get("workflow", ""), "target": run.get("target", ""),
            "started_at": run.get("started_at", ""), "finished_at": run.get("finished_at", "")})

    @app.get("/run/{run_id}/report")
    def run_report(run_id: str, request: Request):
        if not current_user(request):
            return login_redirect()
        if not _RUN_ID_RE.match(run_id):
            return HTMLResponse("Invalid run id", status_code=404)
        try:
            out, _ = report_engine.generate_report(run_id, core_config)
        except FileNotFoundError:
            return HTMLResponse("Run not found", status_code=404)
        return FileResponse(str(out["html"]), media_type="text/html")

    # --- trigger a scan ---------------------------------------------------
    @app.post("/run/{workflow}")
    async def trigger(workflow: str, request: Request, background_tasks: BackgroundTasks):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: scans are disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        if workflow not in load_workflows(core_config):
            return HTMLResponse(f"Unknown workflow: {escape(workflow)}", status_code=404)
        try:
            target = orchestrator.validate_target(form.get("target", ""))
        except ValueError as e:
            return HTMLResponse(f"Invalid target: {escape(str(e))}", status_code=400)
        # Per-run options -> a COPY of the config (global config/core untouched).
        try:
            options = launcher.parse_options(core_config, workflow, form)
        except ValueError as e:
            return HTMLResponse(f"Invalid option: {escape(str(e))}", status_code=400)
        began = _begin_run(workflow, target, options)
        if began is None:
            return HTMLResponse("A scan is already in progress.", status_code=409)
        run_id, run_config, events = began
        background_tasks.add_task(_bg_run, workflow, target, run_config, run_state,
                                  events, run_id)
        return RedirectResponse(f"/run/{run_id}/live", status_code=303)

    # --- live run view + SSE stream --------------------------------------
    @app.get("/run/{run_id}/live")
    def live_view(run_id: str, request: Request):
        """Permanent, addressable live page. Active -> live view; finished ->
        redirect to the report; unknown -> not found. Lets a user navigate away
        and return (e.g. after reconnecting over Tailscale)."""
        if not current_user(request):
            return login_redirect()
        if not _RUN_ID_RE.match(run_id):
            return HTMLResponse("Invalid run id", status_code=404)
        live = run_state.live()
        if run_state.is_active() and live and live.run_id == run_id and not live.done:
            return render("live.html", request, run_id=run_id, snapshot=live.snapshot())
        # Not the active run: if a result exists, it's finished -> show the report.
        try:
            report_engine.load_run(run_id, core_config)
            return RedirectResponse(f"/run/{run_id}", status_code=303)
        except FileNotFoundError:
            return HTMLResponse(f"Run not found: {escape(run_id)}", status_code=404)

    @app.get("/events/{run_id}")
    async def events_stream(run_id: str, request: Request):
        if not current_user(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        live = run_state.live()
        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

        # Scope strictly to this run_id so one stream never leaks another's events.
        if live is None or live.run_id != run_id:
            async def gone():
                yield sse("snapshot", {"run_id": run_id, "active": False, "done": True})
                yield sse("done", {"run_id": run_id, "active": False})
            return StreamingResponse(gone(), media_type="text/event-stream", headers=headers)

        async def gen():
            loop = asyncio.get_event_loop()
            queue: asyncio.Queue = asyncio.Queue()
            live.add_listener(loop, queue)      # register before snapshot (dedup by _seq)
            try:
                yield sse("snapshot", live.snapshot())
                if live.done:
                    yield sse("done", live.snapshot())
                    return
                while True:
                    try:
                        evt, data = await asyncio.wait_for(queue.get(), timeout=3.0)
                    except asyncio.TimeoutError:
                        yield sse("tick", live.snapshot())   # keeps the stream moving
                        if live.done:
                            yield sse("done", live.snapshot())
                            return
                        continue
                    yield sse(evt, data)
                    if evt == "run.done":
                        yield sse("done", live.snapshot())
                        return
            finally:
                live.remove_listener(loop, queue)

        return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)

    # --- scan launcher ----------------------------------------------------
    @app.get("/scan")
    def scan_page(request: Request):
        if not current_user(request):
            return login_redirect()
        wfs = sorted(load_workflows(core_config).keys())
        workflow = request.query_params.get("workflow") or (wfs[0] if wfs else "")
        if workflow not in wfs:
            workflow = wfs[0] if wfs else ""
        prefill = {"target": "", "options": {}}
        rerun = request.query_params.get("rerun")
        if rerun and manage.valid_run_id(rerun):
            lj = launcher.load_launch(core_config, rerun)
            if lj:
                if lj.get("workflow") in wfs:
                    workflow = lj["workflow"]
                prefill = {"target": lj.get("target", ""), "options": lj.get("options", {})}
        return render("scan.html", request, nav_active="scan", workflows=wfs,
                      workflow=workflow, prefill=prefill, active=run_state.current(),
                      option_groups=launcher.workflow_option_groups(core_config, workflow))

    # --- run management ---------------------------------------------------
    @app.post("/run/{run_id}/delete")
    async def delete_run_route(run_id: str, request: Request):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: deletion is disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        try:
            manage.delete_run(core_config, run_id)
        except ValueError as e:
            return HTMLResponse(f"Invalid run id: {escape(str(e))}", status_code=400)
        assets_mod.invalidate(assets_cache)
        return RedirectResponse("/runs?deleted=1&failed=0", status_code=303)

    @app.post("/runs/delete")
    async def bulk_delete_route(request: Request):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: deletion is disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        ids = [x for x in (form.get("run_ids", "").split(",")) if x]
        deleted, failed, errors = manage.bulk_delete(core_config, ids)
        for msg in errors:
            log.warning("bulk delete: %s", msg)
        assets_mod.invalidate(assets_cache)
        return RedirectResponse(f"/runs?deleted={deleted}&failed={failed}", status_code=303)

    @app.post("/run/{run_id}/rename")
    async def rename_run_route(run_id: str, request: Request):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: editing is disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        try:
            manage.save_meta(core_config, run_id, name=form.get("name", ""),
                             tags=form.get("tags", ""))
        except ValueError as e:
            return HTMLResponse(f"Invalid run id: {escape(str(e))}", status_code=400)
        return RedirectResponse("/runs", status_code=303)

    # --- assets inventory -------------------------------------------------
    @app.get("/assets")
    def assets_page(request: Request):
        if not current_user(request):
            return login_redirect()
        return render("assets.html", request, nav_active="assets",
                      hosts=assets_mod.aggregate(core_config, assets_cache))

    @app.get("/assets/{key}")
    def asset_detail(key: str, request: Request):
        if not current_user(request):
            return login_redirect()
        data = assets_mod.aggregate(core_config, assets_cache)
        host = next((h for h in data if h["key"] == key), None)
        if host is None:
            return HTMLResponse(f"Host not found: {escape(key)}", status_code=404)
        return render("asset_detail.html", request, nav_active="assets", host=host)

    # --- schedule ---------------------------------------------------------
    @app.get("/schedule")
    def schedule_page(request: Request):
        if not current_user(request):
            return login_redirect()
        wfs = sorted(load_workflows(core_config).keys())
        offensive = {wf: scheduler.is_offensive(wf) for wf in wfs}
        sel = request.query_params.get("workflow")
        if sel not in wfs:
            sel = next((w for w in wfs if not offensive.get(w)), (wfs[0] if wfs else ""))
        return render("schedule.html", request, nav_active="schedule",
                      schedules=scheduler.list(), workflows=wfs, offensive=offensive,
                      workflow=sel, sel_offensive=offensive.get(sel, False),
                      option_groups=launcher.workflow_option_groups(core_config, sel),
                      prefill={"target": "", "options": {}},
                      msg=request.query_params.get("msg"))

    @app.post("/schedule")
    async def schedule_create(request: Request):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: scheduling is disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        workflow = form.get("workflow", "")
        if workflow not in load_workflows(core_config):
            return HTMLResponse(f"Unknown workflow: {escape(workflow)}", status_code=404)
        try:
            options = launcher.parse_options(core_config, workflow, form)
            scheduler.create(workflow, form.get("target", ""), options,
                             form.get("kind", "interval"),
                             every_hours=form.get("every_hours"), at=form.get("at"))
        except ValueError as e:
            return HTMLResponse(f"Cannot schedule: {escape(str(e))}", status_code=400)
        return RedirectResponse("/schedule?msg=created", status_code=303)

    @app.post("/schedule/{sched_id}/delete")
    async def schedule_delete(sched_id: str, request: Request):
        if not current_user(request):
            return login_redirect()
        if dash_config.readonly:
            return HTMLResponse("Read-only mode: scheduling is disabled.", status_code=403)
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        scheduler.delete(sched_id)
        return RedirectResponse("/schedule?msg=deleted", status_code=303)

    # --- settings ---------------------------------------------------------
    @app.get("/settings")
    def settings_page(request: Request):
        if not current_user(request):
            return login_redirect()
        try:
            registry.discover()
            modules = len(registry.all_modules())
        except Exception:  # noqa: BLE001
            modules = 0
        results = core_config.results_dir
        runs = len(list(results.glob("*.json"))) if results.exists() else 0
        try:
            free = shutil.disk_usage(results if results.exists() else core_config.root).free
        except Exception:  # noqa: BLE001
            free = -1
        return render("settings.html", request, nav_active="settings",
                      cfg={"nmap_timing": core_config.nmap_timing,
                           "nmap_top_ports": core_config.nmap_top_ports,
                           "nmap_timeout": core_config.nmap_timeout},
                      pins={f: settings_mod.env_pinned(f)
                            for f in ("readonly", "nmap_timing", "nmap_top_ports", "nmap_timeout")},
                      info={"version": _version(), "modules": modules, "runs": runs,
                            "free_gb": round(free / 1e9, 1) if free >= 0 else "?"},
                      msg=request.query_params.get("msg"))

    @app.post("/settings/password")
    async def settings_password(request: Request):
        if not current_user(request):
            return login_redirect()
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        if not verify_password(form.get("current", ""), dash_config.password_hash):
            return RedirectResponse("/settings?msg=badcurrent", status_code=303)
        new = form.get("new", "")
        if len(new) < 8:
            return RedirectResponse("/settings?msg=tooshort", status_code=303)
        if new != form.get("confirm", ""):
            return RedirectResponse("/settings?msg=mismatch", status_code=303)
        # Re-hash + persist atomically; session stays valid (secret unchanged).
        dash_config.password_hash = hash_password(new)
        save_dash_config(dash_config)
        return RedirectResponse("/settings?msg=pwchanged", status_code=303)

    @app.post("/settings/config")
    async def settings_config(request: Request):
        if not current_user(request):
            return login_redirect()
        form = await _parse_form(request)
        if not csrf_ok(request.cookies.get(CSRF_COOKIE), form.get("csrf")):
            return HTMLResponse("CSRF validation failed.", status_code=403)
        changes = {"readonly": form.get("readonly") in ("1", "on", "true")}
        for key in ("nmap_timing", "nmap_top_ports", "nmap_timeout"):
            if form.get(key) not in (None, ""):
                changes[key] = form[key]
        try:
            settings_mod.update(core_config, dash_config, changes)
        except ValueError:
            return RedirectResponse("/settings?msg=invalid", status_code=303)
        return RedirectResponse("/settings?msg=saved", status_code=303)

    # --- JSON APIs (auth-required) ---------------------------------------
    @app.get("/api/runs")
    def api_runs(request: Request):
        if not current_user(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"runs": run_rows()})

    @app.get("/api/run/{run_id}")
    def api_run(run_id: str, request: Request):
        if not current_user(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _RUN_ID_RE.match(run_id):
            return JSONResponse({"error": "invalid run id"}, status_code=404)
        try:
            return JSONResponse(report_engine.load_run(run_id, core_config))
        except FileNotFoundError:
            return JSONResponse({"error": "not found"}, status_code=404)

    @app.get("/api/modules")
    def api_modules(request: Request):
        if not current_user(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse({"modules": module_rows()})

    return app


def _bg_run(workflow: str, target: str, run_config: Config, run_state: RunState,
            events=None, run_id=None) -> None:
    """Background scan runner. Passes the per-run config + shared EventBus +
    pre-assigned run_id to the orchestrator (authorized=False, so the offensive
    gate is NOT bypassed) and streams its logs into the live view."""
    live = run_state.live()
    handle = attach_log_capture(live) if live else None
    try:
        orchestrator.run_workflow(workflow, target, config=run_config,
                                  authorized=False, events=events, run_id=run_id)
    except Exception as e:  # noqa: BLE001
        log.error("dashboard-triggered run failed: %s", e)
        if live:
            live.finalize(error=str(e))
    finally:
        detach_log_capture(handle)
        if live and not live.done:
            live.finalize()
        run_state.finish()
