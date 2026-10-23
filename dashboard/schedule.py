"""Recurring scan scheduler for the dashboard.

A single background timer-loop thread (wakes ~every 30s) fires due schedules.
Design guarantees:
  * ONE shared re-entrant lock (the same object RunState uses) guards both the
    schedules store AND the active-run check-and-set, so the scheduler and a web
    trigger can never both start a run.
  * Scheduler-launched runs go through the SAME launch path as web triggers, so
    they register in RunState/LiveRun (running badge, /run/{id}/live, SSE work).
  * If a run is active when a schedule fires the run is QUEUED (FIFO, capped at
    10, drop-with-log beyond) and launched when free — never silently dropped.
  * On start: clears any stale "run in progress" flag and advances overdue
    schedules to their next FUTURE time WITHOUT firing them (no stampede).
  * Persistence is atomic (temp + os.replace) and tolerant (corrupt file -> empty).
  * Offensive workflows are refused at create time; readonly pauses firing.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from core import orchestrator, registry
from core.workflows import load_workflows

QUEUE_CAP = 10
TICK_SECONDS = 30
_HHMM_RE = re.compile(r"^([01]?\d|2[0-3]):[0-5]\d$")


def valid_hhmm(s: str) -> bool:
    return isinstance(s, str) and bool(_HHMM_RE.match(s))


def next_daily(at_hhmm: str, from_ts: float) -> float:
    """Next epoch for HH:MM in the Pi's LOCAL timezone (strictly in the future)."""
    base = datetime.fromtimestamp(from_ts)          # local naive time
    hh, mm = (int(x) for x in at_hhmm.split(":"))
    cand = base.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if cand <= base:
        cand += timedelta(days=1)
    return cand.timestamp()


class Scheduler:
    def __init__(self, config, run_state, dash_config, lock, launch_fn,
                 clock=None, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.run_state = run_state
        self.dash_config = dash_config
        self.lock = lock                 # SHARED with run_state (re-entrant)
        self.launch_fn = launch_fn       # (workflow, target, options) -> run_id|None
        self.clock = clock or time.time
        self.log = logger or logging.getLogger("sentinel.dashboard.schedule")
        self.schedules: List[dict] = []
        self.queue: List[dict] = []
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._load()

    # --- persistence ------------------------------------------------------
    def _path(self):
        return self.config.root / "data" / "schedules.json"

    def _load(self) -> None:
        p = self._path()
        if not p.exists():
            self.schedules = []
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.schedules = data if isinstance(data, list) else []
        except Exception as e:  # noqa: BLE001 — corrupt file must not crash startup
            self.log.warning("schedules load failed (%s); starting with none", e)
            self.schedules = []

    def _save(self) -> None:
        """Atomic write. Caller must hold self.lock."""
        p = self._path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.schedules, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    # --- validation helpers ----------------------------------------------
    def _known_workflows(self) -> set:
        return set(load_workflows(self.config).keys())

    def is_offensive(self, workflow: str) -> bool:
        try:
            registry.discover()
            wf = load_workflows(self.config).get(workflow)
            steps = wf.get("steps", []) if isinstance(wf, dict) else []
            for step in steps:
                m = registry.get(step)
                if m and m.manifest.offensive:
                    return True
        except Exception:  # noqa: BLE001
            return False
        return False

    def _compute_next(self, sched: dict, now: float) -> float:
        if sched.get("kind") == "daily":
            return next_daily(sched["at"], now)
        return now + int(sched["every_hours"]) * 3600

    # --- CRUD -------------------------------------------------------------
    def create(self, workflow: str, target: str, options: dict, kind: str,
               every_hours=None, at=None) -> dict:
        with self.lock:
            if workflow not in self._known_workflows():
                raise ValueError(f"unknown workflow: {workflow}")
            if self.is_offensive(workflow):
                raise ValueError("offensive workflows cannot be scheduled from the dashboard")
            target = orchestrator.validate_target(target)        # ValueError on bad input
            if kind == "daily":
                if not valid_hhmm(at or ""):
                    raise ValueError("time must be HH:MM (24-hour)")
                every_hours = None
            else:
                kind = "interval"
                try:
                    every_hours = int(every_hours)
                except (TypeError, ValueError):
                    raise ValueError("interval hours must be a whole number")
                if not (1 <= every_hours <= 168):
                    raise ValueError("interval hours must be between 1 and 168")
                at = None
            now = self.clock()
            sched = {"id": uuid.uuid4().hex[:12], "workflow": workflow, "target": target,
                     "options": options or {}, "kind": kind, "every_hours": every_hours,
                     "at": at, "last_run_id": "", "created_at": _iso(now)}
            sched["next_run"] = self._compute_next(sched, now)
            self.schedules.append(sched)
            self._save()
            return sched

    def delete(self, sched_id: str) -> bool:
        with self.lock:
            before = len(self.schedules)
            self.schedules = [s for s in self.schedules if s.get("id") != sched_id]
            changed = len(self.schedules) < before
            if changed:
                self._save()
            return changed

    def list(self) -> List[dict]:
        with self.lock:
            out = []
            for s in self.schedules:
                d = dict(s)
                d["next_run_iso"] = _iso(d.get("next_run", 0)) if d.get("next_run") else ""
                out.append(d)
            return out

    # --- lifecycle --------------------------------------------------------
    def prime(self) -> None:
        """Startup reset: clear a stale run flag and advance overdue schedules to
        their next FUTURE occurrence WITHOUT firing them (no stampede)."""
        with self.lock:
            self.run_state.reset_stale()
            now = self.clock()
            for s in self.schedules:
                if s.get("next_run", 0) <= now:
                    self.log.info("schedule %s was due while offline — skipping missed "
                                  "run, computing next", s.get("id"))
                    s["next_run"] = self._compute_next(s, now)
            self._save()

    def start(self) -> None:
        with self.lock:
            if self._thread is not None and self._thread.is_alive():
                return                       # single instance only
            self.prime()
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="sentinel-scheduler",
                                            daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 — one bad tick can't kill scheduling
                self.log.error("scheduler tick failed: %s", e)
            self._stop.wait(TICK_SECONDS)

    # --- the tick ---------------------------------------------------------
    def tick(self) -> None:
        with self.lock:
            if self.dash_config.readonly:
                return                       # readonly pauses scheduled runs too
            now = self.clock()
            changed = False
            for s in self.schedules:
                if s.get("next_run", 0) <= now:
                    self._enqueue(s)
                    s["next_run"] = self._compute_next(s, now)
                    changed = True
            self._drain()
            if changed:
                self._save()

    def _enqueue(self, sched: dict) -> None:
        if len(self.queue) >= QUEUE_CAP:
            self.log.warning("scheduler queue full (%d) — dropping fire of schedule %s",
                             QUEUE_CAP, sched.get("id"))
            return
        self.queue.append({"schedule_id": sched["id"], "workflow": sched["workflow"],
                           "target": sched["target"], "options": sched.get("options", {})})
        self.log.info("scheduled run queued: %s on %s", sched["workflow"], sched["target"])

    def _drain(self) -> None:
        # Holds the lock, so no web trigger can grab the slot between the active
        # check and launch_fn's try_start.
        while self.queue and not self.run_state.is_active():
            req = self.queue.pop(0)
            try:
                run_id = self.launch_fn(req["workflow"], req["target"], req["options"])
            except Exception as e:  # noqa: BLE001
                self.log.error("scheduled launch failed: %s", e)
                run_id = None
            if run_id:
                self.log.info("scheduled run started: %s (%s)", run_id, req["workflow"])
                for s in self.schedules:
                    if s["id"] == req["schedule_id"]:
                        s["last_run_id"] = run_id
                self._save()
            else:
                self.queue.insert(0, req)    # unexpectedly busy — keep it, retry later
                break


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return ""
