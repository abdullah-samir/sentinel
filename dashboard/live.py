# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Live-run state for the dashboard's streaming view.

A LiveRun accumulates progress for the single active scan from the orchestrator's
EventBus (step index/total, findings-by-severity, asset count) plus captured log
lines (per-host recon/capture messages), and fans those out to connected SSE
clients. Thread-safe: the orchestrator publishes from a worker thread while the
SSE generators consume on the event loop, so updates are marshalled onto each
listener's loop with ``call_soon_threadsafe``.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import List, Optional, Tuple

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_MAX_LOG = 300            # cap the retained console/event log


def sse(event: str, data) -> str:
    """Format one Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


class LiveRun:
    def __init__(self, run_id: str, workflow: str, target: str) -> None:
        self.run_id = run_id
        self.workflow = workflow
        self.target = target
        self.started_at = time.time()
        self.steps_total = 0
        self.steps_done = 0
        self.current_step = ""
        self.hosts_done = 0          # assets discovered so far (per nmap, no up-front total)
        self.hosts_total = 0         # 0 = unknown (nmap discovers; not known up front)
        self.findings = {s: 0 for s in SEV_ORDER}
        self.done = False
        self.error = ""
        self.log: List[dict] = []    # recent events for the console / late subscribers
        self._seq = 0
        self._lock = threading.Lock()
        self._listeners: List[Tuple] = []   # (loop, queue)

    # --- progress / ETA ---------------------------------------------------
    def _progress_fraction(self) -> float:
        # Prefer host progress if a total is known (usually not, for nmap), else
        # a coarse per-step fraction.
        if self.hosts_total > 0:
            return min(self.hosts_done / self.hosts_total, 1.0)
        if self.steps_total > 0:
            return min(self.steps_done / self.steps_total, 1.0)
        return 0.0

    def eta(self) -> dict:
        elapsed = time.time() - self.started_at
        frac = self._progress_fraction()
        if self.done:
            return {"state": "done", "elapsed": int(elapsed), "remaining": 0, "fraction": 1.0}
        if frac <= 0.0 or self.steps_done == 0:
            return {"state": "estimating", "elapsed": int(elapsed), "remaining": None,
                    "fraction": frac}
        # honest estimate: total ≈ elapsed / fraction_done; remaining = total − elapsed
        remaining = max(0, int(elapsed / frac - elapsed))
        return {"state": "ok", "elapsed": int(elapsed), "remaining": remaining,
                "fraction": frac}

    def snapshot(self) -> dict:
        return {
            "run_id": self.run_id, "workflow": self.workflow, "target": self.target,
            "steps_total": self.steps_total, "steps_done": self.steps_done,
            "current_step": self.current_step, "hosts_done": self.hosts_done,
            "hosts_total": self.hosts_total,
            "findings": dict(self.findings), "done": self.done, "error": self.error,
            "eta": self.eta(), "log": list(self.log),
        }

    # --- listeners (SSE connections) --------------------------------------
    def add_listener(self, loop, queue) -> None:
        with self._lock:
            self._listeners.append((loop, queue))

    def remove_listener(self, loop, queue) -> None:
        with self._lock:
            self._listeners = [(l, q) for (l, q) in self._listeners if q is not queue]

    def _emit(self, event: str, data: dict) -> None:
        """Record an event and push it to every listener (thread-safe). Each
        payload carries a monotonic `_seq` so clients can dedup an event that
        appears both in the initial snapshot log and the live stream."""
        with self._lock:
            self._seq += 1
            seq = self._seq
            entry = {"seq": seq, "event": event, **data}
            if event in ("log", "run.start", "step.start", "step.done",
                         "step.skip", "step.refuse", "run.done"):
                self.log.append(entry)
                if len(self.log) > _MAX_LOG:
                    self.log = self.log[-_MAX_LOG:]
            listeners = list(self._listeners)
        payload = {**data, "_seq": seq}
        for loop, queue in listeners:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, (event, payload))
            except Exception:  # noqa: BLE001 — a dead listener must not break others
                pass

    # --- event + log intake (called from the run worker thread) -----------
    def on_event(self, topic: str, payload) -> None:
        data = payload if isinstance(payload, dict) else {"value": payload}
        if topic == "run.start":
            self.steps_total = int(data.get("steps_total", self.steps_total) or 0)
            if data.get("run_id"):
                self.run_id = data["run_id"]
        elif topic == "step.start":
            self.current_step = data.get("name", "")
        elif topic in ("step.done", "step.skip", "step.refuse"):
            idx = data.get("index")
            self.steps_done = int(idx) if idx is not None else self.steps_done + 1
            bysev = data.get("findings_by_severity")
            if isinstance(bysev, dict):
                for s in SEV_ORDER:
                    self.findings[s] = int(bysev.get(s, self.findings[s]) or 0)
            if data.get("assets") is not None:
                self.hosts_done = int(data["assets"])
        elif topic == "run.done":
            bysev = data.get("findings_by_severity")
            if isinstance(bysev, dict):
                for s in SEV_ORDER:
                    self.findings[s] = int(bysev.get(s, 0) or 0)
            if data.get("assets") is not None:
                self.hosts_done = int(data["assets"])
            self.done = True
        self._emit(topic, {**data, "snapshot_eta": self.eta()})

    def on_log(self, name: str, message: str) -> None:
        self._emit("log", {"logger": name, "message": message})

    def finalize(self, error: str = "") -> None:
        """Mark done (idempotent) and notify listeners so streams can close."""
        if error and not self.error:
            self.error = error
        if not self.done:
            self.done = True
        self._emit("run.done", {"run_id": self.run_id, "done": True,
                                "error": self.error, "findings_by_severity": dict(self.findings)})


# --- log capture: forward sentinel run/orchestrator logs into a LiveRun ----
class _LiveLogHandler(logging.Handler):
    def __init__(self, live: LiveRun) -> None:
        super().__init__(level=logging.INFO)
        self._live = live

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._live.on_log(record.name, record.getMessage())
        except Exception:  # noqa: BLE001
            pass


def attach_log_capture(live: LiveRun):
    """Stream INFO logs from the run + orchestrator loggers into the live view.
    Returns an opaque handle to pass back to detach_log_capture."""
    handler = _LiveLogHandler(live)
    loggers = [logging.getLogger("sentinel.run"), logging.getLogger("sentinel.orchestrator")]
    for lg in loggers:
        lg.addHandler(handler)
    return (handler, loggers)


def detach_log_capture(handle) -> None:
    if not handle:
        return
    handler, loggers = handle
    for lg in loggers:
        lg.removeHandler(handler)
