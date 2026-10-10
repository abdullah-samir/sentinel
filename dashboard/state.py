"""Single-active-run guard + live-run state for dashboard-triggered scans.

Only one scan may run at a time (capture/recon contend for interfaces/sockets).
This object also holds the current LiveRun so both the SSE stream and a plain
page refresh reflect the same progress.
"""
from __future__ import annotations

import threading
from typing import Optional

from dashboard.live import LiveRun


class RunState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = False
        self._live: Optional[LiveRun] = None     # current or most-recent run

    def try_start(self, workflow: str, target: str,
                  run_id: Optional[str] = None) -> Optional[LiveRun]:
        """Atomically claim the single run slot and start tracking a LiveRun.
        Returns the new LiveRun, or None if a scan is already active."""
        with self._lock:
            if self._active:
                return None
            self._active = True
            self._live = LiveRun(run_id or "pending", workflow, target)
            return self._live

    def finish(self) -> None:
        """Free the run slot. The LiveRun is kept (now done) so a refresh still
        shows the completed state + report link."""
        with self._lock:
            self._active = False

    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def current(self) -> Optional[dict]:
        with self._lock:
            if not self._active or self._live is None:
                return None
            return {"workflow": self._live.workflow, "target": self._live.target,
                    "run_id": self._live.run_id, "started_at": self._live.started_at}

    def live(self) -> Optional[LiveRun]:
        with self._lock:
            return self._live
