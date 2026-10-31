# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""PTY-backed shell session for the dashboard web terminal.

This provides a REAL interactive shell (a pseudo-terminal running `bash`) so the
maintainer can administer the Pi from the dashboard. It runs as whatever user the
dashboard runs as (the unprivileged `sentinel` user) — it does not escalate.

Security note: this is only ever reachable when `DashConfig.shell_enabled` is set
AND the request carries a valid session AND the dashboard is not read-only (all
enforced in app.py). The session is bounded to the process lifetime and killed
(whole process group) on disconnect. This grants arbitrary command execution by
design; keep it off unless the dashboard is on a trusted, non-public network.
"""
from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import termios
from typing import Optional


class PtySession:
    """A bash process attached to a pseudo-terminal, read/written by fd."""

    def __init__(self, cwd: Optional[str] = None, shell: str = "/bin/bash") -> None:
        self.master_fd, slave_fd = pty.openpty()
        env = dict(os.environ)
        env.setdefault("TERM", "xterm-256color")
        env["SENTINEL_WEB_TERMINAL"] = "1"      # so a shell rc can show a warning if it wants
        try:
            self.proc = subprocess.Popen(
                [shell, "-i"],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                cwd=cwd or os.path.expanduser("~"),
                env=env,
                preexec_fn=os.setsid,           # own session + controlling tty
                close_fds=True,
            )
        finally:
            os.close(slave_fd)                   # child holds its own copy

    # --- io ---------------------------------------------------------------
    def read(self, timeout: float = 0.1) -> bytes:
        """Non-blocking-ish read of available output (up to `timeout` s)."""
        try:
            r, _, _ = select.select([self.master_fd], [], [], timeout)
        except (OSError, ValueError):
            return b""
        if self.master_fd in r:
            try:
                return os.read(self.master_fd, 65536)
            except OSError:
                return b""
        return b""

    def write(self, data: bytes) -> None:
        try:
            os.write(self.master_fd, data)
        except OSError:
            pass

    def resize(self, rows: int, cols: int) -> None:
        rows = max(1, min(int(rows), 1000))
        cols = max(1, min(int(cols), 1000))
        try:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    # --- lifecycle --------------------------------------------------------
    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        """Terminate the shell and its whole process group, then close the fd."""
        try:
            pgid = os.getpgid(self.proc.pid)
        except OSError:
            pgid = None
        for sig in (signal.SIGHUP, signal.SIGKILL):
            if pgid is not None:
                try:
                    os.killpg(pgid, sig)
                except OSError:
                    pass
            if self.proc.poll() is not None:
                break
        try:
            self.proc.wait(timeout=2)
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass
