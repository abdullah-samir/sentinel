# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""CLI entry points for the dashboard: `sentinel dashboard` and
`sentinel dashboard-setpass`. All logic lives here; core.cli only dispatches."""
from __future__ import annotations

import getpass
import sys
from typing import Optional

import uvicorn

from core.config import Config
from dashboard.auth import hash_password
from dashboard.config import DashConfig, load_dash_config, save_dash_config

_LOCAL = {"127.0.0.1", "localhost", "::1", ""}


def setpass(core_config: Optional[Config] = None,
            _prompt=None) -> int:
    """Prompt for a password and store only its scrypt hash in the config file
    (creating the file + session secret if needed)."""
    core_config = core_config or Config.from_env()
    cfg = load_dash_config(core_config)      # ensures a persisted secret exists
    prompt = _prompt or getpass.getpass
    pw1 = prompt("New dashboard password: ")
    pw2 = prompt("Confirm password: ")
    if not pw1:
        print("Password must not be empty.", file=sys.stderr)
        return 1
    if pw1 != pw2:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    cfg.password_hash = hash_password(pw1)
    save_dash_config(cfg)
    print(f"Dashboard password set for user '{cfg.user}'. Config: {cfg.path}")
    return 0


def dashboard(host: str = "127.0.0.1", port: int = 8000,
              core_config: Optional[Config] = None) -> int:
    """Launch the dashboard via uvicorn. Refuses to start if no admin password
    is configured (never runs unauthenticated)."""
    core_config = core_config or Config.from_env()
    cfg = load_dash_config(core_config)
    if not cfg.configured:
        print("No admin password set — run `sentinel dashboard-setpass` first.",
              file=sys.stderr)
        return 1

    if host not in _LOCAL:
        print(f"WARNING: binding to {host} — the dashboard is exposed on the network. "
              "Ensure auth is set, prefer the Tailscale IP, and treat this as lab use only.",
              file=sys.stderr)
    print(f"Sentinel dashboard on http://{host}:{port}  (user: {cfg.user})")

    from dashboard.app import create_app
    uvicorn.run(create_app(core_config, cfg), host=host, port=port, log_level="info")
    return 0
