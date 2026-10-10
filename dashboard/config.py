"""Dashboard auth configuration.

A small JSON file (``data/dashboard.json``, gitignored) holds the admin
username, the scrypt password hash, and a persisted session-signing secret.
Environment variables override the file. The secret is generated once and reused
across restarts — never regenerated per launch — so sessions survive restarts.
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.config import Config


def config_path(core_config: Optional[Config] = None) -> Path:
    core_config = core_config or Config()
    return core_config.root / "data" / "dashboard.json"


@dataclass
class DashConfig:
    user: str
    password_hash: str          # scrypt hash string, or "" when unset
    secret: str                 # session-signing secret (hex)
    readonly: bool
    path: Path

    @property
    def configured(self) -> bool:
        return bool(self.password_hash)


def _read_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — a corrupt file must not crash startup
        return {}


def save_dash_config(cfg: DashConfig) -> None:
    cfg.path.parent.mkdir(parents=True, exist_ok=True)
    data = {"user": cfg.user, "password_hash": cfg.password_hash,
            "secret": cfg.secret, "readonly": cfg.readonly}
    tmp = cfg.path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, cfg.path)
    try:
        os.chmod(cfg.path, 0o600)       # secrets: owner read/write only
    except OSError:
        pass


def load_dash_config(core_config: Optional[Config] = None) -> DashConfig:
    """Load config, applying env overrides. Generates + persists a session
    secret on first use when none exists (and no env secret is set)."""
    path = config_path(core_config)
    data = _read_file(path)

    user = os.environ.get("SENTINEL_DASH_USER") or data.get("user") or "admin"
    password_hash = data.get("password_hash", "") or ""

    env_secret = os.environ.get("SENTINEL_DASH_SECRET")
    secret = env_secret or data.get("secret") or ""
    persist = False
    if not secret:
        secret = secrets.token_hex(32)
        persist = True                  # generate once, reuse across restarts

    readonly_env = os.environ.get("SENTINEL_DASH_READONLY")
    if readonly_env is not None:
        readonly = readonly_env == "1"
    else:
        readonly = bool(data.get("readonly", False))

    cfg = DashConfig(user=user, password_hash=password_hash, secret=secret,
                     readonly=readonly, path=path)
    # Only persist a newly-generated FILE secret (never persist an env secret).
    if persist and not env_secret:
        save_dash_config(cfg)
    return cfg
