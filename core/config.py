"""Runtime configuration for a Sentinel run.

A single dataclass carries every knob the core and plugins read. Defaults are
safe for the Pi today: mock hardware, unprivileged nmap, offensive modules off.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _default_root() -> Path:
    """Project root = the directory that contains this package.

    Lets `data/results`, `data/models`, etc. resolve no matter the CWD.
    """
    return Path(__file__).resolve().parent.parent


@dataclass
class Config:
    root: Path = field(default_factory=_default_root)
    wifi_iface: str = "wlan1"           # USB adapter; wlan0 is built-in
    authorized_lab: bool = False        # offensive modules refuse unless True
    use_mock_hardware: bool = True      # True until real hardware is wired
    nmap_privileged: bool = False       # True -> -sS/-O (needs root); else -sT

    # --- nmap recon tuning (red.recon_nmap reads these) -------------------
    # Tri-state: None = auto (fast for /24-or-larger targets, full otherwise);
    # True = force fast (top-100, no -sV/-O); False = force full (top-1000 + -sV).
    nmap_fast: Optional[bool] = None
    nmap_top_ports: int = 0             # 0 = auto (100 fast / 1000 full); else override
    nmap_timeout: int = 300             # nmap --host-timeout seconds (0 disables)
    nmap_timing: str = "4"              # nmap -T<timing> (0-5); 4 = aggressive

    # --- derived paths (never serialized into run JSON) -------------------
    @property
    def results_dir(self) -> Path:
        return self.root / "data" / "results"

    @property
    def logs_dir(self) -> Path:
        return self.root / "data" / "logs"

    @property
    def models_dir(self) -> Path:
        return self.root / "data" / "models"

    @property
    def captures_dir(self) -> Path:
        return self.root / "captures"

    @property
    def reports_dir(self) -> Path:
        return self.root / "data" / "reports"

    def ensure_dirs(self) -> None:
        """Create the writable directories a run needs. Idempotent."""
        for d in (self.results_dir, self.logs_dir, self.models_dir, self.captures_dir):
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config, letting environment variables override defaults.

        Offensive modules are double-gated (see the orchestrator):
          * SENTINEL_AUTHORIZED_LAB=1 asserts this appliance lives in an
            isolated, authorized lab -> sets `authorized_lab` here.
          * SENTINEL_AUTHORIZED=1 (or the `--i-am-authorized` run flag) is the
            separate per-invocation confirmation, handled at run time.
        Both must hold before an offensive module executes.
        """
        cfg = cls()
        if os.environ.get("SENTINEL_AUTHORIZED_LAB") == "1":
            cfg.authorized_lab = True
        iface = os.environ.get("SENTINEL_WIFI_IFACE")
        if iface:
            cfg.wifi_iface = iface
        if os.environ.get("SENTINEL_NMAP_PRIVILEGED") == "1":
            cfg.nmap_privileged = True
        if os.environ.get("SENTINEL_REAL_HARDWARE") == "1":
            cfg.use_mock_hardware = False
        # nmap recon tuning (env overrides defaults; CLI flags later override these)
        if os.environ.get("SENTINEL_NMAP_FAST") is not None:
            cfg.nmap_fast = os.environ["SENTINEL_NMAP_FAST"] == "1"
        for env_key, attr in (("SENTINEL_NMAP_TOP_PORTS", "nmap_top_ports"),
                              ("SENTINEL_NMAP_TIMEOUT", "nmap_timeout")):
            raw = os.environ.get(env_key)
            if raw:
                try:
                    setattr(cfg, attr, int(raw))
                except ValueError:
                    pass
        timing = os.environ.get("SENTINEL_NMAP_TIMING")
        if timing:
            cfg.nmap_timing = timing
        return cfg
