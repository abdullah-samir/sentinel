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
    nmap_pn: bool = False               # -Pn: skip host discovery (slow on big CIDRs)

    # --- Wi-Fi scan tuning (red.wifi_scan reads these) --------------------
    # wifi_iface (above) "" / a non-present name -> auto-detect the RTL8188EUS
    # USB adapter by driver/chipset; set it to a present iface to pin one.
    wifi_scan_seconds: int = 30         # bounded airodump-ng capture duration
    wifi_scan_channel: str = ""         # "" -> channel-hop; else lock to this channel

    # --- packet capture tuning (blue.capture_tshark reads these) ----------
    capture_iface: str = ""             # "" -> auto-select (default route / first up)
    capture_seconds: int = 30           # primary stop: -a duration:
    capture_max_packets: int = 20000    # stop: -c
    capture_max_filesize_kb: int = 51200  # stop: -a filesize:
    capture_filter: str = ""            # optional BPF, e.g. "not port 22" (exclude SSH)

    # --- ESP32-S3 wireless sensor (blue.esp_sensor reads these) -----------
    # Serial is PRIMARY (the flashed firmware defaults to MODE_SNIFFER = serial
    # only). esp_url is the alternate HTTP path for a MODE_CONNECTED reflash.
    esp_serial_port: str = "/dev/ttyACM0"  # S3 native-USB / UART bridge port
    esp_baud: int = 115200
    esp_url: str = ""                      # e.g. http://10.10.1.50 (MODE_CONNECTED)
    esp_listen_seconds: int = 30           # bounded read/poll duration

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
        if os.environ.get("SENTINEL_NMAP_PN") == "1":
            cfg.nmap_pn = True
        # Wi-Fi scan tuning
        raw = os.environ.get("SENTINEL_WIFI_SCAN_SECONDS")
        if raw:
            try:
                cfg.wifi_scan_seconds = int(raw)
            except ValueError:
                pass
        chan = os.environ.get("SENTINEL_WIFI_SCAN_CHANNEL")
        if chan is not None:
            cfg.wifi_scan_channel = chan
        # packet capture tuning
        iface = os.environ.get("SENTINEL_CAPTURE_IFACE")
        if iface:
            cfg.capture_iface = iface
        for env_key, attr in (("SENTINEL_CAPTURE_SECONDS", "capture_seconds"),
                              ("SENTINEL_CAPTURE_MAX_PACKETS", "capture_max_packets"),
                              ("SENTINEL_CAPTURE_MAX_FILESIZE_KB", "capture_max_filesize_kb")):
            raw = os.environ.get(env_key)
            if raw:
                try:
                    setattr(cfg, attr, int(raw))
                except ValueError:
                    pass
        cfilter = os.environ.get("SENTINEL_CAPTURE_FILTER")
        if cfilter is not None:
            cfg.capture_filter = cfilter
        # ESP32-S3 wireless sensor
        port = os.environ.get("SENTINEL_ESP_SERIAL_PORT")
        if port:
            cfg.esp_serial_port = port
        esp_url = os.environ.get("SENTINEL_ESP_URL")
        if esp_url is not None:
            cfg.esp_url = esp_url
        for env_key, attr in (("SENTINEL_ESP_BAUD", "esp_baud"),
                              ("SENTINEL_ESP_LISTEN_SECONDS", "esp_listen_seconds")):
            raw = os.environ.get(env_key)
            if raw:
                try:
                    setattr(cfg, attr, int(raw))
                except ValueError:
                    pass
        return cfg
