"""Full scan launcher: surface EVERY existing per-run option as a form field,
validate it, and build a per-run Config (never mutating global config/core).

Options map 1:1 to Config fields the orchestrator/modules already read. No new
scan behavior is introduced here — this only exposes what already exists.
"""
from __future__ import annotations

import dataclasses
import json
import re
from typing import List, Tuple

from core.workflows import load_workflows
from dashboard.manage import safe_path, valid_run_id

# Per-module option groups. `key` is the form field; for most it is also the
# Config attribute (except "mode" -> nmap_fast). kind: bool|int|choice|text.
OPTION_GROUPS = {
    "red.recon_nmap": [
        {"key": "mode", "label": "Scan depth", "kind": "choice", "default": "auto",
         "choices": [("auto", "Auto (fast for /24+, full for one host)"),
                     ("fast", "Fast (top-100, no version)"),
                     ("full", "Full (top-1000 + service versions)")],
         "help": "Fast skips version detection; full is slower but detailed."},
        {"key": "nmap_pn", "label": "Skip host discovery (-Pn)", "kind": "bool",
         "default": False, "help": "Treat every address as up — much slower on a large CIDR."},
        {"key": "nmap_timeout", "label": "Per-host timeout (s)", "kind": "int",
         "default": 300, "min": 0, "max": 3600, "help": "nmap --host-timeout; 0 disables."},
        {"key": "nmap_top_ports", "label": "Top ports", "kind": "int",
         "default": 0, "min": 0, "max": 65535, "help": "0 = mode default (100 fast / 1000 full)."},
        {"key": "nmap_timing", "label": "Timing", "kind": "choice", "default": "4",
         "choices": [("1", "T1 — slow / stealthy"), ("2", "T2"), ("3", "T3 — normal"),
                     ("4", "T4 — aggressive"), ("5", "T5 — fastest")],
         "help": "nmap -T template."},
        {"key": "nmap_privileged", "label": "Privileged (-sS/-O)", "kind": "bool",
         "default": False, "help": "SYN + OS detection; only effective when running as root."},
    ],
    "red.wifi_scan": [
        {"key": "wifi_scan_seconds", "label": "Duration (s)", "kind": "int",
         "default": 30, "min": 1, "max": 3600, "help": "How long to listen (airodump-ng)."},
        {"key": "wifi_scan_channel", "label": "Channel", "kind": "text", "default": "",
         "maxlen": 4, "pattern": r"^[0-9]+$",
         "help": "Blank = channel-hop; else lock to this 2.4/5 GHz channel number."},
        {"key": "wifi_iface", "label": "Adapter interface", "kind": "text", "default": "",
         "maxlen": 32, "pattern": r"^[A-Za-z0-9._:-]+$",
         "help": "Blank = auto-detect the RTL8188EUS USB adapter by driver/chipset."},
    ],
    "blue.capture_tshark": [
        {"key": "capture_seconds", "label": "Duration (s)", "kind": "int",
         "default": 30, "min": 1, "max": 3600, "help": "Capture stop time."},
        {"key": "capture_iface", "label": "Interface", "kind": "text", "default": "",
         "maxlen": 32, "pattern": r"^[A-Za-z0-9._:-]+$",
         "help": "Blank = auto (default route / first up)."},
        {"key": "capture_filter", "label": "BPF filter", "kind": "text", "default": "",
         "maxlen": 200, "help": "e.g. 'not port 22' to exclude the SSH session."},
        {"key": "capture_max_packets", "label": "Max packets", "kind": "int",
         "default": 20000, "min": 1, "max": 10_000_000, "help": "Capture stop packet count."},
    ],
}

# Config attributes that may be set from options (besides the mode->nmap_fast map).
_CONFIG_KEYS = ("nmap_pn", "nmap_timeout", "nmap_top_ports", "nmap_timing",
                "nmap_privileged", "capture_seconds", "capture_iface",
                "capture_filter", "capture_max_packets",
                "wifi_scan_seconds", "wifi_scan_channel", "wifi_iface")


def _steps(config, workflow: str) -> List[str]:
    wf = load_workflows(config).get(workflow)
    return wf.get("steps", []) if isinstance(wf, dict) else []


# spec.key -> Config attr whose current value is the field's default (so Settings
# changes to default scan options flow into the launcher).
_DEFAULT_FROM_CONFIG = {
    "nmap_pn": "nmap_pn", "nmap_timeout": "nmap_timeout", "nmap_top_ports": "nmap_top_ports",
    "nmap_timing": "nmap_timing", "nmap_privileged": "nmap_privileged",
    "capture_seconds": "capture_seconds", "capture_iface": "capture_iface",
    "capture_filter": "capture_filter", "capture_max_packets": "capture_max_packets",
    "wifi_scan_seconds": "wifi_scan_seconds", "wifi_scan_channel": "wifi_scan_channel",
    "wifi_iface": "wifi_iface",
}


def _resolve(spec: dict, config) -> dict:
    s = dict(spec)
    if spec["key"] == "mode":
        s["default"] = {None: "auto", True: "fast", False: "full"}.get(
            getattr(config, "nmap_fast", None), "auto")
    else:
        attr = _DEFAULT_FROM_CONFIG.get(spec["key"])
        if attr and hasattr(config, attr):
            s["default"] = getattr(config, attr)
    return s


def workflow_option_groups(config, workflow: str) -> List[Tuple[str, list]]:
    """[(module, specs)] for the modules in `workflow` that have options, with
    each spec's default resolved from the current config."""
    return [(mod, [_resolve(s, config) for s in OPTION_GROUPS[mod]])
            for mod in _steps(config, workflow) if mod in OPTION_GROUPS]


def _parse_one(spec: dict, form: dict):
    key, kind = spec["key"], spec["kind"]
    raw = form.get(key)
    if kind == "bool":
        return raw in ("1", "true", "on", "yes") if raw is not None else bool(spec["default"])
    if kind == "int":
        if raw is None or raw == "":
            return int(spec["default"])
        try:
            n = int(raw)
        except (ValueError, TypeError):
            raise ValueError(f"{spec['label']} must be a whole number")
        if n < spec["min"] or n > spec["max"]:
            raise ValueError(f"{spec['label']} must be between {spec['min']} and {spec['max']}")
        return n
    if kind == "choice":
        choices = [c[0] for c in spec["choices"]]
        if raw is None or raw == "":
            return spec["default"]
        if raw not in choices:
            raise ValueError(f"invalid {spec['label']}")
        return raw
    # text
    v = (raw if raw is not None else spec["default"]) or ""
    v = v.strip()
    if spec.get("maxlen") and len(v) > spec["maxlen"]:
        raise ValueError(f"{spec['label']} is too long")
    if spec.get("pattern") and v and not re.match(spec["pattern"], v):
        raise ValueError(f"invalid {spec['label']}")
    return v


def parse_options(config, workflow: str, form: dict) -> dict:
    """Validated option values for `workflow` (raises ValueError on bad input)."""
    opts = {}
    for _mod, specs in workflow_option_groups(config, workflow):
        for spec in specs:
            opts[spec["key"]] = _parse_one(spec, form)
    return opts


def config_from_options(core_config, options: dict):
    """Return a COPY of core_config with per-run overrides applied (no mutation)."""
    overrides = {}
    if "mode" in options:
        overrides["nmap_fast"] = {"auto": None, "fast": True, "full": False}.get(options["mode"])
    for k in _CONFIG_KEYS:
        if k in options:
            overrides[k] = options[k]
    return dataclasses.replace(core_config, **overrides)


# --- launch sidecar (for re-run prefill) ----------------------------------
def save_launch(config, run_id: str, workflow: str, target: str, options: dict) -> None:
    if not valid_run_id(run_id):
        return
    p = safe_path(config.reports_dir, f"{run_id}.launch.json")
    if not p:
        return
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps({"workflow": workflow, "target": target,
                                 "options": options}), encoding="utf-8")
    except OSError:
        pass


def load_launch(config, run_id: str):
    if not valid_run_id(run_id):
        return None
    p = safe_path(config.reports_dir, f"{run_id}.launch.json")
    if p and p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
    return None
