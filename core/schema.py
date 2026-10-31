# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""Data schema for Sentinel results.

One run -> one `RunResult` -> one JSON file. Everything here is a plain
dataclass of JSON-friendly types (str-enums, string timestamps, lists/dicts) so
`json.dumps(dataclasses.asdict(run), default=str)` just works.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List


class Severity(str, Enum):
    """Severity levels. Subclassing str means `Severity.HIGH` serializes to
    the bare string "high" with no special encoder."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Numeric order for sorting findings in reports (higher = worse).
SEVERITY_RANK: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp string (seconds precision, trailing 'Z')."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug_workflow(workflow: str) -> str:
    """Lowercase the workflow, collapsing any non-alphanumeric run to '-'."""
    s = re.sub(r"[^a-z0-9]+", "-", str(workflow).lower()).strip("-")
    return s or "workflow"


def _slug_target(target: str) -> str:
    """Filesystem-safe target slug: '/' and ':' -> '-', strip anything outside
    [a-z0-9._-]. e.g. '10.10.1.0/24' -> '10.10.1.0-24'."""
    s = str(target).strip().lower().replace("/", "-").replace(":", "-")
    return re.sub(r"[^a-z0-9._-]+", "", s).strip("-")


def make_run_id(workflow: str, target: str = "") -> str:
    """Human-readable, filesystem-safe, time-sortable, unique run id.

    Shape: ``YYYY-MM-DD_HH-MM_<workflow>_<target>_<shortid>`` e.g.
    ``2026-10-09_18-28_quick-recon_10.10.1.0-24_e369d6``. The minute-precision
    timestamp keeps ids lexically time-sortable; the 6-char uuid keeps them
    unique. The target segment is omitted when empty (e.g. wireless runs).
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M")
    parts = [stamp, _slug_workflow(workflow)]
    tgt = _slug_target(target)
    if tgt:
        parts.append(tgt)
    parts.append(uuid.uuid4().hex[:6])
    return "_".join(parts)


def coerce_severity(value) -> str:
    """Accept a Severity or a str; return the canonical lowercase string.

    Unknown strings fall back to "info" rather than raising — a plugin should
    never crash a run over a typo'd severity.
    """
    if isinstance(value, Severity):
        return value.value
    s = str(value).strip().lower()
    return s if s in SEVERITY_RANK else Severity.INFO.value


@dataclass
class Finding:
    finding_id: str
    module: str
    type: str
    severity: str                      # canonical lowercase; see coerce_severity
    target: str
    title: str
    detail: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=utcnow_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class Asset:
    ip: str                            # host IP, or a BSSID/station MAC for Wi-Fi assets
    alive: bool = False
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    open_ports: List[int] = field(default_factory=list)
    os_guess: str = ""
    # --- wireless (red.wifi_scan); defaults keep host assets byte-identical ---
    kind: str = "host"                 # "host" | "wifi_ap" | "wifi_client"
    ssid: str = ""                     # AP network name (ESSID)
    channel: str = ""                  # Wi-Fi channel (string; "" = unknown)
    encryption: str = ""               # e.g. "WPA2", "WEP", "OPEN"
    signal: str = ""                   # signal/power as reported (dBm string)
    # --- generic per-module metadata (additive; defaults keep other assets
    # byte-identical). e.g. blue.esp_sensor stashes the ESP's latest
    # heartbeat/status here (mode, channel, frames_seen, uptime, alive, ...).
    extra: Dict = field(default_factory=dict)


@dataclass
class RunResult:
    run_id: str
    workflow: str
    target: str
    started_at: str
    schema_version: int = 1
    finished_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

    def compute_stats(self) -> None:
        """Recompute `stats` from current findings/assets. Called at finalize."""
        by_sev = {k: 0 for k in SEVERITY_RANK}
        for f in self.findings:
            # coerce_severity always returns a key present in by_sev, so += is safe.
            by_sev[coerce_severity(f.severity)] += 1
        self.stats = {
            "hosts_up": sum(a.alive for a in self.assets),
            "assets_total": len(self.assets),
            "findings_total": len(self.findings),
            "findings_by_severity": by_sev,
        }
