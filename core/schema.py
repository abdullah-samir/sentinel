"""Data schema for Sentinel results.

One run -> one `RunResult` -> one JSON file. Everything here is a plain
dataclass of JSON-friendly types (str-enums, string timestamps, lists/dicts) so
`json.dumps(dataclasses.asdict(run), default=str)` just works.
"""
from __future__ import annotations

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


def make_run_id(workflow: str) -> str:
    """Filesystem-safe, time-sortable, unique run id.

    Shape: ``20261007T143210_quick_recon_a1b2c3``.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    safe_wf = "".join(c if (c.isalnum() or c in "-_") else "_" for c in workflow)
    return f"{stamp}_{safe_wf}_{uuid.uuid4().hex[:6]}"


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
    ip: str
    alive: bool = False
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    open_ports: List[int] = field(default_factory=list)
    os_guess: str = ""


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
