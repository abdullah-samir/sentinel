"""Run history and diffing for reports.

Finding identity is deliberately coarse — ``module + type + target + port`` — so
a version/evidence change is NOT counted as one finding resolved plus a new one
appearing. Volatile fields (version strings, full evidence text) are excluded;
only the stable numeric port is pulled from the title/evidence.

Orchestration/status findings (skipped/refused/module_status/…) are not
exposures, so they are excluded from diff counts.
"""
from __future__ import annotations

import json
import re
from typing import List, Optional

from reporting import risk

_PORT_RE = re.compile(r"(?<!\d)(\d{1,5})/(?:tcp|udp|sctp)", re.IGNORECASE)
_EXCLUDE_TYPES = {"skipped", "refused", "module_status", "module_error", "scan_timeout"}


def _port_of(f: dict) -> str:
    """Pull a stable port number from the title or evidence, or '' if none."""
    for field in (f.get("title", ""), f.get("evidence", "")):
        m = _PORT_RE.search(str(field))
        if m:
            return m.group(1)
    return ""


def finding_key(f: dict) -> str:
    """Stable identity for diffing: module|type|target|port (no version/evidence)."""
    return "|".join([
        str(f.get("module", "")), str(f.get("type", "")),
        str(f.get("target", "")), _port_of(f),
    ])


def _real_findings(run: dict) -> List[dict]:
    return [f for f in (run.get("findings") or [])
            if str(f.get("type", "")) not in _EXCLUDE_TYPES]


def diff_runs(current: dict, previous: Optional[dict]) -> dict:
    """Diff the current run against the previous comparable run (or None).

    With no previous run this is a baseline: new/resolved are 0 (there is
    nothing to compare against), not "every finding is new"."""
    cur_grade = risk.grade_for_score(risk.score(current.get("findings") or []))
    if previous is None:
        return {
            "has_previous": False, "previous_run_id": None,
            "new": 0, "resolved": 0, "new_keys": [], "resolved_keys": [],
            "grade_from": None, "grade_to": cur_grade, "grade_changed": False,
        }
    cur = {finding_key(f) for f in _real_findings(current)}
    prev = {finding_key(f) for f in _real_findings(previous)}
    new = cur - prev
    resolved = prev - cur
    prev_grade = risk.grade_for_score(risk.score(previous.get("findings") or []))
    return {
        "has_previous": True, "previous_run_id": previous.get("run_id"),
        "new": len(new), "resolved": len(resolved),
        "new_keys": sorted(new), "resolved_keys": sorted(resolved),
        "grade_from": prev_grade, "grade_to": cur_grade,
        "grade_changed": prev_grade != cur_grade,
    }


def _sort_key(run: dict):
    return (str(run.get("started_at", "")), str(run.get("run_id", "")))


def load_all_runs(config) -> List[dict]:
    """Load every run JSON from the results dir, newest first."""
    runs = []
    for p in config.results_dir.glob("*.json"):
        if p.name.startswith("."):
            continue
        try:
            with open(p, encoding="utf-8") as fh:
                runs.append(json.load(fh))
        except Exception:  # noqa: BLE001 — a corrupt file is skipped, not fatal
            continue
    runs.sort(key=_sort_key, reverse=True)
    return runs


def previous_run(current: dict, config, runs: Optional[List[dict]] = None) -> Optional[dict]:
    """Newest run of the SAME workflow AND SAME target started before `current`."""
    runs = runs if runs is not None else load_all_runs(config)
    wf, tgt, cid = current.get("workflow"), current.get("target"), current.get("run_id")
    ck = _sort_key(current)
    cands = [r for r in runs
             if r.get("workflow") == wf and r.get("target") == tgt
             and r.get("run_id") != cid and _sort_key(r) < ck]
    return max(cands, key=_sort_key) if cands else None
