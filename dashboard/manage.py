"""Run management for the dashboard: strict run-id validation, path-safe file
resolution, delete/bulk-delete, and per-run name/tag sidecars.

Every filesystem operation validates the run_id against a strict allowlist AND
resolves the final path, confirming it stays inside the expected directory —
raw user input is never concatenated into a path (rejects '..' and absolutes).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

log = logging.getLogger("sentinel.dashboard.manage")

# Must start alphanumeric; only [A-Za-z0-9._-] after. Excludes '/', '\', spaces.
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def valid_run_id(run_id: str) -> bool:
    return (isinstance(run_id, str) and bool(run_id)
            and ".." not in run_id and "/" not in run_id and "\\" not in run_id
            and bool(RUN_ID_RE.match(run_id)))


def safe_path(base: Path, filename: str) -> Optional[Path]:
    """Resolve base/filename and confirm it stays strictly within base.
    Returns None if it would escape (defense in depth over valid_run_id)."""
    try:
        base_r = base.resolve()
        p = (base_r / filename).resolve()
        p.relative_to(base_r)          # raises ValueError if p is outside base_r
    except (ValueError, OSError):
        return None
    return None if p == base_r else p


def run_files(config, run_id: str) -> List[Path]:
    """All files owned by a run: the result JSON + report artifacts + sidecars."""
    files: List[Path] = []
    rp = safe_path(config.results_dir, f"{run_id}.json")
    if rp:
        files.append(rp)
    for name in (f"{run_id}.html", f"{run_id}.md", f"{run_id}.pdf",
                 f"{run_id}.launch.json", f"{run_id}.meta.json"):
        p = safe_path(config.reports_dir, name)
        if p:
            files.append(p)
    return files


def delete_run(config, run_id: str) -> bool:
    """Delete a run's result + report + sidecar files. Returns True if anything
    was removed. Raises ValueError for an invalid/traversing run_id."""
    if not valid_run_id(run_id):
        raise ValueError(f"invalid run id: {run_id!r}")
    removed = False
    for p in run_files(config, run_id):
        try:
            if p.exists():
                p.unlink()
                removed = True
        except OSError as e:  # noqa: PERF203
            log.warning("delete failed for %s: %s", p, e)
    return removed


def bulk_delete(config, run_ids: List[str]) -> Tuple[int, int, List[str]]:
    """Delete many runs, continuing past errors. Returns (deleted, failed, msgs)."""
    deleted = failed = 0
    errors: List[str] = []
    for rid in run_ids:
        try:
            if delete_run(config, rid):
                deleted += 1
            else:
                failed += 1
                errors.append(f"{rid}: nothing to delete")
        except Exception as e:  # noqa: BLE001 — one bad id must not abort the batch
            failed += 1
            errors.append(f"{rid}: {e}")
    return deleted, failed, errors


# --- per-run name/tag sidecar --------------------------------------------
def _meta_path(config, run_id: str) -> Optional[Path]:
    return safe_path(config.reports_dir, f"{run_id}.meta.json") if valid_run_id(run_id) else None


def load_meta(config, run_id: str) -> dict:
    p = _meta_path(config, run_id)
    if p and p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            return {}
    return {}


def save_meta(config, run_id: str, name: Optional[str] = None,
              tags: Optional[str] = None) -> None:
    if not valid_run_id(run_id):
        raise ValueError(f"invalid run id: {run_id!r}")
    p = _meta_path(config, run_id)
    if p is None:
        raise ValueError("unsafe path")
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    data = load_meta(config, run_id)
    if name is not None:
        data["name"] = name.strip()[:120]
    if tags is not None:
        data["tags"] = tags.strip()[:200]
    p.write_text(json.dumps(data), encoding="utf-8")
